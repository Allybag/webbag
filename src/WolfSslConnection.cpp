#include <WolfSslConnection.hpp>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/settings.h>

#include <seaplane/error.hpp>
#include <seaplane/log.hpp>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  // For TCP_NODELAY and TCP_KEEPALIVE
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>

// Linux-specific headers for packet timestamping
#ifdef __linux__
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <errno.h>
#include <poll.h>
#define PACKET_TIMESTAMPING_AVAILABLE 1
#else
#define PACKET_TIMESTAMPING_AVAILABLE 0
#define SIOCOUTQ 0
#define TCP_INFO 0
struct tcp_info { int tcpi_retransmits; int tcpi_snd_cwnd; int tcpi_rcv_mss; int tcpi_rtt; int tcpi_unacked; };
#endif

#include <array>
#include <cstring>
#include <thread>
#include <vector>

class WolfSSLConnection::Impl
{
public:
    struct SSLDeleter
    {
        void operator()(WOLFSSL* ssl) { if (ssl) wolfSSL_free(ssl); }
        void operator()(WOLFSSL_CTX* ctx) { if (ctx) wolfSSL_CTX_free(ctx); }
    };

    using SSLPtr = std::unique_ptr<WOLFSSL, SSLDeleter>;
    using CTXPtr = std::unique_ptr<WOLFSSL_CTX, SSLDeleter>;

    Impl()
    {
        if ((false))
        {
            wolfSSL_Debugging_ON();
        }

        if (wolfSSL_Init() != WOLFSSL_SUCCESS)
        {
            throw FlushingError{"Failed to initialize WolfSSL"};
        }
    }

    ~Impl()
    {
        disconnect();
        wolfSSL_Cleanup();
    }

    void setupSocket()
    {
        mSocketFd = socket(AF_INET, SOCK_STREAM, 0);
        if (mSocketFd < 0)
        {
            throw FlushingError{"Failed to create socket"};
        }

        int flag = 1;
        if (setsockopt(mSocketFd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
        {
            sea_log("Failed to set TCP_NODELAY: {}", strerror(errno));
        }
        if (setsockopt(mSocketFd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0)
        {
            sea_log("Failed to set SO_KEEPALIVE: {}", strerror(errno));
        }

        int myNodelay = 0;
        socklen_t myLen = sizeof(myNodelay);
        getsockopt(mSocketFd, IPPROTO_TCP, TCP_NODELAY, &myNodelay, &myLen);
        sea_log("TCP_NODELAY is {}", myNodelay ? "enabled" : "disabled");

        struct timeval timeout = {10, 0};
        setsockopt(mSocketFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setupTimestamping();
    }

    void createSsl()
    {
        wolfSSL_CTX_SetIORecv(mCtx.get(), customReceiveCallback);
        mSsl = SSLPtr(wolfSSL_new(mCtx.get()));
        if (!mSsl)
        {
            throw FlushingError{"Failed to create SSL session"};
        }

        if (wolfSSL_set_fd(mSsl.get(), mSocketFd) != WOLFSSL_SUCCESS)
        {
            throw FlushingError{"Failed to set SSL socket"};
        }

        wolfSSL_SetIOReadCtx(mSsl.get(), this);
    }

    void connect(const std::string& hostname, int port)
    {
        setupSocket();
        mCtx = CTXPtr(wolfSSL_CTX_new(wolfTLS_client_method()));
        if (!mCtx)
        {
            throw FlushingError{"Failed to create SSL context"};
        }

        wolfSSL_CTX_SetMinVersion(mCtx.get(), TLS1_3_VERSION);
        wolfSSL_CTX_set_verify(mCtx.get(), WOLFSSL_VERIFY_NONE, nullptr);
        wolfSSL_CTX_set_session_cache_mode(mCtx.get(), WOLFSSL_SESS_CACHE_CLIENT);
        wolfSSL_CTX_set_timeout(mCtx.get(), 300);

        wolfSSL_CTX_set_cipher_list(mCtx.get(),
            "TLS_CHACHA20_POLY1305_SHA256:"
            "TLS_AES_128_GCM_SHA256:"
            "ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-AES128-GCM-SHA256");

        loadClientCertificate();
        connectTcp(hostname, port);
        createSsl();

        wolfSSL_UseSNI(mSsl.get(), WOLFSSL_SNI_HOST_NAME, hostname.c_str(), hostname.length());

        auto handshakeStart = std::chrono::high_resolution_clock::now();

        if (wolfSSL_connect(mSsl.get()) != WOLFSSL_SUCCESS)
        {
            char buffer[256];
            int error = wolfSSL_get_error(mSsl.get(), 0);
            memset(buffer, 0, sizeof(buffer));
            wolfSSL_ERR_error_string(error, buffer);
            throw FlushingError{std::format("Failed to connect via SSL: {} - {}", error, buffer)};
        }

        auto handshakeEnd = std::chrono::high_resolution_clock::now();
        auto handshakeDuration = std::chrono::duration_cast<std::chrono::microseconds>(
            handshakeEnd - handshakeStart);

        std::println("SSL handshake completed in {} mics", handshakeDuration.count());
        int myNodelay = 0;
        socklen_t myLen = sizeof(myNodelay);
        getsockopt(mSocketFd, IPPROTO_TCP, TCP_NODELAY, &myNodelay, &myLen);
        sea_log("TCP_NODELAY post connection is {}", myNodelay ? "enabled" : "disabled");

        mHostname = hostname;
        mPort = port;
    }

    void disconnect()
    {
        mSsl.reset();
        mCtx.reset();
        if (mSocketFd >= 0)
        {
            close(mSocketFd);
            mSocketFd = -1;
        }
    }

    std::size_t write(const void* data, std::size_t size)
    {
        if (fin())
        {
            sea_log("Received fin, connection closed by other end, reconnecting to {}", mHostname);
            disconnect();
            connect(mHostname, mPort);
        }

        int result = wolfSSL_write(mSsl.get(), data, size);
        if (result != static_cast<int>(size))
        {
            char buffer[256];
            int error = wolfSSL_get_error(mSsl.get(), 0);
            memset(buffer, 0, sizeof(buffer));
            wolfSSL_ERR_error_string(error, buffer);

            int queuedBytes;
            if (ioctl(mSocketFd, SIOCOUTQ, &queuedBytes) == 0) {
                sea_log("Send failure: {} bytes queued", queuedBytes);
            }

            struct tcp_info tcpInfo;
            socklen_t len = sizeof(tcpInfo);

            if (getsockopt(mSocketFd, IPPROTO_TCP, TCP_INFO, &tcpInfo, &len) == 0) {
                std::println("Retransmit {}, send windo {}, recv window {}, rtt {} mics, unacked packets {}",
                    tcpInfo.tcpi_retransmits, tcpInfo.tcpi_snd_cwnd, tcpInfo.tcpi_rcv_mss, tcpInfo.tcpi_rtt, tcpInfo.tcpi_unacked);
            }

            sea_log("Send failure {}: {} - {}", result, error, buffer);
            static constexpr int cErrorResult{-1};
            while (error == WOLFSSL_ERROR_WANT_WRITE_E && result == cErrorResult)
            {
                result = wolfSSL_write(mSsl.get(), data, size);
                if (result == static_cast<int>(size))
                {
                    return result;
                }

                error = wolfSSL_get_error(mSsl.get(), 0);
                sea_log("Send failure {}: {} - {}", result, error, buffer);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }

        return result;
    }

    std::size_t read(void* buffer, std::size_t size, bool immediate = false)
    {
        auto previous = mReadImmediate;
        mReadImmediate = immediate;
        int result = wolfSSL_read(mSsl.get(), buffer, size);
        mReadImmediate = previous;

        if (result <= 0)
        {
            int error = wolfSSL_get_error(mSsl.get(), result);
            if (error == WOLFSSL_ERROR_WANT_READ || error == WOLFSSL_ERROR_WANT_WRITE)
            {
                return 0;
            }

            if (error == WOLFSSL_ERROR_ZERO_RETURN)
            {
                throw ConnectionCloseError{"WolfSSL error: zero return"};
            }

            throw ConnectionCloseError{std::format("WolfSSL read failure ({})", error)};
        }

        return result;
    }

    bool fin()
    {
        if (mSocketFd < 0)
        {
            std::println("Somehow socket fd is now {}", mSocketFd);
            return true;
        }

#if PACKET_TIMESTAMPING_AVAILABLE
        struct pollfd pfd = {mSocketFd, POLLIN | POLLRDHUP, 0};
        int result = poll(&pfd, 1, 0);

        if (result > 0)
        {
            return (pfd.revents & (POLLRDHUP | POLLHUP)) != 0;
        }
#else
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(mSocketFd, &readSet);

        struct timeval zeroTimeout = {0, 0};
        int result = select(mSocketFd + 1, &readSet, nullptr, nullptr, &zeroTimeout);

        if (result > 0 && FD_ISSET(mSocketFd, &readSet))
        {
            char dummy;
            int peekResult = recv(mSocketFd, &dummy, 1, MSG_PEEK | MSG_DONTWAIT);

            if (peekResult == 0)
            {
                return true;
            }
        }
#endif
        return false;
    }

    TimestampNanos getLastRxTimestamp() const { return mRxTimestampNanos; }
    const std::string& getHostname() const { return mHostname; }

private:
    void loadClientCertificate()
    {
        const char* certFile = std::getenv("WOLF_CERT_FILE");
        const char* keyFile = std::getenv("WOLF_CERT_KEY");

        if (!certFile || !keyFile)
        {
            throw FlushingError{"WOLF_CERT_FILE and WOLF_CERT_KEY must be set"};
        }

        if (wolfSSL_CTX_use_certificate_file(mCtx.get(), certFile, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        {
            throw FlushingError{"Failed to load certificate"};
        }

        if (wolfSSL_CTX_use_PrivateKey_file(mCtx.get(), keyFile, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        {
            throw FlushingError{"Failed to load private key"};
        }
    }

    void connectTcp(const std::string& hostname, int port)
    {
        struct hostent* hostEntry = gethostbyname(hostname.c_str());
        if (!hostEntry)
        {
            throw FlushingError{std::format("Failed to resolve hostname: {}", hostname)};
        }

        struct sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(port);
        serverAddr.sin_addr = *reinterpret_cast<struct in_addr*>(hostEntry->h_addr);
        sea_log("Connecting to {}, IP address {}", hostname, inet_ntoa(serverAddr.sin_addr));

        if (::connect(mSocketFd, reinterpret_cast<struct sockaddr*>(&serverAddr),
                     sizeof(serverAddr)) < 0)
        {
            throw FlushingError{std::format("Failed to connect to {}", hostname)};
        }
    }

    void setupTimestamping()
    {
#if PACKET_TIMESTAMPING_AVAILABLE
        int timestampFlags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE;

        if (setsockopt(mSocketFd, SOL_SOCKET, SO_TIMESTAMPING,
                      &timestampFlags, sizeof(timestampFlags)) < 0)
        {
            std::println("Warning: Failed to enable timestamping");
        } else
        {
            std::println("RX Timestamps enabled");
        }
#else
        std::println("Packet timestamping not available on this platform (Mac development)");
#endif
    }

    static int customReceiveCallback(WOLFSSL* ssl, char* buffer, int size, void* context)
    {
        auto* impl = static_cast<WolfSSLConnection::Impl*>(context);
        return impl->receiveWithTimestamp(ssl, buffer, size);
    }

    int receiveWithTimestamp(WOLFSSL*, char* buffer, int size)
    {
#if PACKET_TIMESTAMPING_AVAILABLE
        mRxTimestampNanos = 0;

        struct msghdr msg;
        struct iovec iov;
        char control[CMSG_SPACE(sizeof(struct scm_timestamping))];

        iov.iov_base = buffer;
        iov.iov_len = size;

        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control;
        msg.msg_controllen = sizeof(control);

        int flags = mReadImmediate ? MSG_DONTWAIT : 0;

        int received = recvmsg(mSocketFd, &msg, flags);
        if (received == -1)
        {
            switch (errno)
            {
#if EAGAIN != EWOULDBLOCK
                case EAGAIN:
#endif
                case EWOULDBLOCK:
                    return WOLFSSL_CBIO_ERR_WANT_READ;
                case ECONNRESET:
                    return WOLFSSL_CBIO_ERR_CONN_RST;
                case EINTR:
                    return WOLFSSL_CBIO_ERR_ISR;
                case ECONNREFUSED:
                    return WOLFSSL_CBIO_ERR_WANT_READ;
                case ECONNABORTED:
                    return WOLFSSL_CBIO_ERR_CONN_CLOSE;
                default:
                    return WOLFSSL_CBIO_ERR_GENERAL;
            }
        }

        if (received == 0)
        {
            std::println("WolfSSL internal receive returned 0");
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }

        for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
             cmsg != nullptr;
             cmsg = CMSG_NXTHDR(&msg, cmsg))
        {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING)
            {
                struct scm_timestamping* ts = reinterpret_cast<struct scm_timestamping*>(CMSG_DATA(cmsg));
                constexpr auto cNanosInSec = 1000000000LL;
                mRxTimestampNanos = ts->ts[0].tv_sec * cNanosInSec + ts->ts[0].tv_nsec;
                break;
            }
        }

        return received;
#else
        return recv(mSocketFd, buffer, size, 0);
#endif
    }

    CTXPtr mCtx{};
    SSLPtr mSsl{};
    TimestampNanos mRxTimestampNanos{};
    std::string mHostname{};
    int mPort{};
    int mSocketFd{-1};
    bool mReadImmediate{};
};

WolfSSLConnection::WolfSSLConnection() : mImpl(std::make_unique<Impl>()) {}
WolfSSLConnection::~WolfSSLConnection() = default;

void WolfSSLConnection::connect(const std::string& hostname, int port)
{
    mImpl->connect(hostname, port);
}

void WolfSSLConnection::disconnect()
{
    mImpl->disconnect();
}

std::size_t WolfSSLConnection::write(const void* data, std::size_t size)
{
    return mImpl->write(data, size);
}

std::size_t WolfSSLConnection::read(void* buffer, std::size_t size, bool readImmediate)
{
    return mImpl->read(buffer, size, readImmediate);
}

bool WolfSSLConnection::fin()
{
    return mImpl->fin();
}

WolfSSLConnection::TimestampNanos WolfSSLConnection::getLastRxTimestamp() const
{
    return mImpl->getLastRxTimestamp();
}

const std::string& WolfSSLConnection::getHostname() const
{
    return mImpl->getHostname();
}
