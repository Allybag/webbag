#include <WolfSslConnectionImpl.hpp>

#include <array>

// Client-specific implementation
class WolfSslClientConnection::ClientImpl : public WolfSslConnectionBase::Impl
{
public:
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

    std::size_t write(const void* data, std::size_t size)
    {
        if (fin())
        {
            sea_log("Received fin, connection closed by other end, reconnecting to {}", mHostname);
            disconnect();
            connect(mHostname, mPort);
        }

        return Impl::write(data, size);
    }

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

    std::string mHostname{};
    int mPort{};
};

// Base class implementation
WolfSslConnectionBase::WolfSslConnectionBase() = default;
WolfSslConnectionBase::~WolfSslConnectionBase() = default;

void WolfSslConnectionBase::disconnect()
{
    mImpl->disconnect();
}

std::size_t WolfSslConnectionBase::write(const void* data, std::size_t size)
{
    return mImpl->write(data, size);
}

std::size_t WolfSslConnectionBase::read(void* buffer, std::size_t size, bool readImmediate)
{
    return mImpl->read(buffer, size, readImmediate);
}

bool WolfSslConnectionBase::fin()
{
    return mImpl->fin();
}

WolfSslConnectionBase::TimestampNanos WolfSslConnectionBase::getLastRxTimestamp() const
{
    return mImpl->getLastRxTimestamp();
}

// Client connection implementation
WolfSslClientConnection::WolfSslClientConnection()
{
    mImpl = std::make_unique<ClientImpl>();
}

WolfSslClientConnection::~WolfSslClientConnection() = default;

void WolfSslClientConnection::connect(const std::string& hostname, int port)
{
    static_cast<ClientImpl*>(mImpl.get())->connect(hostname, port);
}

const std::string& WolfSslClientConnection::getHostname() const
{
    return static_cast<ClientImpl*>(mImpl.get())->getHostname();
}
