#include <WolfSslServer.hpp>
#include <WolfSslConnectionImpl.hpp>

#include <cerrno>
#include <fcntl.h>

// Shared server context for session caching
class ServerContext
{
public:
    static WOLFSSL_CTX* get()
    {
        static ServerContext instance;
        return instance.mCtx;
    }

private:
    ServerContext()
    {
        if (wolfSSL_Init() != WOLFSSL_SUCCESS)
        {
            throw FlushingError{"Failed to initialize WolfSSL"};
        }

        mCtx = wolfSSL_CTX_new(wolfTLS_server_method());
        if (!mCtx)
        {
            throw FlushingError{"Failed to create server SSL context"};
        }

        wolfSSL_CTX_SetMinVersion(mCtx, TLS1_2_VERSION);
        wolfSSL_CTX_set_verify(mCtx, WOLFSSL_VERIFY_NONE, nullptr);
        wolfSSL_CTX_set_session_cache_mode(mCtx, WOLFSSL_SESS_CACHE_SERVER);
        wolfSSL_CTX_set_timeout(mCtx, 3600);  // 1 hour session timeout

        loadServerCertificate();
    }

    ~ServerContext()
    {
        if (mCtx)
        {
            wolfSSL_CTX_free(mCtx);
        }
        wolfSSL_Cleanup();
    }

    void loadServerCertificate()
    {
        const char* certFile = std::getenv("WOLF_SERVER_CERT");
        const char* keyFile = std::getenv("WOLF_SERVER_KEY");

        if (!certFile || !keyFile)
        {
            throw FlushingError{"WOLF_SERVER_CERT and WOLF_SERVER_KEY must be set"};
        }

        if (wolfSSL_CTX_use_certificate_file(mCtx, certFile, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        {
            throw FlushingError{"Failed to load server certificate"};
        }

        if (wolfSSL_CTX_use_PrivateKey_file(mCtx, keyFile, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        {
            throw FlushingError{"Failed to load server private key"};
        }
    }

    WOLFSSL_CTX* mCtx{nullptr};
};

// Server-specific implementation
class WolfSslServerConnection::ServerImpl : public WolfSslConnectionBase::Impl
{
public:
    explicit ServerImpl(int clientSocketFd)
    {
        setupSocket(clientSocketFd);

        int flags = fcntl(mSocketFd, F_GETFL, 0);
        if (flags < 0 || fcntl(mSocketFd, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            throw FlushingError{"Failed to set O_NONBLOCK on server socket"};
        }

        // Use shared context for session caching
        mSharedCtx = ServerContext::get();
        createSslFromSharedCtx();
    }

    HandshakeStatus tryAccept()
    {
        if (wolfSSL_accept(mSsl.get()) == WOLFSSL_SUCCESS)
        {
            auto handshakeDuration = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::high_resolution_clock::now() - mHandshakeStart);
            bool resumed = wolfSSL_session_reused(mSsl.get());
            sea_log("Server SSL handshake completed in {} mics{}", handshakeDuration.count(),
                    resumed ? " (resumed session)" : "");
            return HandshakeStatus::Done;
        }

        int error = wolfSSL_get_error(mSsl.get(), 0);
        if (error == WOLFSSL_ERROR_WANT_READ)
        {
            return HandshakeStatus::WantRead;
        }
        if (error == WOLFSSL_ERROR_WANT_WRITE)
        {
            return HandshakeStatus::WantWrite;
        }

        char buffer[256];
        memset(buffer, 0, sizeof(buffer));
        wolfSSL_ERR_error_string(error, buffer);
        throw FlushingError{std::format("SSL accept failed: {} - {}", error, buffer)};
    }

    int socketFd() const
    {
        return mSocketFd;
    }

private:
    void createSslFromSharedCtx()
    {
        wolfSSL_CTX_SetIORecv(mSharedCtx, serverReceiveCallback);
        mSsl = SSLPtr(wolfSSL_new(mSharedCtx));
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

    // The shared client callback captures kernel RX timestamps; the server
    // just needs a plain read that reports WANT_READ on a drained
    // non-blocking socket (the non-Linux fallback in the shared callback
    // would treat that as a fatal error)
    static int serverReceiveCallback(WOLFSSL*, char* buffer, int size, void* context)
    {
        auto* impl = static_cast<ServerImpl*>(context);
        int received = static_cast<int>(recv(impl->mSocketFd, buffer, size, 0));
        if (received > 0)
        {
            return received;
        }
        if (received == 0)
        {
            return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }

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
            default:
                return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    std::chrono::high_resolution_clock::time_point mHandshakeStart{std::chrono::high_resolution_clock::now()};
    WOLFSSL_CTX* mSharedCtx{nullptr};
};

// Server connection implementation
WolfSslServerConnection::WolfSslServerConnection(int clientSocketFd)
{
    mImpl = std::make_unique<ServerImpl>(clientSocketFd);
}

WolfSslServerConnection::~WolfSslServerConnection() = default;

WolfSslServerConnection::HandshakeStatus WolfSslServerConnection::tryAccept()
{
    return static_cast<ServerImpl*>(mImpl.get())->tryAccept();
}

int WolfSslServerConnection::socketFd() const
{
    return static_cast<const ServerImpl*>(mImpl.get())->socketFd();
}
