#include <WolfSslServer.hpp>
#include <WolfSslConnectionImpl.hpp>

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
        : mClientSocketFd(clientSocketFd)
    {
    }

    void accept()
    {
        setupSocket(mClientSocketFd);

        // Use shared context for session caching
        mSharedCtx = ServerContext::get();
        createSslFromSharedCtx();

        auto handshakeStart = std::chrono::high_resolution_clock::now();

        if (wolfSSL_accept(mSsl.get()) != WOLFSSL_SUCCESS)
        {
            char buffer[256];
            int error = wolfSSL_get_error(mSsl.get(), 0);
            memset(buffer, 0, sizeof(buffer));
            wolfSSL_ERR_error_string(error, buffer);
            throw FlushingError{std::format("SSL accept failed: {} - {}", error, buffer)};
        }

        auto handshakeEnd = std::chrono::high_resolution_clock::now();
        auto handshakeDuration = std::chrono::duration_cast<std::chrono::microseconds>(
            handshakeEnd - handshakeStart);

        bool resumed = wolfSSL_session_reused(mSsl.get());
        sea_log("Server SSL handshake completed in {} mics{}", handshakeDuration.count(),
                resumed ? " (resumed session)" : "");
    }

private:
    void createSslFromSharedCtx()
    {
        wolfSSL_CTX_SetIORecv(mSharedCtx, customReceiveCallback);
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

    int mClientSocketFd;
    WOLFSSL_CTX* mSharedCtx{nullptr};
};

// Server connection implementation
WolfSslServerConnection::WolfSslServerConnection(int clientSocketFd)
{
    mImpl = std::make_unique<ServerImpl>(clientSocketFd);
}

WolfSslServerConnection::~WolfSslServerConnection() = default;

void WolfSslServerConnection::accept()
{
    static_cast<ServerImpl*>(mImpl.get())->accept();
}
