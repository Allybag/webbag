#include <WolfSslServer.hpp>
#include <WolfSslConnectionImpl.hpp>

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

        mCtx = CTXPtr(wolfSSL_CTX_new(wolfTLS_server_method()));
        if (!mCtx)
        {
            throw FlushingError{"Failed to create server SSL context"};
        }

        wolfSSL_CTX_SetMinVersion(mCtx.get(), TLS1_2_VERSION);
        wolfSSL_CTX_set_verify(mCtx.get(), WOLFSSL_VERIFY_NONE, nullptr);

        loadServerCertificate();
        createSsl();

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

        sea_log("Server SSL handshake completed in {} mics", handshakeDuration.count());
    }

private:
    void loadServerCertificate()
    {
        const char* certFile = std::getenv("WOLF_SERVER_CERT");
        const char* keyFile = std::getenv("WOLF_SERVER_KEY");

        if (!certFile || !keyFile)
        {
            throw FlushingError{"WOLF_SERVER_CERT and WOLF_SERVER_KEY must be set"};
        }

        if (wolfSSL_CTX_use_certificate_file(mCtx.get(), certFile, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        {
            throw FlushingError{"Failed to load server certificate"};
        }

        if (wolfSSL_CTX_use_PrivateKey_file(mCtx.get(), keyFile, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS)
        {
            throw FlushingError{"Failed to load server private key"};
        }
    }

    int mClientSocketFd;
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
