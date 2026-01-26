#pragma once

#include <WolfSslConnection.hpp>

#include <memory>

// Server SSL connection - accepts connections from clients
class WolfSslServerConnection : public WolfSslConnectionBase
{
public:
    // Takes an already-connected socket fd from accept()
    explicit WolfSslServerConnection(int clientSocketFd);
    ~WolfSslServerConnection() override;

    // Performs wolfSSL_accept() handshake
    void accept();

private:
    class ServerImpl;
};
