#pragma once

#include <WolfSslConnection.hpp>

#include <memory>

// Server SSL connection - accepts connections from clients
class WolfSslServerConnection : public WolfSslConnectionBase
{
public:
    enum class HandshakeStatus { Done, WantRead, WantWrite };

    // Takes an already-connected socket fd from accept() and switches it to
    // non-blocking mode
    explicit WolfSslServerConnection(int clientSocketFd);
    ~WolfSslServerConnection() override;

    // Drives the wolfSSL_accept() handshake; on WantRead/WantWrite call again
    // once the socket polls ready in that direction
    HandshakeStatus tryAccept();

    int socketFd() const;

private:
    class ServerImpl;
};
