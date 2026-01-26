#pragma once

#include <seaplane/error.hpp>

#include <string>
#include <memory>
#include <unordered_map>
#include <vector>

class ConnectionCloseError : public FlushingError
{
public:
    ConnectionCloseError(const std::string& what) : FlushingError(what)
    {
    }
};

// Base class for SSL connections (both client and server)
class WolfSslConnectionBase
{
public:
    using TimestampNanos = std::int64_t;

    virtual ~WolfSslConnectionBase();

    WolfSslConnectionBase(const WolfSslConnectionBase&) = delete;
    WolfSslConnectionBase& operator=(const WolfSslConnectionBase&) = delete;
    WolfSslConnectionBase(WolfSslConnectionBase&&) = delete;
    WolfSslConnectionBase& operator=(WolfSslConnectionBase&&) = delete;

    void disconnect();

    std::size_t write(const void* data, std::size_t size);
    std::size_t read(void* buffer, std::size_t size, bool immediate = false);

    bool fin();
    TimestampNanos getLastRxTimestamp() const;

protected:
    WolfSslConnectionBase();

    class Impl;
    std::unique_ptr<Impl> mImpl;
};

// Client SSL connection - connects to a remote server
class WolfSslClientConnection : public WolfSslConnectionBase
{
public:
    WolfSslClientConnection();
    ~WolfSslClientConnection() override;

    void connect(const std::string& hostname, int port);
    const std::string& getHostname() const;

private:
    class ClientImpl;
};

// Backwards compatibility alias
using WolfSSLConnection = WolfSslClientConnection;
