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

class WolfSSLConnection
{
    using TimestampNanos = std::int64_t;
public:
    WolfSSLConnection();
    ~WolfSSLConnection();

    WolfSSLConnection(const WolfSSLConnection&) = delete;
    WolfSSLConnection& operator=(const WolfSSLConnection&) = delete;
    WolfSSLConnection(WolfSSLConnection&&) = delete;
    WolfSSLConnection& operator=(WolfSSLConnection&&) = delete;

    void connect(const std::string& hostname, int port);
    void disconnect();

    std::size_t write(const void* data, std::size_t size);
    std::size_t read(void* buffer, std::size_t size, bool immediate = false);

    bool fin();
    TimestampNanos getLastRxTimestamp() const;
    const std::string& getHostname() const;

private:
    class Impl;
    std::unique_ptr<Impl> mImpl;
};
