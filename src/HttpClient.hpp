#pragma once

#include <WolfSslConnection.hpp>

#include <seaplane/error.hpp>

#include <string>
#include <memory>
#include <unordered_map>
#include <vector>

class WolfHttpClient
{
public:
    struct HttpResponse
    {
        int statusCode = 0;
        std::string statusMessage;
        std::unordered_map<std::string, std::string> headers;
        std::string body;
    };

    WolfHttpClient();
    ~WolfHttpClient();

    WolfHttpClient(const WolfHttpClient&) = delete;
    WolfHttpClient& operator=(const WolfHttpClient&) = delete;
    WolfHttpClient(WolfHttpClient&&) = delete;
    WolfHttpClient& operator=(WolfHttpClient&&) = delete;

    void connect(const std::string& hostname, int port = 443);
    void disconnect();

    HttpResponse httpPost(const std::string& path, const std::string& body,
                         const std::vector<std::string>& headers = {});
    HttpResponse httpGet(const std::string& path,
                        const std::vector<std::string>& headers = {});

private:
    class Impl;
    std::unique_ptr<Impl> mImpl;
};

