#pragma once

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

struct HttpRequest
{
    std::string method;
    std::string path;
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

struct HttpResponse
{
    int statusCode = 200;
    std::string statusMessage = "OK";
    std::unordered_map<std::string, std::string> headers;
    std::string body;
};

class HttpServer
{
public:
    using Handler = std::function<HttpResponse(const HttpRequest&)>;

    HttpServer();
    ~HttpServer();

    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;
    HttpServer(HttpServer&&) = delete;
    HttpServer& operator=(HttpServer&&) = delete;

    void setStaticRoot(const std::string& path);
    void setHostname(const std::string& hostname);
    void addRoute(const std::string& method, const std::string& path, Handler handler);
    void listen(int port);
    void listenHttpRedirect(int port);  // Listen for HTTP and redirect to HTTPS
    void run();  // Single-threaded accept loop
    void stop();

private:
    class Impl;
    std::unique_ptr<Impl> mImpl;
};
