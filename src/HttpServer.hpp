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

    // Route whose response leaves the connection open for later broadcast()
    // pushes (e.g. Server-Sent Events). The handler supplies the response
    // headers and any initial payload; no Content-Length or Connection: close
    // headers are added.
    void addStreamRoute(const std::string& method, const std::string& path, Handler handler);

    // Write raw bytes to every open stream connection established via path
    void broadcast(const std::string& path, const std::string& data);

    // Called from run() after every poll iteration (at least ~1Hz)
    void setTickHandler(std::function<void()> handler);
    void listen(int port);
    void listenHttpRedirect(int port);  // Listen for HTTP and redirect to HTTPS
    void run();  // Single-threaded accept loop
    void stop();

private:
    class Impl;
    std::unique_ptr<Impl> mImpl;
};
