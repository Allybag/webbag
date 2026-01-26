#include <HttpServer.hpp>

#include <csignal>
#include <iostream>

static HttpServer* gServer = nullptr;

void signalHandler(int)
{
    if (gServer)
    {
        gServer->stop();
    }
}

int main()
{
    std::signal(SIGINT, signalHandler);

    HttpServer server;
    gServer = &server;

    server.setStaticRoot("./www");

    server.addRoute("GET", "/api/health", [](const HttpRequest&) {
        HttpResponse response;
        response.statusCode = 200;
        response.statusMessage = "OK";
        response.body = R"({"status":"healthy"})";
        response.headers["Content-Type"] = "application/json";
        response.headers["Content-Length"] = std::to_string(response.body.length());
        return response;
    });

    server.addRoute("GET", "/api/echo", [](const HttpRequest& req) {
        HttpResponse response;
        response.statusCode = 200;
        response.statusMessage = "OK";
        response.body = "You requested: " + req.path;
        response.headers["Content-Type"] = "text/plain";
        response.headers["Content-Length"] = std::to_string(response.body.length());
        return response;
    });

    std::cout << "Starting HTTPS server on port 8443..." << std::endl;
    std::cout << "Test with:" << std::endl;
    std::cout << "  curl -k https://localhost:8443/" << std::endl;
    std::cout << "  curl -k https://localhost:8443/api/health" << std::endl;
    std::cout << "Press Ctrl+C to stop." << std::endl;

    server.listen(8443);
    server.run();

    return 0;
}
