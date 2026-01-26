#include <HttpServer.hpp>

#include <csignal>
#include <cstring>
#include <print>

static HttpServer* gServer = nullptr;

void signalHandler(int)
{
    if (gServer)
    {
        gServer->stop();
    }
}

int main(int argc, char* argv[])
{
    std::signal(SIGINT, signalHandler);

    bool prod = false;
    for (int i = 1; i < argc; ++i)
    {
        if (std::strcmp(argv[i], "-prod") == 0)
        {
            prod = true;
        }
    }

    int port = prod ? 443 : 8443;

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

    server.listen(port);

    if (prod)
    {
        server.setHostname("allybag.org");
        server.listenHttpRedirect(80);
        std::println("Starting HTTPS server on port 443 with HTTP redirect on port 80...");
    }
    else
    {
        std::println("Starting HTTPS server on port {}...", port);
    }
    std::println("Press Ctrl+C to stop.");

    server.run();

    return 0;
}
