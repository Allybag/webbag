#pragma once

#include <memory>
#include <string>

class HttpServer;

// State/sync server for the bughouse chess client (www/chess/index.html):
// an append-only event log plus a seat registry, pushed to every browser
// over Server-Sent Events. Events are stamped with server time so all
// players compute identical clocks; the chess rules live in the client.
class Bughouse
{
public:
    // Registers the /chess/api/* routes and the SSE keep-alive tick on
    // server. Match state persists to savePath across restarts.
    Bughouse(HttpServer& server, std::string savePath);
    ~Bughouse();

    Bughouse(const Bughouse&) = delete;
    Bughouse& operator=(const Bughouse&) = delete;
    Bughouse(Bughouse&&) = delete;
    Bughouse& operator=(Bughouse&&) = delete;

private:
    class Impl;
    std::unique_ptr<Impl> mImpl;
};
