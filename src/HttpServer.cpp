#include <HttpServer.hpp>
#include <WolfSslServer.hpp>

#include <seaplane/error.hpp>
#include <seaplane/log.hpp>

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <poll.h>

#include <cstring>
#include <fstream>
#include <filesystem>
#include <sstream>

class HttpServer::Impl
{
public:
    static constexpr size_t cMaxBufferSize = 64 * 1024;
    static constexpr size_t cMaxBodySize = 10 * 1024 * 1024;  // 10 MB

    void setStaticRoot(const std::string& path)
    {
        mStaticRoot = path;
    }

    void setHostname(const std::string& hostname)
    {
        mHostname = hostname;
    }

    void addRoute(const std::string& method, const std::string& path, Handler handler)
    {
        mRoutes[method + " " + path] = std::move(handler);
    }

    void listen(int port)
    {
        mListenFd = socket(AF_INET, SOCK_STREAM, 0);
        if (mListenFd < 0)
        {
            throw FlushingError{"Failed to create listen socket"};
        }

        int opt = 1;
        if (setsockopt(mListenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            throw FlushingError{"Failed to set SO_REUSEADDR"};
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(mListenFd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
        {
            throw FlushingError{std::format("Failed to bind to port {}", port)};
        }

        if (::listen(mListenFd, 10) < 0)
        {
            throw FlushingError{"Failed to listen on socket"};
        }

        mPort = port;
        sea_log("HTTPS server listening on port {}", port);
    }

    void listenHttpRedirect(int port)
    {
        mHttpRedirectFd = socket(AF_INET, SOCK_STREAM, 0);
        if (mHttpRedirectFd < 0)
        {
            throw FlushingError{"Failed to create HTTP redirect socket"};
        }

        int opt = 1;
        if (setsockopt(mHttpRedirectFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            throw FlushingError{"Failed to set SO_REUSEADDR on HTTP redirect socket"};
        }

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(mHttpRedirectFd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
        {
            throw FlushingError{std::format("Failed to bind HTTP redirect to port {}", port)};
        }

        if (::listen(mHttpRedirectFd, 10) < 0)
        {
            throw FlushingError{"Failed to listen on HTTP redirect socket"};
        }

        sea_log("HTTP redirect server listening on port {}", port);
    }

    void run()
    {
        mRunning = true;

        while (mRunning)
        {
            std::vector<pollfd> fds;
            fds.push_back({mListenFd, POLLIN, 0});
            if (mHttpRedirectFd >= 0)
            {
                fds.push_back({mHttpRedirectFd, POLLIN, 0});
            }

            int ret = poll(fds.data(), fds.size(), 1000);
            if (ret < 0)
            {
                if (mRunning)
                {
                    sea_log("Poll failed: {}", strerror(errno));
                }
                continue;
            }
            if (ret == 0)
            {
                continue;  // Timeout, check mRunning
            }

            // Check HTTPS socket
            if (fds[0].revents & POLLIN)
            {
                struct sockaddr_in clientAddr{};
                socklen_t clientLen = sizeof(clientAddr);
                int clientFd = ::accept(mListenFd, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen);
                if (clientFd >= 0)
                {
                    sea_log("HTTPS connection from {}", inet_ntoa(clientAddr.sin_addr));
                    try
                    {
                        handleConnection(clientFd);
                    }
                    catch (const std::exception& e)
                    {
                        sea_log("Error handling HTTPS connection: {}", e.what());
                    }
                }
            }

            // Check HTTP redirect socket
            if (fds.size() > 1 && (fds[1].revents & POLLIN))
            {
                struct sockaddr_in clientAddr{};
                socklen_t clientLen = sizeof(clientAddr);
                int clientFd = ::accept(mHttpRedirectFd, reinterpret_cast<struct sockaddr*>(&clientAddr), &clientLen);
                if (clientFd >= 0)
                {
                    sea_log("HTTP redirect for {}", inet_ntoa(clientAddr.sin_addr));
                    try
                    {
                        handleHttpRedirect(clientFd);
                    }
                    catch (const std::exception& e)
                    {
                        sea_log("Error handling HTTP redirect: {}", e.what());
                    }
                }
            }
        }
    }

    void stop()
    {
        mRunning = false;
        if (mListenFd >= 0)
        {
            close(mListenFd);
            mListenFd = -1;
        }
        if (mHttpRedirectFd >= 0)
        {
            close(mHttpRedirectFd);
            mHttpRedirectFd = -1;
        }
    }

private:
    void handleHttpRedirect(int clientFd)
    {
        // Set a receive timeout so a silent client can't block the server
        struct timeval tv{.tv_sec = 5, .tv_usec = 0};
        setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Read enough to get the request line (we just need the path)
        char buffer[4096];
        ssize_t bytesRead = recv(clientFd, buffer, sizeof(buffer) - 1, 0);

        std::string path = "/";
        if (bytesRead > 0)
        {
            buffer[bytesRead] = '\0';
            // Parse "GET /path HTTP/1.1"
            char* firstSpace = strchr(buffer, ' ');
            if (firstSpace)
            {
                char* secondSpace = strchr(firstSpace + 1, ' ');
                if (secondSpace)
                {
                    path = std::string(firstSpace + 1, secondSpace);
                }
            }
        }

        std::string response = std::format(
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Location: https://{}{}\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n",
            mHostname, path);

        send(clientFd, response.data(), response.size(), 0);
        close(clientFd);
    }

    void handleConnection(int clientFd)
    {
        WolfSslServerConnection conn(clientFd);
        conn.accept();

        HttpRequest request = parseRequest(conn);
        HttpResponse response = routeRequest(request);
        sendResponse(conn, response);
    }

    HttpRequest parseRequest(WolfSslServerConnection& conn)
    {
        HttpRequest request;
        mReadIndex = 0;
        mConn = &conn;

        // Read request line
        std::string requestLine = readHttpLine();
        parseRequestLine(requestLine, request);

        // Read headers
        while (true)
        {
            std::string line = readHttpLine();
            if (line.empty())
            {
                break;
            }
            parseHeaderLine(line, request);
        }

        // Read body if Content-Length specified
        auto it = request.headers.find("Content-Length");
        if (it != request.headers.end())
        {
            size_t contentLength = std::stoul(it->second);
            if (contentLength > cMaxBodySize)
            {
                throw FlushingError{"Request body too large"};
            }
            request.body = readExactBytes(contentLength);
        }

        mConn = nullptr;
        return request;
    }

    void parseRequestLine(const std::string& line, HttpRequest& request)
    {
        size_t firstSpace = line.find(' ');
        size_t secondSpace = line.find(' ', firstSpace + 1);

        if (firstSpace != std::string::npos && secondSpace != std::string::npos)
        {
            request.method = line.substr(0, firstSpace);
            request.path = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
        }
    }

    void parseHeaderLine(const std::string& line, HttpRequest& request)
    {
        size_t colon = line.find(':');
        if (colon != std::string::npos)
        {
            std::string name = line.substr(0, colon);
            std::string value = line.substr(colon + 1);

            // Trim whitespace
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            request.headers[name] = value;
        }
    }

    HttpResponse routeRequest(const HttpRequest& request)
    {
        sea_log("Request: {} {}", request.method, request.path);

        // Check registered routes for exact match
        std::string routeKey = request.method + " " + request.path;
        auto it = mRoutes.find(routeKey);
        if (it != mRoutes.end())
        {
            return it->second(request);
        }

        // Try static file serving
        if (!mStaticRoot.empty())
        {
            return serveStaticFile(request.path);
        }

        return make404();
    }

    HttpResponse serveStaticFile(const std::string& requestPath)
    {
        std::string path = requestPath;
        if (path == "/")
        {
            path = "/index.html";
        }

        std::filesystem::path filePath = mStaticRoot + path;

        // Security: prevent directory traversal
        std::filesystem::path canonicalRoot = std::filesystem::weakly_canonical(mStaticRoot);
        std::filesystem::path canonicalFile = std::filesystem::weakly_canonical(filePath);

        if (canonicalFile.string().find(canonicalRoot.string()) != 0)
        {
            sea_log("Directory traversal attempt blocked: {}", requestPath);
            return make404();
        }

        // Try exact path, then .html extension, then directory index
        if (!std::filesystem::exists(filePath) || !std::filesystem::is_regular_file(filePath))
        {
            std::filesystem::path withHtml = filePath;
            withHtml += ".html";
            std::filesystem::path dirIndex = filePath / "index.html";

            if (std::filesystem::is_regular_file(withHtml))
            {
                filePath = withHtml;
            }
            else if (std::filesystem::is_regular_file(dirIndex))
            {
                filePath = dirIndex;
            }
            else
            {
                return make404();
            }
        }

        std::ifstream file(filePath, std::ios::binary);
        if (!file)
        {
            return make404();
        }

        std::ostringstream contents;
        contents << file.rdbuf();

        HttpResponse response;
        response.statusCode = 200;
        response.statusMessage = "OK";
        response.body = contents.str();
        response.headers["Content-Type"] = getMimeType(filePath.extension().string());
        response.headers["Content-Length"] = std::to_string(response.body.length());

        return response;
    }

    std::string getMimeType(const std::string& extension)
    {
        static const std::unordered_map<std::string, std::string> mimeTypes = {
            {".html", "text/html"},
            {".css", "text/css"},
            {".js", "application/javascript"},
            {".json", "application/json"},
            {".png", "image/png"},
            {".jpg", "image/jpeg"},
            {".jpeg", "image/jpeg"},
            {".ico", "image/x-icon"},
            {".svg", "image/svg+xml"},
            {".txt", "text/plain"},
            {".xml", "application/xml"},
            {".woff", "font/woff"},
            {".woff2", "font/woff2"},
            {".ttf", "font/ttf"},
        };

        auto it = mimeTypes.find(extension);
        if (it != mimeTypes.end())
        {
            return it->second;
        }
        return "application/octet-stream";
    }

    HttpResponse make404()
    {
        HttpResponse response;
        response.statusCode = 404;
        response.statusMessage = "Not Found";
        response.body = "<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>";
        response.headers["Content-Type"] = "text/html";
        response.headers["Content-Length"] = std::to_string(response.body.length());
        return response;
    }

    void sendResponse(WolfSslServerConnection& conn, const HttpResponse& response)
    {
        std::ostringstream responseStream;
        responseStream << "HTTP/1.1 " << response.statusCode << " " << response.statusMessage << "\r\n";

        for (const auto& [name, value] : response.headers)
        {
            responseStream << name << ": " << value << "\r\n";
        }

        responseStream << "Connection: close\r\n";
        responseStream << "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n";
        responseStream << "\r\n";
        responseStream << response.body;

        std::string responseStr = responseStream.str();
        conn.write(responseStr.data(), responseStr.size());
    }

    // HTTP parsing helpers (similar to HttpClient)
    void fillBuffer()
    {
        if (mReadIndex == sizeof(mReadBuffer))
        {
            throw FlushingError{"HTTP buffer full"};
        }

        std::size_t bytesRead = mConn->read(mReadBuffer + mReadIndex,
                                            sizeof(mReadBuffer) - mReadIndex);
        if (bytesRead == 0)
        {
            throw FlushingError{"Connection closed while reading HTTP request"};
        }

        mReadIndex += bytesRead;
    }

    void consumeBuffer(std::size_t bytes)
    {
        if (bytes > mReadIndex)
        {
            throw FlushingError{"Consuming more bytes than available"};
        }

        if (bytes < mReadIndex)
        {
            std::memmove(mReadBuffer, mReadBuffer + bytes, mReadIndex - bytes);
        }
        mReadIndex -= bytes;
    }

    std::string readHttpLine()
    {
        std::string line;

        while (true)
        {
            if (mReadIndex == 0)
            {
                fillBuffer();
            }

            for (size_t i = 0; i < mReadIndex; ++i)
            {
                char c = mReadBuffer[i];

                if (c == '\r' && i + 1 < mReadIndex && mReadBuffer[i + 1] == '\n')
                {
                    line.append(mReadBuffer, i);
                    consumeBuffer(i + 2);
                    return line;
                }
            }

            line.append(mReadBuffer, mReadIndex);
            mReadIndex = 0;
        }
    }

    std::string readExactBytes(size_t count)
    {
        std::string result;
        result.reserve(count);

        while (result.length() < count)
        {
            if (mReadIndex == 0)
            {
                fillBuffer();
            }

            size_t byteCount = std::min(count - result.length(), mReadIndex);
            result.append(mReadBuffer, byteCount);
            consumeBuffer(byteCount);
        }

        return result;
    }

    std::unordered_map<std::string, Handler> mRoutes;
    std::string mStaticRoot;
    std::string mHostname;
    int mListenFd{-1};
    int mHttpRedirectFd{-1};
    int mPort{0};
    bool mRunning{false};

    // Per-request state for parsing
    WolfSslServerConnection* mConn{nullptr};
    std::size_t mReadIndex{0};
    char mReadBuffer[cMaxBufferSize];
};

HttpServer::HttpServer() : mImpl(std::make_unique<Impl>()) {}
HttpServer::~HttpServer() = default;

void HttpServer::setStaticRoot(const std::string& path)
{
    mImpl->setStaticRoot(path);
}

void HttpServer::setHostname(const std::string& hostname)
{
    mImpl->setHostname(hostname);
}

void HttpServer::addRoute(const std::string& method, const std::string& path, Handler handler)
{
    mImpl->addRoute(method, path, std::move(handler));
}

void HttpServer::listen(int port)
{
    mImpl->listen(port);
}

void HttpServer::listenHttpRedirect(int port)
{
    mImpl->listenHttpRedirect(port);
}

void HttpServer::run()
{
    mImpl->run();
}

void HttpServer::stop()
{
    mImpl->stop();
}
