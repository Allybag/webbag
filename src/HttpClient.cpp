#include <HttpClient.hpp>

#include <seaplane/error.hpp>
#include <seaplane/log.hpp>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  // For TCP_NODELAY and TCP_KEEPALIVE
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include <array>
#include <cstring>
#include <thread>
#include <vector>

class WolfHttpClient::Impl
{
public:
    static constexpr size_t cMaxBufferSize = 64 * 1024;

    void connect(const std::string& hostname, int port = 443)
    {
        mConnection.connect(hostname, port);
        mReadIndex = 0;
    }

    void disconnect() {
        mConnection.disconnect();
        mReadIndex = 0;
    }

    WolfHttpClient::HttpResponse httpPost(const std::string& path, const std::string& body,
                                         const std::vector<std::string>& extraHeaders = {})
    {
        return makeHttpRequest("POST", path, body, extraHeaders);
    }

    WolfHttpClient::HttpResponse httpGet(const std::string& path,
                                        const std::vector<std::string>& extraHeaders = {})
    {
        return makeHttpRequest("GET", path, "", extraHeaders);
    }

private:
    WolfHttpClient::HttpResponse makeHttpRequest(const std::string& method, const std::string& path,
                                               const std::string& body, const std::vector<std::string>& extraHeaders)
    {
        if (mReadIndex > 0)
        {
            std::println("Warning: {} bytes of leftover data in buffer before new request", mReadIndex);
            std::println("Leftover data: '{}'", std::string(mReadBuffer, std::min(mReadIndex, size_t(100))));

            std::fflush(nullptr);
            std::abort();
        }

        sendHttpRequest(method, path, body, extraHeaders);
        return readHttpResponse();
    }

    void sendHttpRequest(const std::string& method, const std::string& path,
                        const std::string& body, const std::vector<std::string>& extraHeaders)
    {
        static constexpr auto cMaxRequestSize{8192};
        std::array<char, cMaxRequestSize> request{};
        int written{};
        auto result = std::format_to_n(request.begin(), cMaxRequestSize - written, "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: WebBag\r\nConnection: keep-alive\r\n",
            method, path, mConnection.getHostname());
        written += result.size;

        for (const auto& extraHeader : extraHeaders)
        {
            result = std::format_to_n(result.out, cMaxRequestSize - written, "{}\r\n", extraHeader);
            written += result.size;
        }

        if (body.empty())
        {
            result = std::format_to_n(result.out, cMaxRequestSize - written, "\r\n");
            written += result.size;
        }
        else
        {
            result = std::format_to_n(result.out, cMaxRequestSize - written, "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}",
                                    body.length(), body);
            written += result.size;
        }

        if (written >= cMaxRequestSize)
        {
            throw FlushingError{std::format("Attempted to write http request of {} bytes vs max {}", written, cMaxRequestSize)};
        }

        mConnection.write(request.data(), written);
    }

    WolfHttpClient::HttpResponse readHttpResponse()
    {
        WolfHttpClient::HttpResponse response;
        std::string rawHeaders;
        bool readingHeaders = true;
        size_t contentLength = 0;
        bool isChunked = false;

        while (readingHeaders)
        {
            std::string line = readHttpLine();

            if (line.empty())
            {
                readingHeaders = false;
            }
            else if (response.statusCode == 0)
            {
                parseStatusLine(line, response);
            }
            else
            {
                parseHeaderLine(line, response, contentLength, isChunked);
            }

            rawHeaders += line + "\r\n";
        }

        if (isChunked)
        {
            response.body = readChunkedBody();
        }
        else if (contentLength > 0)
        {
            response.body = readExactBytes(contentLength);
        }

        return response;
    }

    void fillBuffer()
    {
        if (mReadIndex == sizeof(mReadBuffer))
        {
            throw FlushingError{"HTTP buffer full"};
        }

        std::size_t bytesRead = mConnection.read(mReadBuffer + mReadIndex,
                                                   sizeof(mReadBuffer) - mReadIndex);
        if (bytesRead == 0)
        {
            sea_log("Connection closed while reading HTTP response");
            throw FlushingError{"Connection closed while reading HTTP line"};
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

    void parseStatusLine(const std::string& line, WolfHttpClient::HttpResponse& response)
    {
        size_t firstSpace = line.find(' ');
        size_t secondSpace = line.find(' ', firstSpace + 1);

        if (firstSpace != std::string::npos && secondSpace != std::string::npos)
        {
            std::string statusCode = line.substr(firstSpace + 1, secondSpace - firstSpace - 1);
            response.statusCode = std::stoi(statusCode);
            response.statusMessage = line.substr(secondSpace + 1);
        }
        else
        {
            std::println("Failed to parse HTTP status from line: {}", line);
        }
    }

    void parseHeaderLine(const std::string& line, WolfHttpClient::HttpResponse& response, size_t& contentLength, bool& isChunked)
    {
        size_t colon = line.find(':');
        if (colon != std::string::npos)
        {
            std::string name = line.substr(0, colon);
            std::string value = line.substr(colon + 1);

            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            response.headers[name] = value;

            if (name == "Content-Length")
            {
                contentLength = std::stoul(value);
            }
            else if (name == "Transfer-Encoding" && value == "chunked")
            {
                isChunked = true;
            }
        }
    }

    std::string readChunkedBody()
    {
        std::string body;

        while (true)
        {
            std::string chunkSizeLine = readHttpLine();

            size_t semicolon = chunkSizeLine.find(';');
            std::string chunkSizeStr = (semicolon != std::string::npos) ?
                chunkSizeLine.substr(0, semicolon) : chunkSizeLine;

            size_t chunkSize = 0;
            try
            {
                chunkSize = std::stoul(chunkSizeStr, nullptr, 16);
            }
            catch (const std::exception& e)
            {
                std::println("Error parsing chunk size '{}': {}", chunkSizeStr, e.what());
                break;
            }

            if (chunkSize == 0)
            {
                while (true)
                {
                    std::string trailerLine = readHttpLine();
                    if (trailerLine.empty()) {
                        break;
                    }
                }
                break;
            }

            std::string chunkData = readExactBytes(chunkSize);
            body += chunkData;

            std::string crlf = readExactBytes(2);
            if (crlf != "\r\n")
            {
                throw FlushingError{std::format("Received dodgy delimiter bytes: {}", crlf)};
            }
        }

        if (mReadIndex > 0)
        {
            std::println("Warning: {} bytes left in buffer after chunked read", mReadIndex);
        }

        return body;
    }

    WolfSSLConnection mConnection;
    std::size_t mReadIndex{};
    char mReadBuffer[cMaxBufferSize];
};

WolfHttpClient::WolfHttpClient() : mImpl(std::make_unique<Impl>()) {}
WolfHttpClient::~WolfHttpClient() = default;

void WolfHttpClient::connect(const std::string& hostname, int port)
{
    mImpl->connect(hostname, port);
}

void WolfHttpClient::disconnect()
{
    mImpl->disconnect();
}

WolfHttpClient::HttpResponse WolfHttpClient::httpPost(const std::string& path, const std::string& body,
                                                     const std::vector<std::string>& extraHeaders)
{
    return mImpl->httpPost(path, body, extraHeaders);
}

WolfHttpClient::HttpResponse WolfHttpClient::httpGet(const std::string& path,
                                                    const std::vector<std::string>& extraHeaders)
{
    return mImpl->httpGet(path, extraHeaders);
}

