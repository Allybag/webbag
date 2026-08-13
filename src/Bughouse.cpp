#include <Bughouse.hpp>
#include <HttpServer.hpp>

#include <glaze/glaze.hpp>

#include <seaplane/log.hpp>

#include <chrono>
#include <format>
#include <fstream>
#include <sstream>

class Bughouse::Impl
{
public:
    static constexpr std::string_view cEventsPath = "/chess/api/events";
    static constexpr size_t cMaxNameLength = 20;
    static constexpr size_t cMaxEventTypeLength = 12;
    static constexpr std::chrono::seconds cKeepAliveInterval{25};

    Impl(HttpServer& server, std::string savePath)
        : mServer(server), mSavePath(std::move(savePath))
    {
        load();

        server.addRoute("GET", "/chess/api/state", [this](const HttpRequest&) {
            return jsonResponse(snapshot());
        });

        server.addRoute("POST", "/chess/api/seat", [this](const HttpRequest& request) {
            claimSeat(request.body);
            HttpResponse response = jsonResponse(snapshot());
            publish();
            return response;
        });

        server.addRoute("POST", "/chess/api/event", [this](const HttpRequest& request) {
            if (!appendEvent(request.body))
            {
                HttpResponse response;
                response.statusCode = 400;
                response.statusMessage = "Bad Request";
                response.body = "bad event";
                response.headers["Content-Type"] = "text/plain";
                response.headers["Content-Length"] = std::to_string(response.body.size());
                return response;
            }

            HttpResponse response = jsonResponse(snapshot());
            publish();
            return response;
        });

        server.addStreamRoute("GET", std::string(cEventsPath), [this](const HttpRequest&) {
            HttpResponse response;
            response.headers["Content-Type"] = "text/event-stream";
            response.headers["Cache-Control"] = "no-store";
            response.body = "retry: 1500\n\ndata: " + snapshot() + "\n\n";
            return response;
        });

        // SSE keep-alive so proxies don't drop idle streams
        server.setTickHandler([this] {
            const auto now = std::chrono::steady_clock::now();
            if (now - mLastKeepAlive < cKeepAliveInterval)
            {
                return;
            }
            mLastKeepAlive = now;
            mServer.broadcast(std::string(cEventsPath), ": keep-alive\n\n");
        });
    }

private:
    std::string snapshot() const
    {
        return std::format("{{\"log\":{},\"seats\":{},\"now\":{}}}",
                           glz::write_json(mLog).value_or("[]"),
                           glz::write_json(mSeats).value_or("[null,null,null,null]"),
                           nowMillis());
    }

    void claimSeat(const std::string& body)
    {
        glz::generic json;
        if (glz::read_json(json, body) || !json.is_object())
        {
            return;
        }
        if (!json.contains("seat") || !json["seat"].is_number())
        {
            return;
        }

        int seat = static_cast<int>(json["seat"].get_number());
        if (seat < 0 || seat >= 4)
        {
            return;
        }

        std::string name = "Player";
        if (json.contains("name") && json["name"].is_string())
        {
            std::string candidate = trim(json["name"].get_string()).substr(0, cMaxNameLength);
            if (!candidate.empty())
            {
                name = candidate;
            }
        }

        auto& seats = mSeats.get_array();
        glz::generic::object_t claimed;
        claimed["name"] = name;
        seats[seat] = claimed;

        // the same name switching seats vacates the old one
        for (int i = 0; i < 4; ++i)
        {
            if (i == seat || !seats[i].is_object())
            {
                continue;
            }
            if (seats[i].contains("name") && seats[i]["name"].is_string() &&
                seats[i]["name"].get_string() == name)
            {
                seats[i] = glz::generic{};
            }
        }
    }

    bool appendEvent(const std::string& body)
    {
        glz::generic event;
        if (glz::read_json(event, body) || !event.is_object())
        {
            return false;
        }
        if (!event.contains("t") || !event["t"].is_string() ||
            event["t"].get_string().size() > cMaxEventTypeLength)
        {
            return false;
        }

        auto& log = mLog.get_array();
        bool start = event["t"].get_string() == "start";
        event["at"] = static_cast<double>(nowMillis());
        event["n"] = start ? 0.0 : static_cast<double>(log.size());
        if (start)  // a new game trims the history
        {
            log.clear();
        }
        log.push_back(std::move(event));
        return true;
    }

    void publish()
    {
        mServer.broadcast(std::string(cEventsPath), "data: " + snapshot() + "\n\n");
        save();
    }

    void load()
    {
        std::ifstream file(mSavePath, std::ios::binary);
        if (!file)
        {
            return;  // fresh start
        }
        std::ostringstream contents;
        contents << file.rdbuf();

        glz::generic root;
        if (glz::read_json(root, contents.str()) || !root.is_object())
        {
            sea_log("Bughouse: ignoring unparseable state file {}", mSavePath);
            return;
        }

        if (root.contains("log") && root["log"].is_array())
        {
            mLog = root["log"];
        }
        if (root.contains("seats") && root["seats"].is_array() &&
            root["seats"].get_array().size() == 4)
        {
            mSeats = root["seats"];
        }
        sea_log("Bughouse: loaded {} events from {}", mLog.get_array().size(), mSavePath);
    }

    void save() const
    {
        std::ofstream file(mSavePath, std::ios::binary | std::ios::trunc);
        if (!file)
        {
            return;  // read-only fs is fine
        }
        file << std::format("{{\"log\":{},\"seats\":{}}}",
                            glz::write_json(mLog).value_or("[]"),
                            glz::write_json(mSeats).value_or("[null,null,null,null]"));
    }

    static HttpResponse jsonResponse(std::string body)
    {
        HttpResponse response;
        response.body = std::move(body);
        response.headers["Content-Type"] = "application/json";
        response.headers["Cache-Control"] = "no-store";
        response.headers["Content-Length"] = std::to_string(response.body.size());
        return response;
    }

    static std::uint64_t nowMillis()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    static std::string trim(std::string text)
    {
        text.erase(0, text.find_first_not_of(" \t\r\n"));
        text.erase(text.find_last_not_of(" \t\r\n") + 1);
        return text;
    }

    HttpServer& mServer;
    std::string mSavePath;
    glz::generic mLog = glz::generic::array_t{};
    glz::generic mSeats = glz::generic::array_t(4);
    std::chrono::steady_clock::time_point mLastKeepAlive{std::chrono::steady_clock::now()};
};

Bughouse::Bughouse(HttpServer& server, std::string savePath)
    : mImpl(std::make_unique<Impl>(server, std::move(savePath)))
{
}

Bughouse::~Bughouse() = default;
