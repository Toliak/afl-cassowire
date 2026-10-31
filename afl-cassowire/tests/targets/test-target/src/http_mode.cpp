// src/http_mode.cpp

#include "http_mode.hpp"

#include <cstring>
#include <string>

namespace testtarget {

const char* http_bad_request() {
    return "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
}

std::string http_response(const std::string& raw) {
    size_t line_end = raw.find('\n');
    if (line_end == std::string::npos) {
        line_end = raw.size();
    }
    std::string first = raw.substr(0, line_end);
    while (!first.empty() && (first.back() == '\r' || first.back() == ' ')) {
        first.pop_back();
    }

    const size_t method_end = first.find(' ');
    if (method_end == std::string::npos) {
        return http_bad_request();
    }
    const std::string method = first.substr(0, method_end);
    const std::string rest = first.substr(method_end + 1);
    const size_t path_end = rest.find(' ');
    const std::string path = path_end == std::string::npos ? rest : rest.substr(0, path_end);
    if (path.empty()) {
        return http_bad_request();
    }

    const char* status = "200 OK";
    const char* body = "OK";
    if (method != "GET") {
        status = "405 Method Not Allowed";
        body = "";
    } else if (path != "/") {
        status = "404 Not Found";
        body = "";
    }
    return std::string("HTTP/1.1 ") + status + "\r\nContent-Length: " +
        std::to_string(std::strlen(body)) + "\r\nConnection: close\r\n\r\n" + body;
}

} // namespace testtarget
