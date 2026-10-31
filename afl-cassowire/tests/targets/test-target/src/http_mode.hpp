// src/http_mode.hpp

#pragma once

#include <string>

namespace testtarget {

/**
 * @brief Fixed 400 reply shared by the http and cache modes for malformed requests.
 */
const char* http_bad_request();

/**
 * @brief Handles one http-mode request.
 *
 * Parses only the request line: GET / -> 200 OK, other methods -> 405,
 * other paths -> 404, anything malformed -> 400.
 */
std::string http_response(const std::string& raw);

} // namespace testtarget
