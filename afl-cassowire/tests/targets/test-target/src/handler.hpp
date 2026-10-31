// src/handler.hpp

#pragma once

#include "options.hpp"

#include <string>

namespace testtarget {

/**
 * @brief Handles one received message.
 *
 * Implements the CRASH/HANG/SLOW fault hooks (disabled in cache mode, which
 * has its own opt-in lottery crash) and dispatches to the active mode
 * (calc/http/cache), sending the reply on @p fd.
 */
void handle_message(int fd, const Options& opts, const std::string& data);

/**
 * @brief Serves one accepted connection.
 *
 * Reads framed requests (RequestReader) and forwards each to handle_message();
 * --multi_request keeps going until EOF, otherwise exactly one message is
 * handled.
 */
void handle_connection(int fd, const Options& opts);

} // namespace testtarget
