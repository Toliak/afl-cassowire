// src/calc_mode.hpp

#pragma once

#include <string>

namespace testtarget {

/**
 * @brief Handles one calc-mode request line "<lhs> <op> <rhs>".
 *
 * Returns the reply line ("ERR\n" on malformed input or division by zero).
 * With @p with_crash, one operand combination triggers the deliberate
 * NULL-write crash (see the inline crash hook).
 */
std::string calc_response(const std::string& line, const bool with_crash);

} // namespace testtarget
