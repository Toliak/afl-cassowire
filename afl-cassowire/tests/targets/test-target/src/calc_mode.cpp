// src/calc_mode.cpp

#include "calc_mode.hpp"

#include <string>

namespace testtarget {

namespace {

unsigned long long parse_number(const std::string& text, size_t& index, bool& ok) {
    const size_t start = index;
    unsigned long long value = 0;
    while (index < text.size() && text[index] >= '0' && text[index] <= '9') {
        value = value * 10ULL + static_cast<unsigned long long>(text[index] - '0');
        ++index;
    }
    ok = index > start;
    return value;
}

volatile int *ptr;

} // namespace

std::string calc_response(const std::string& line, const bool with_crash) {
    size_t index = 0;
    auto skip_spaces = [&index, &line] {
        while (index < line.size() && (line[index] == ' ' || line[index] == '\t')) {
            ++index;
        }
    };
    skip_spaces();
    bool ok = false;
    const unsigned long long lhs = parse_number(line, index, ok);
    if (!ok) {
        return "ERR\n";
    }
    skip_spaces();
    if (index >= line.size()) {
        return "ERR\n";
    }
    const char op = line[index++];
    if (op != '+' && op != '-' && op != '*' && op != '/') {
        return "ERR\n";
    }
    skip_spaces();
    const unsigned long long rhs = parse_number(line, index, ok);
    if (!ok) {
        return "ERR\n";
    }
    skip_spaces();
    if (index != line.size()) {
        return "ERR\n";
    }
    if (op == '/' && rhs == 0) {
        return "ERR\n";
    }
    unsigned long long result = 0;
    switch (op) {
        case '+': result = lhs + rhs; break;
        case '-': result = lhs - rhs; break;
        case '*': result = lhs * rhs; break;
        default: result = lhs / rhs; break;
    }
    // <BEGIN> Simulated crash (random numbers + operator)
    if (with_crash && lhs == 115 && 115 > rhs && rhs > 100 && op == '*' ) {
        ptr = 0x0uL;  // Point to nothing
        *ptr = 42;        // CRASH: Trying to write to address 0
    }
    // <END> Simulated crash
    return std::to_string(result) + "\n";
}

} // namespace testtarget
