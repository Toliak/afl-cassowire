// src/utils.hpp

#pragma once

#include <cstdint>

namespace utils {

    /**
     * @brief Gets the current monotonic time in milliseconds.
     * 
     * @return uint64_t Current time in ms.
     */
    uint64_t get_time_ms();

    /**
     * @brief Sleeps for a specified number of milliseconds.
     * 
     * @param ms The duration to sleep in milliseconds.
     */
    void sleep_ms(int ms);

    /**
     * @brief Crashes the proxy intentionally (e.g., to trigger AFL respawn).
     * Raises SIGSEGV.
     */
    [[noreturn]] void crash_proxy();

} // namespace utils