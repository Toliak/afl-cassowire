// src/cache_mode.hpp

#pragma once

#include <string>

namespace testtarget {

/**
 * @brief Handles one cache-mode request.
 *
 * A deliberately stateful HTTP-like server: the same request takes different
 * paths depending on the server state (cold fill, warm hit, LRU eviction,
 * periodic revalidation, admin unlock, CmpLog-gated PRNG region, opt-in
 * lottery crash), which is exactly the coverage instability that AFL++
 * calibration marks as variable. All state transitions are deterministic
 * given the request history, so the mode provides ground truth for
 * instability-aware fuzzing experiments.
 */
std::string cache_response(const std::string& raw, bool with_crash);

} // namespace testtarget
