// src/main.cpp

#include <algorithm>
#include <iostream>
#include <string>
#include <string_view>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <sys/socket.h>
#include <vector>
#include <variant>
#include <optional>
#include <cstdlib>
#include <csignal>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include <spdlog/spdlog.h>

#include "args.hpp"
#include "config.hpp"
#include "log.hpp"
#include "process.hpp"
#include "network.hpp"
#include "utils.hpp"
#include "afl_compat.h"

__AFL_FUZZ_INIT();

// Coverage discard support. afl-cc injects the real macros via -D; the
// placeholders in afl_compat.h are no-ops otherwise. __AFL_COVERAGE defines
// the weak runtime flag that __AFL_COVERAGE_DISCARD() relies on. The binary is
// built with the patched afl-clang-fast++ (patch/force_loc.patch), which skips
// PC-guard edge emission for afl-cassowire, so the proxy itself writes no
// coverage; __AFL_COVERAGE_ON() / __AFL_COVERAGE_OFF() therefore have no
// effect here. The proxy and the target share one coverage map, and
// __AFL_COVERAGE_DISCARD() (run_proxy_mode(), when afl.cov_discard_init is
// true) zeroes that map before the first __AFL_LOOP() pass, so startup
// feedback from both is not attributed to the first fuzzed testcase.
__AFL_COVERAGE();

// Target pid for the current mode. Plain lifecycle state: no signal handler
// exists in the proxy, so nothing publishes or consumes this from handler
// context. If the proxy dies for any reason, the target is killed by its
// PR_SET_PDEATHSIG(SIGKILL) (see process::fork_target()).
pid_t g_child_pid = 0;

// Upper bound on how long check_target_state() waits for an already-dying
// target to become waitable. poll(pidfd) returns immediately on death, so this
// only matters when the target is wedged (e.g. stuck in a coredump pipe).
constexpr int kTargetDeathGraceMs = 200;

// Hard-stop the target's process group: SIGKILL to the whole group, then a
// bounded reap of the group leader so no zombie outlives a mode function. The
// shared coverage map is shm-backed and written on every edge hit, so nothing
// AFL reads is lost to the SIGKILL. If the leader is stuck in uninterruptible
// kernel work past the deadline, whatever is left is re-parented to init when
// the proxy exits.
void kill_and_reap_pgid(pid_t pgid) {
    if (pgid <= 0) return;
    kill(-pgid, SIGKILL);

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (true) {
        int status;
        // The target is never ptraced, so waitpid(WNOHANG) without WUNTRACED
        // reports real death only; nothing else can make this loop spin early.
        pid_t res = waitpid(pgid, &status, WNOHANG);
        if (res == pgid) {
            break; // Leader reaped
        } else if (res == -1) {
            if (errno == EINTR) {
                // Try again, so do nothing and continue the loop.
            } else {
                // ECHILD or unexpected error: nothing left to reap.
                break;
            }
        }
        // res == 0 means the leader is still dying.

        clock_gettime(CLOCK_MONOTONIC, &now);
        long long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000LL +
                               (now.tv_nsec - start.tv_nsec) / 1000000LL;
        if (elapsed_ms >= 200) {
            // Deadline reached; leave the zombie to init.
            break;
        }

        // Short sleep to avoid busy-waiting
        struct timespec req = {0, 10000000}; // 10ms
        nanosleep(&req, nullptr);
    }
}

// NOTES: about log
// The proxy's own logs go through spdlog to stdout (see src/log.hpp). The
// target's stdout/stderr are not "logs": they are redirected per mode in
// process.cpp (/dev/null by default, forwarded to our fds with --child-output).

/**
 * @brief Result of one exchange_once() cycle. Error details are kept so each
 *        caller can log and react according to its mode (proxy vs test).
 */
struct ExchangeOutcome {
    std::optional<network::ConnectError> connect_error;  ///< fatal: no socket was established
    std::optional<network::SendError> send_error;        ///< send failed, cycle still continued
    std::optional<network::WaitError> wait_error;        ///< response failed/timed out
    std::vector<uint8_t> response;                       ///< received bytes, valid when wait_error is empty
    size_t request_size = 0;                             ///< bytes queued for sending (prefix + input + suffix)
    // Wall-clock cost of each stage, for the slow/mostly-hanging cases. These
    // are the observability hook that makes a stuck network stage visible at
    // WARN level (the per-iteration detail itself stays at TRACE).
    uint64_t connect_ms = 0;   ///< time spent in network::connect_target()
    uint64_t send_ms = 0;      ///< time spent in network::send_all()
    uint64_t shutdown_ms = 0;  ///< time spent in shutdown(SHUT_WR)
    uint64_t wait_ms = 0;      ///< time spent in network::wait_response()
};

/**
 * @brief Rolling per-proxy-loop statistics driving the INFO heartbeat and the
 *        rate limiters for repeated per-iteration errors.
 */
struct IterationStats {
    uint64_t iterations = 0;
    uint64_t last_heartbeat_ms = 0;  ///< wall clock of the last heartbeat line
    uint64_t slow_iters = 0;         ///< iterations that hit a stage budget
    uint64_t max_connect_ms = 0;
    uint64_t max_send_ms = 0;
    uint64_t max_wait_ms = 0;
    uint64_t max_probe_ms = 0;
    log::Throttle connect_err{3, 5000};
    log::Throttle send_err{3, 5000};
    log::Throttle wait_err{3, 5000};
    log::Throttle probe_err{3, 5000};
};

/// Emit at most one INFO iteration summary per this interval.
constexpr uint64_t kHeartbeatMs = 5000;

/// Fold one iteration's stage times into the rolling statistics and emit the
/// periodic INFO heartbeat (flushed, so it survives AFL's output capture).
static void update_iteration_stats(IterationStats& stats, uint64_t connect_ms,
                                   uint64_t send_ms, uint64_t wait_ms,
                                   uint64_t probe_ms, uint64_t budget_ms) {
    ++stats.iterations;
    stats.max_connect_ms = std::max(stats.max_connect_ms, connect_ms);
    stats.max_send_ms = std::max(stats.max_send_ms, send_ms);
    stats.max_wait_ms = std::max(stats.max_wait_ms, wait_ms);
    stats.max_probe_ms = std::max(stats.max_probe_ms, probe_ms);
    if (connect_ms >= budget_ms || send_ms >= budget_ms ||
        wait_ms >= budget_ms || probe_ms >= budget_ms) {
        ++stats.slow_iters;
    }

    const uint64_t now_ms = utils::get_time_ms();
    if (now_ms - stats.last_heartbeat_ms >= kHeartbeatMs) {
        PROXY_LOG_INFO("heartbeat: {} iterations, max connect/send/wait/probe = {}/{}/{}/{} ms, slow={}, cpu affinity: {}",
                       stats.iterations, stats.max_connect_ms, stats.max_send_ms,
                       stats.max_wait_ms, stats.max_probe_ms, stats.slow_iters,
                       utils::get_cpu_affinity());
        spdlog::default_logger()->flush();
        stats.last_heartbeat_ms = now_ms;
    }
}

/// Human-readable hint appended to probe-failure WARNs when the underlying
/// connect error points at proxy-side resource exhaustion instead of a target
/// problem (empty string otherwise).
static std::string probe_exhaustion_hint(const network::ProbeResult& pr) {
    if (!pr.error) return "";
    const int e = pr.error->sys_errno;
    if (pr.error->kind == network::ConnectError::Kind::SocketCreate && (e == EMFILE || e == ENFILE)) {
        return " (socket()/fd exhaustion on the proxy side; check ulimit -n)";
    }
    if (pr.error->kind == network::ConnectError::Kind::ConnectFailed &&
        (e == EADDRNOTAVAIL || e == EAGAIN || e == ENOBUFS || e == ENOMEM)) {
        return " (likely proxy-side ephemeral port exhaustion; check `ss -s`, "
               "net.ipv4.ip_local_port_range, tcp_tw_reuse)";
    }
    return "";
}

/**
 * @brief Performs one request/response cycle against the target: connect,
 *        send prefix + input + suffix, half-close (SHUT_WR), read the
 *        response. Does not touch target health or log; each caller does
 *        that per its mode. The socket is closed before returning.
 *
 * @param cfg The global configuration (network + payload sections).
 * @param input The raw input bytes (fuzz testcase or test file contents).
 * @param input_len Number of bytes in @p input.
 * @param payload_buf Scratch buffer reused to build the final payload
 *        (clear() keeps capacity, so the hot loop does not reallocate).
 * @return ExchangeOutcome The per-stage result; on connect failure the send,
 *         wait, response and request_size fields stay empty/zero.
 */
ExchangeOutcome exchange_once(const Config& cfg, const uint8_t* input, size_t input_len,
                              std::vector<uint8_t>& payload_buf) {
    ExchangeOutcome out;
    network::pump_notif_listener();

    // Final payload = configured prefix + input data + configured suffix.
    // Built before connecting so payload_buf always reflects the current
    // iteration (termination dumps read it even when connect fails).
    payload_buf.clear();
    payload_buf.insert(payload_buf.end(), cfg.payload.prefix.begin(), cfg.payload.prefix.end());
    payload_buf.insert(payload_buf.end(), input, input + input_len);
    payload_buf.insert(payload_buf.end(), cfg.payload.suffix.begin(), cfg.payload.suffix.end());
    out.request_size = payload_buf.size();

    uint64_t t_stage = utils::get_time_ms();
    auto conn = network::connect_target(cfg.network);
    out.connect_ms = utils::get_time_ms() - t_stage;
    if (std::holds_alternative<network::ConnectError>(conn)) {
        out.connect_error = std::get<network::ConnectError>(conn);
        return out;
    }
    utils::FdGuard sock = std::get<utils::FdGuard>(std::move(conn));
    // The socket is closed when `sock` goes out of scope at the end.
    network::pump_notif_listener();

    t_stage = utils::get_time_ms();
    if (auto send_res = network::send_all(sock.get(), payload_buf.data(), payload_buf.size(), cfg.network.timeout_ms);
        std::holds_alternative<network::SendError>(send_res)) {
        out.send_error = std::get<network::SendError>(send_res);
    }
    out.send_ms = utils::get_time_ms() - t_stage;

    t_stage = utils::get_time_ms();
    shutdown(sock.get(), SHUT_WR);
    out.shutdown_ms = utils::get_time_ms() - t_stage;

    t_stage = utils::get_time_ms();
    if (auto wait_res = network::wait_response(sock.get(), cfg.network.timeout_ms);
        std::holds_alternative<network::WaitError>(wait_res)) {
        out.wait_error = std::get<network::WaitError>(wait_res);
    } else {
        out.response = std::get<std::vector<uint8_t>>(std::move(wait_res));
    }
    out.wait_ms = utils::get_time_ms() - t_stage;
    // The response is fully read (or the wait gave up), so nothing wanted can
    // be lost: turn the upcoming close() into an RST so this socket does not
    // sit in TIME_WAIT for ~2 minutes pinning one ephemeral port. At thousands
    // of iterations/s that accumulation used to exhaust the local port range
    // and made later connect()s (including the probe) fail with EADDRNOTAVAIL.
    network::arm_rst_on_close(sock.get());
    network::pump_notif_listener();
    return out;
}

/**
 * @brief One iteration of the __AFL_LOOP body: exchange the current testcase
 *        with the target, then health-check the target (race-free).
 */
void run_fuzz_iteration(const Config& cfg, pid_t child_pid, int target_pidfd,
                        std::vector<uint8_t>& payload_buf, IterationStats& stats) {
    PROXY_LOG_TRACE("loop beginning");
    int len = __AFL_FUZZ_TESTCASE_LEN;
    uint8_t* buf = __AFL_FUZZ_TESTCASE_BUF;
    const uint64_t budget_ms = static_cast<uint64_t>(cfg.network.timeout_ms);

    ExchangeOutcome ex = exchange_once(cfg, buf, static_cast<size_t>(len), payload_buf);

    if (ex.connect_error) {
        // Rate-limited: a target that is alive but refuses connections would
        // otherwise log this every iteration and drown the useful WARNs.
        if (stats.connect_err.allow()) {
            PROXY_LOG_ERROR("failed to connect to {}:{} after {} ms: {}{}",
                            cfg.network.host, cfg.network.port, ex.connect_ms,
                            ex.connect_error->to_string(),
                            log::throttle_suffix(stats.connect_err));
        }
        // Connection failed, target might be dead. Check health immediately; a
        // live target falls through to the quiescence probe below: it is
        // another connect, so a persistently unreachable listener exhausts
        // probe_attempts there and aborts the proxy for the AFL respawn, while
        // a transient blip is serviced and the next iteration exchanges
        // normally. (With network.probe disabled the loop keeps retrying with
        // rate-limited logs - the explicit opt-out of the auto-respawn.)
        auto st = process::check_target_state(child_pid, target_pidfd, kTargetDeathGraceMs);
        switch (st.kind) {
        case process::TargetState::Kind::Crashed:
            PROXY_LOG_WARN("target {} after connect failure, crashing the proxy so AFL respawns it",
                           st.to_string());
            utils::crash_proxy("target crashed after connect failure: " + st.to_string(),
                               payload_buf);
            break;
        case process::TargetState::Kind::Exited:
        case process::TargetState::Kind::Unknown:
            PROXY_LOG_WARN("target {} after connect failure, aborting the proxy so AFL respawns it",
                           st.to_string());
            utils::abort_proxy("target " + st.to_string() + " after connect failure",
                               payload_buf);
            break;
        case process::TargetState::Kind::Alive:
            break; // live target: the quiescence probe below decides
        }
    } else {
        PROXY_LOG_TRACE("successfully connected");

        if (ex.connect_ms >= budget_ms) {
            PROXY_LOG_WARN("connect to {}:{} took {} ms (>= timeout {} ms)",
                           cfg.network.host, cfg.network.port, ex.connect_ms, budget_ms);
        }

        if (ex.send_error) {
            if (stats.send_err.allow()) {
                PROXY_LOG_ERROR("send failed after {} ms: {}{}",
                                ex.send_ms, ex.send_error->to_string(),
                                log::throttle_suffix(stats.send_err));
            }
        } else if (ex.send_ms >= budget_ms) {
            PROXY_LOG_WARN("send_all of {} bytes took {} ms (>= timeout {} ms); target stopped draining the socket",
                           ex.request_size, ex.send_ms, budget_ms);
        }

        PROXY_LOG_TRACE("Request (size={}): '{}'",
                            ex.request_size,
                            log::escape_bytes(payload_buf, 256));
        if (ex.wait_error) {
            if (stats.wait_err.allow()) {
                std::string hint;
                if (ex.wait_error->kind == network::WaitError::Kind::TimedOut) {
                    hint = " (no response; if the request declared a Content-Length larger than the "
                           "body sent, or the server is keep-alive, the target may withhold its "
                           "response even after shutdown(SHUT_WR))";
                }
                PROXY_LOG_ERROR("waiting for response failed after {} ms: {}{}{}",
                                ex.wait_ms, ex.wait_error->to_string(), hint,
                                log::throttle_suffix(stats.wait_err));
            }
        } else {
            PROXY_LOG_TRACE("Response (size={}): '{}'",
                            ex.response.size(),
                            log::escape_bytes(ex.response, 256));
            if (ex.wait_ms >= budget_ms) {
                PROXY_LOG_WARN("response took {} ms (>= timeout {} ms): {} bytes received; target kept the connection open",
                               ex.wait_ms, budget_ms, ex.response.size());
            }
        }
    }

    // Post-response quiescence probe (network.probe). The target must service
    // a throwaway connection before this iteration ends; a serial server can
    // only do that once the previous connection is fully handled (post-response
    // cleanup included). If the target died during that cleanup, the probe
    // socket gets RST (also "readable"), and the health check below sees the
    // dying flags in the same iteration, so the crash stays attributed to the
    // input that caused it.
    //
    // Multi-strike failure handling (network.probe_attempts, default 2): a
    // failed probe never decides by itself - check_target_state() classifies.
    // If the target is dead, the classification terminates the proxy right
    // here with the right signal (SIGSEGV for a crash, SIGABRT for a
    // clean/unknown exit). If the target is alive, the failure was likely
    // transient, so the probe is retried after probe_retry_ms; only when all
    // configured attempts fail consecutively does the proxy abort so AFL
    // respawns it. (The old single-shot abort killed the whole run on purely
    // local errors, e.g. EADDRNOTAVAIL from ephemeral port exhaustion.)
    uint64_t probe_ms = 0;
    if (cfg.network.probe) {
        auto pr = network::ProbeResult{network::ProbeOutcome::Failed, std::nullopt};
        uint64_t first_ms = 0;
        auto first_outcome = pr.outcome;

        for (int attempt = 1; attempt <= cfg.network.probe_attempts; ++attempt) {
            const uint64_t t_probe = utils::get_time_ms();
            pr = network::probe_target(cfg.network);
            const uint64_t attempt_ms = utils::get_time_ms() - t_probe;
            probe_ms += attempt_ms;

            if (attempt == 1) {
                first_ms = attempt_ms;
                first_outcome = pr.outcome;
            }

            if (pr.outcome == network::ProbeOutcome::Serviced) {
                if (attempt > 1) {
                    PROXY_LOG_INFO("probe recovered on attempt {}/{} after {} ms total",
                                   attempt, cfg.network.probe_attempts, probe_ms);
                }
                break;
            }

            if (attempt == 1 && stats.probe_err.allow()) {
                PROXY_LOG_WARN("probe connection {} after {} ms (timeout {} ms) against a live target{}{}{}",
                               network::probe_outcome_to_string(pr.outcome), first_ms, budget_ms,
                               pr.error ? ": " + pr.error->to_string() : std::string(),
                               probe_exhaustion_hint(pr),
                               log::throttle_suffix(stats.probe_err));
            }

            // Classify the target before deciding anything: if it is dead, the
            // classification terminates the proxy with the right signal.
            auto st = process::check_target_state(child_pid, target_pidfd, kTargetDeathGraceMs);
            switch (st.kind) {
            case process::TargetState::Kind::Crashed:
                PROXY_LOG_WARN("target {} after probe failure ({}), crashing the proxy so AFL records the finding",
                               st.to_string(), network::probe_outcome_to_string(pr.outcome));
                utils::crash_proxy("target " + st.to_string() + " after probe failure ("
                                       + network::probe_outcome_to_string(pr.outcome) + ")",
                                   payload_buf);
                break;
            case process::TargetState::Kind::Exited:
            case process::TargetState::Kind::Unknown:
                PROXY_LOG_WARN("target {} after probe failure ({}), aborting the proxy so AFL respawns it",
                               st.to_string(), network::probe_outcome_to_string(pr.outcome));
                utils::abort_proxy("target " + st.to_string() + " after probe failure ("
                                       + network::probe_outcome_to_string(pr.outcome) + ")",
                                   payload_buf);
                break;
            case process::TargetState::Kind::Alive:
                break; // transient failure, handled below (retry)
            }

            // All attempts failed: the listener is persistently unavailable,
            // respawn via AFL.
            if (attempt == cfg.network.probe_attempts) {
                std::string err_detail = pr.error ? ": " + pr.error->to_string() : std::string();
                if (cfg.network.probe_attempts == 2) {
                    PROXY_LOG_WARN("probe connection {} twice in one iteration ({} ms total; "
                                   "first attempt: {} after {} ms){} - target listener is gone",
                                   network::probe_outcome_to_string(pr.outcome), probe_ms,
                                   network::probe_outcome_to_string(first_outcome), first_ms,
                                   err_detail);
                } else {
                    PROXY_LOG_WARN("probe connection {} in all {} attempts in one iteration ({} ms total; "
                                   "first attempt: {} after {} ms){} - target listener is gone",
                                   network::probe_outcome_to_string(pr.outcome), cfg.network.probe_attempts,
                                   probe_ms,
                                   network::probe_outcome_to_string(first_outcome), first_ms,
                                   err_detail);
                }
                utils::abort_proxy("probe connection " + network::probe_outcome_to_string(pr.outcome)
                                       + " in all " + std::to_string(cfg.network.probe_attempts)
                                       + " attempts in one iteration (total " + std::to_string(probe_ms)
                                       + " ms" + err_detail + ") - target listener is gone",
                                   payload_buf);
            }

            // Apply retry delay if configured
            if (cfg.network.probe_retry_ms > 0) {
                utils::sleep_ms(cfg.network.probe_retry_ms);
            }
        }

        PROXY_LOG_TRACE("probe: {} ({} ms)", network::probe_outcome_to_string(pr.outcome), probe_ms);
        if (probe_ms >= budget_ms) {
            PROXY_LOG_WARN("probe took {} ms (>= timeout {} ms)", probe_ms, budget_ms);
        }
    }

    // Health check (race-free). Replaces the old sleep_ms()+waitpid(WNOHANG)
    // heuristic: do_exit() closes the target's socket fds before it becomes a
    // waitable zombie, so a bare WNOHANG right after wait_response() could miss
    // a crash and attribute it to the NEXT input. check_target_state reads the
    // kernel's PF_EXITING/PF_SIGNALED flags from /proc and blocks on the pidfd
    // until the death materialises, so the crash is seen in THIS iteration.
    // (1) still racy for a crash that happens AFTER this check
    //   returns Alive and after the probe was serviced (deferred timers / async
    //   work). A top-of-iteration check would only move this window, not close
    //   it; a full fix needs idle detection (e.g. a procfs syscall whitelist).
    //   This is a known limitation, documented in AGENTS.md; afl.dump_history
    //   retains the last N completed payloads so a crash detected one iteration
    //   late still preserves the input that likely caused it. (2) crashes in
    //   worker children of the target (nginx workers, not the direct child) are
    //   still not detected here - only the direct child pid is watched
    //   (procfs/PF check is per-pid); a dead worker surfaces as a probe/connect
    //   timeout -> abort_proxy -> AFL respawn, not as a crash finding.
    auto st = process::check_target_state(child_pid, target_pidfd, kTargetDeathGraceMs);
    PROXY_LOG_TRACE("target state: {}", st.to_string());
    switch (st.kind) {
    case process::TargetState::Kind::Crashed:
        PROXY_LOG_WARN("target {}, crashing the proxy so AFL records the finding", st.to_string());
        utils::crash_proxy("target " + st.to_string(), payload_buf);
        break;
    case process::TargetState::Kind::Exited:
    case process::TargetState::Kind::Unknown:
        PROXY_LOG_WARN("target {}, aborting the proxy so AFL records the finding", st.to_string());
        utils::abort_proxy("target " + st.to_string(), payload_buf);
        break;
    case process::TargetState::Kind::Alive:
        break; // normal case, keep fuzzing
    }

    update_iteration_stats(stats, ex.connect_ms, ex.send_ms, ex.wait_ms, probe_ms, budget_ms);
}

int run_proxy_mode(Config cfg, bool forward_output) {
    if (prctl(PR_SET_DUMPABLE, 0) != 0) {
        PROXY_LOG_WARN("prctl(PR_SET_DUMPABLE, 0) failed: {} (continuing)", std::strerror(errno));
    }

    // Check AFL SHM IDs
    if (!getenv("__AFL_SHM_ID")) {
        PROXY_LOG_ERROR("__AFL_SHM_ID not found in environment. Run with afl-fuzz.");
        return 1;
    }
    // __AFL_CMPLOG_SHM_ID presence indicates AFL compare-log mode; its absence
    // means normal mode. The config validation already ensures target_cmplog and
    // network_cmplog are set when enable_cmplog is true, so we don't need to
    // check it here.
    if (!getenv("__AFL_CMPLOG_SHM_ID")) {
        // Normal mode: use `target`
        // cfg is already configured correctly
    } else {
        // CMPLOG MODE: use `target_cmplog`/`network_cmplog` instead of `target`/`network`
        Config cfg_cmplog = cfg;
        cfg_cmplog.target = cfg.target_cmplog;
        cfg_cmplog.network = cfg.network_cmplog;
        cfg = cfg_cmplog;
    }

    // AFL_CASSOWIRE_FORCE_FINAL_LOC is consumed by the target's AFL++ runtime to
    // force __afl_final_loc. In proxy mode it must be set and be a valid
    // uint64 integer. The proxy only validates and logs the value; it is NOT
    // forwarded explicitly: the target sees it only with env_preserve: all, or
    // when it is listed under target.env.
    const char* final_loc_str = getenv("AFL_CASSOWIRE_FORCE_FINAL_LOC");
    if (!final_loc_str) {
        PROXY_LOG_ERROR("AFL_CASSOWIRE_FORCE_FINAL_LOC not found in environment. Run with AFL_CASSOWIRE_FORCE_FINAL_LOC=<uint64>.");
        return 1;
    }

    uint64_t force_final_loc = 0;
    if (auto parsed = utils::parse_u64_strict(final_loc_str);
        std::holds_alternative<uint64_t>(parsed)) {
        force_final_loc = std::get<uint64_t>(parsed);
    } else {
        PROXY_LOG_ERROR("AFL_CASSOWIRE_FORCE_FINAL_LOC must be an integer (uint64), got: '{}'", final_loc_str);
        return 1;
    }

    PROXY_LOG_INFO("AFL_CASSOWIRE_FORCE_FINAL_LOC = {}", force_final_loc);

    // Pre-spawn cleanup: only in a validated proxy invocation, against the
    // already-selected normal/cmplog target and port.
    if (!process::handle_port_conflict(cfg)) {
        return 1;
    }

    // Initialize AFL persistent mode
    __AFL_INIT();

    // Spawn target
    auto prep_opt = process::prepare_target(cfg, process::SpawnMode::ProxyMode);
    if (!prep_opt) {
        PROXY_LOG_ERROR("failed to prepare target process.");
        return 1;
    }
    process::SpawnedTarget spawned = process::fork_target(cfg, *prep_opt, process::SpawnMode::ProxyMode,
                                                          forward_output);
    if (spawned.pid <= 0) {
        PROXY_LOG_ERROR("failed to spawn target process.");
        return 1;
    }
    g_child_pid = spawned.pid;

    // Pollable pidfd for the target, used by the race-free health check
    // (process::check_target_state). Declared at function scope so it lives
    // for the whole AFL loop; closed when run_proxy_mode returns.
    utils::FdGuard target_pidfd{process::open_pidfd(spawned.pid)};
    if (target_pidfd.get() < 0) {
        PROXY_LOG_ERROR("pidfd_open failed for target pid {}: {} (requires kernel >= 5.3)",
                        static_cast<int>(spawned.pid), std::strerror(errno));
        kill_and_reap_pgid(g_child_pid);
        return 1;
    }

    // Wait for port readiness. In seccomp(user-notif) mode the listener fd
    // (from fork_target) guards the target's irremovable bind/listen filter:
    // keep it open for the whole run and register it for the pump right after
    // successful detection so later bind()/listen() (workers, reloads, QEMU
    // guest forks) are released instead of parking in the kernel.
    PROXY_LOG_DEBUG("Waiting for port");
    utils::FdGuard notif_guard{spawned.notif_fd};
    auto port_res = network::wait_for_port(g_child_pid, cfg, spawned.notif_fd);
    if (std::holds_alternative<network::DetectError>(port_res)) {
        PROXY_LOG_ERROR("failed to detect port {}: {}",
                        cfg.network.port, std::get<network::DetectError>(port_res).to_string());

        // TODO: make a health check here maybe?
        network::set_notif_listener(-1);
        kill_and_reap_pgid(g_child_pid);
        return 1;
    }
    network::set_notif_listener(spawned.notif_fd);

    // Main AFL Loop
    // Scratch buffer reused every iteration to send prefix + fuzz data + suffix
    // (clear() keeps its capacity, so the hot loop does not reallocate).
    std::vector<uint8_t> payload_buf;
    payload_buf.reserve(cfg.payload.prefix.size() + cfg.payload.suffix.size() + 4096);

    IterationStats stats;
    stats.last_heartbeat_ms = utils::get_time_ms();

    // Coverage hand-off to the fuzz loop. wait_for_port() guarantees the
    // target is fully initialized here, so the shared coverage map holds only
    // startup feedback (the target's initialization plus the proxy's startup).
    // __AFL_COVERAGE_DISCARD() zeroes that map (and the cmplog map) right
    // before the loop, so the first __AFL_LOOP() pass starts from a clean
    // slate instead of the startup snapshot, which afl-fuzz would otherwise
    // re-deliver slightly differently on every respawn (the low stability).
    // afl.cov_discard_init (default true) gates the discard; when false the
    // startup feedback is kept.
    if (cfg.afl.cov_discard_init) {
        __AFL_COVERAGE_DISCARD();
    }

    while (__AFL_LOOP(cfg.afl.loop_count)) {
        // One-based iteration number for the termination dumps (.msg), set
        // before run_fuzz_iteration() so every failure path inside it
        // reports the same, current iteration.
        utils::set_current_iteration(stats.iterations + 1);
        run_fuzz_iteration(cfg, g_child_pid, target_pidfd.get(), payload_buf, stats);
        // Record this completed iteration's payload so a later termination
        // dump can preserve it (a deferred/async crash detected on the next
        // iteration then finds the input that likely caused it). payload_buf
        // still holds the just-finished payload here; the next iteration
        // overwrites it inside exchange_once().
        utils::record_dump_input(payload_buf);
    }

    // Clean exit of AFL loop: hard-stop the target's process group. The
    // coverage map is shm-backed (written on every edge hit), so a SIGKILL'd
    // target loses nothing AFL reads; a graceful SIGTERM would only add
    // respawn latency per __AFL_LOOP exit.
    kill_and_reap_pgid(g_child_pid);
    PROXY_LOG_TRACE("kill {}", static_cast<int>(g_child_pid));
    return 0;
}

int run_test_mode(const Config& cfg, const std::string& input_path, bool forward_output) {
    // input_path is guaranteed non-empty: the parser makes --input mandatory
    // for the `test` subcommand (src/args.cpp), long before this point.

    // --- Pass 1: Map Size Extraction ---
    // prepare_target() injects AFL_DUMP_MAP_SIZE=1 into the child's envp for
    // SpawnMode::MapSizePass; the proxy's own environment is not touched.
    auto prep_opt1 = process::prepare_target(cfg, process::SpawnMode::MapSizePass);
    if (!prep_opt1) {
        PROXY_LOG_ERROR("failed to prepare target for map size extraction.");
        return 1;
    }
    process::SpawnedTarget spawned1 = process::fork_target(cfg, *prep_opt1, process::SpawnMode::MapSizePass,
                                                           false);
    if (spawned1.pid <= 0) {
        PROXY_LOG_ERROR("failed to spawn target for map size extraction.");
        return 1;
    }
    g_child_pid = spawned1.pid;

    // TODO(claude): the exit status is only logged, not acted on, and Pass 1 still proceeds to Pass 2
    //   even when the map size was missing/invalid (see the TODO below).
    //   The wait is bounded by network.initial_ms; on timeout the target is killed
    //   (SIGKILL via kill_and_reap_pgid).
    PROXY_LOG_DEBUG("before waitpid");
    auto pass1 = process::wait_target_exit(spawned1.pid, cfg.network.initial_ms);
    PROXY_LOG_DEBUG("after waitpid");
    if (!pass1.exited) {
        PROXY_LOG_ERROR("Pass 1 target did not exit within {} ms; killing it.", cfg.network.initial_ms);
        kill_and_reap_pgid(g_child_pid);
        if (spawned1.map_size_fd >= 0) {
            close(spawned1.map_size_fd);
        }
        return 1;
    }
    PROXY_LOG_DEBUG("Pass 1 target status {:x} (exited={}, signaled={})",
                    pass1.status, WIFEXITED(pass1.status), WIFSIGNALED(pass1.status));

    // Collect map size from the pipe
    if (spawned1.map_size_fd >= 0) {
        process::collect_map_size(spawned1.map_size_fd);
    }

    // TODO(claude): Pass 1 failure (no/invalid map size) is NOT propagated: collect_map_size() returns
    //   void, so this always prints "completed" and goes on to Pass 2 even when the parse failed. It
    //   should return a std::optional<uint64_t> and abort test mode on failure.
    PROXY_LOG_INFO("Pass 1 (Map Size) completed.");

    // --- Pass 2: Single Iteration ---
    // TODO(claude): the --input file is only opened after Pass 1 has spawned (and waited for) the
    //   target; validate that it is readable up front to fail early. Also an empty regular file is
    //   reported as "failed to read" below, although an empty input is valid.
    std::vector<uint8_t> input_data;
    if (auto input_res = utils::read_input_file(input_path);
        std::holds_alternative<std::error_code>(input_res)) {
        PROXY_LOG_ERROR("failed to read payload from {}: {}",
                        input_path, std::get<std::error_code>(input_res).message());
        return 1;
    } else {
        input_data = std::get<std::vector<uint8_t>>(std::move(input_res));
    }
    if (input_data.empty() && input_path != "-") {
        PROXY_LOG_ERROR("failed to read payload from {}", input_path);
        return 1;
    }

    // Scratch buffer for the final payload = configured prefix + input data
    // + configured suffix (built by exchange_once()).
    std::vector<uint8_t> payload_buf;
    payload_buf.reserve(cfg.payload.prefix.size() + cfg.payload.suffix.size() + input_data.size() + 64);

    auto prep_opt2 = process::prepare_target(cfg, process::SpawnMode::PlainTest);
    if (!prep_opt2) {
        PROXY_LOG_ERROR("failed to prepare target for test iteration.");
        return 1;
    }
    PROXY_LOG_DEBUG("fork_target 2");
    process::SpawnedTarget spawned2 = process::fork_target(cfg, *prep_opt2, process::SpawnMode::PlainTest,
                                                           forward_output);
    if (spawned2.pid <= 0) {
        PROXY_LOG_ERROR("failed to spawn target for test iteration.");
        return 1;
    }
    g_child_pid = spawned2.pid;

    PROXY_LOG_DEBUG("wait_for_port");
    utils::FdGuard notif_guard{spawned2.notif_fd};
    auto port_res2 = network::wait_for_port(g_child_pid, cfg, spawned2.notif_fd);
    if (std::holds_alternative<network::DetectError>(port_res2)) {
        PROXY_LOG_ERROR("failed to detect port {}: {}",
                        cfg.network.port, std::get<network::DetectError>(port_res2).to_string());
        network::set_notif_listener(-1);
        kill_and_reap_pgid(g_child_pid);
        return 1;
    }
    network::set_notif_listener(spawned2.notif_fd);

    // One-shot of the same connect -> send -> wait cycle the AFL loop runs.
    PROXY_LOG_DEBUG("exchange_once");
    ExchangeOutcome ex = exchange_once(cfg, input_data.data(), input_data.size(), payload_buf);
    if (ex.connect_error) {
        PROXY_LOG_ERROR("failed to connect to {}:{}: {}",
                        cfg.network.host, cfg.network.port, ex.connect_error->to_string());
        kill_and_reap_pgid(g_child_pid);
        return 1;
    }

    bool io_ok = true;
    if (ex.send_error) {
        PROXY_LOG_ERROR("send failed: {}", ex.send_error->to_string());
        io_ok = false;
    }

    // Log the target's response in test mode (escaped, any binary safe).
    if (ex.wait_error) {
        PROXY_LOG_ERROR("waiting for response failed: {}", ex.wait_error->to_string());
        io_ok = false;
    } else {
        PROXY_LOG_INFO("Response: '{}'", log::escape_bytes(ex.response));
    }

    if (io_ok) {
        PROXY_LOG_INFO("Pass 2 (Single Iteration) completed successfully.");
    } else {
        PROXY_LOG_ERROR("Pass 2 (Single Iteration) failed.");
    }

    // TODO: wip, maybe remove that later
    // utils::sleep_ms(500);

    int status;
    pid_t res = waitpid(g_child_pid, &status, WNOHANG);
    PROXY_LOG_INFO("waitpid res {} status {:x}, signaled={}", res, status, WIFSIGNALED(status));
    
    // Clean exit
    kill_and_reap_pgid(g_child_pid);
    return 0;
}

int main(int argc, char* argv[]) {
    // Initialize logging first so that CLI/config errors are reported through
    // the logger; --log-level reconfigures the console after parsing, and the
    // second init() below applies --log-level plus afl.msg_log_level (from the
    // config) once the config is loaded.
    log::init(spdlog::level::info, spdlog::level::warn);

    // Note: global options (-c/--config, --log-level, --child-output,
    // --data-dir) must precede the subcommand; `test --input <file>` carries
    // its option after `test`. This split is intentional (see src/args.hpp).
    auto args_res = args::parse_args(argc, argv);
    if (const auto* parse_err = std::get_if<args::ArgParseError>(&args_res)) {
        PROXY_LOG_ERROR("{}", parse_err->message);
        std::cerr << parse_err->usage;
        return 1;
    }
    const auto& parsed = std::get<args::ParsedArgs>(args_res);

    // parse_args() already validated the --log-level name; this only converts it.
    auto log_level = log::parse_level(parsed.log_level);
    if (!log_level) {
        PROXY_LOG_ERROR("invalid --log-level '{}': expected trace, debug, info, warn, error, critical, or off",
                        parsed.log_level);
        return 1;
    }
    log::init(*log_level, spdlog::level::warn);

    // Destination for crash/abort termination dumps (.msg/.data).
    utils::set_data_dir(parsed.data_dir);

    // Tag termination dumps and their log lines with the instance kind: the
    // normal and the cmplog proxy can run concurrently against the same data
    // dir, so their dumps must stay attributable.
    if (parsed.is_test_mode) {
        utils::set_instance_tag("test");
    } else {
        utils::set_instance_tag(getenv("__AFL_CMPLOG_SHM_ID") ? "cmplog" : "normal");
    }

    // Load Configuration
    auto config_res = load_config(parsed.config_path);
    if (std::holds_alternative<ConfigError>(config_res)) {
        PROXY_LOG_ERROR("{}", std::get<ConfigError>(config_res).to_string());
        return 1;
    }

    Config cfg = std::get<Config>(config_res);

    // Reconfigure the logger with the parsed --log-level (console) and the
    // config-provided afl.msg_log_level (ring sink feeding .msg dumps). The
    // level name is validated here (not in load_config()) because config.cpp
    // cannot include log.hpp (yaml-cpp's <cmath> collides with namespace log).
    auto crash_msg_level = log::parse_level(cfg.afl.msg_log_level);
    if (!crash_msg_level) {
        PROXY_LOG_ERROR("invalid afl.msg_log_level '{}': expected trace, debug, info, warn, error, critical, or off",
                        cfg.afl.msg_log_level);
        return 1;
    }
    log::init(*log_level, *crash_msg_level);

    // Retain the last N completed payloads so a termination dump can preserve
    // the input that likely caused a deferred/async crash (see
    // afl.dump_history). 0 disables the history.
    utils::set_dump_history_size(cfg.afl.dump_history);

    if (parsed.is_test_mode) {
        return run_test_mode(cfg, parsed.input_path, parsed.forward_output);
    } else {
        return run_proxy_mode(std::move(cfg), parsed.forward_output);
    }
}
