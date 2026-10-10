// src/main.cpp

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

volatile sig_atomic_t g_child_pid = 0;

void kill_pgid(pid_t pgid) {
    if (pgid <= 0) return;
    kill(-pgid, SIGKILL);
}

// Async-signal-safe timed kill for process group
void timed_kill_pgid(pid_t pgid, int ms) {
    if (pgid <= 0) return;

    // Send SIGTERM to process group
    kill(-pgid, SIGTERM);

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    while (true) {
        int status;
        // Check if the process group leader has exited
        pid_t res = waitpid(pgid, &status, WNOHANG);
        if (res == pgid) {
            break; // Process exited
        } else if (res == -1) {
            if (errno == ECHILD) {
                break; // No child processes
            } else if (errno == EINTR) {
                // Try again, so do nothing and continue the loop.
            } else {
                // Unexpected error: break out of the loop to send SIGKILL.
                break;
            }
        }
        // res == 0 means the process is still alive (or stopped, etc.)

        clock_gettime(CLOCK_MONOTONIC, &now);
        long long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000LL + 
                               (now.tv_nsec - start.tv_nsec) / 1000000LL;
                                
        if (elapsed_ms >= ms) {
            // Timeout reached, break to send SIGKILL
            break;
        }

        // Short sleep to avoid busy-waiting (nanosleep is async-signal-safe)
        struct timespec req = {0, 10000000}; // 10ms
        nanosleep(&req, nullptr);
    }

    // Send SIGKILL to the entire process group to ensure cleanup
    kill(-pgid, SIGKILL);

    // Reap the leader to avoid zombie (if it hasn't been reaped already)
    int status;
    waitpid(pgid, &status, 0);
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
};

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

    auto conn = network::connect_target(cfg.network);
    if (std::holds_alternative<network::ConnectError>(conn)) {
        out.connect_error = std::get<network::ConnectError>(conn);
        return out;
    }
    utils::FdGuard sock = std::get<utils::FdGuard>(std::move(conn));
    // The socket is closed when `sock` goes out of scope at the end.

    // Final payload = configured prefix + input data + configured suffix
    payload_buf.clear();
    payload_buf.insert(payload_buf.end(), cfg.payload.prefix.begin(), cfg.payload.prefix.end());
    payload_buf.insert(payload_buf.end(), input, input + input_len);
    payload_buf.insert(payload_buf.end(), cfg.payload.suffix.begin(), cfg.payload.suffix.end());
    out.request_size = payload_buf.size();

    if (auto send_res = network::send_all(sock.get(), payload_buf.data(), payload_buf.size(), cfg.network.timeout_ms);
        std::holds_alternative<network::SendError>(send_res)) {
        out.send_error = std::get<network::SendError>(send_res);
    }

    shutdown(sock.get(), SHUT_WR);

    if (auto wait_res = network::wait_response(sock.get(), cfg.network.timeout_ms);
        std::holds_alternative<network::WaitError>(wait_res)) {
        out.wait_error = std::get<network::WaitError>(wait_res);
    } else {
        out.response = std::get<std::vector<uint8_t>>(std::move(wait_res));
    }
    return out;
}

/**
 * @brief One iteration of the __AFL_LOOP body: exchange the current testcase
 *        with the target, then health-check the target (race-free).
 */
void run_fuzz_iteration(const Config& cfg, pid_t child_pid, int target_pidfd,
                        std::vector<uint8_t>& payload_buf) {
    PROXY_LOG_TRACE("loop beginning");
    // TODO(claude): __AFL_FUZZ_TESTCASE_BUF/LEN only work if the shmem testcase feature is enabled by the AFL
    //   toolchain; `buf` is used without a null check, and len == 0 still opens a connection and sends nothing.
    //   (The former per-iteration std::cout debug lines are now PROXY_LOG_TRACE, compiled out with
    //   -Dstrip_low_logs=true and filtered by --log-level otherwise.)
    int len = __AFL_FUZZ_TESTCASE_LEN;
    uint8_t* buf = __AFL_FUZZ_TESTCASE_BUF;

    ExchangeOutcome ex = exchange_once(cfg, buf, static_cast<size_t>(len), payload_buf);

    if (ex.connect_error) {
        PROXY_LOG_ERROR("failed to connect to {}:{}: {}",
                        cfg.network.host, cfg.network.port, ex.connect_error->to_string());
        // Connection failed, target might be dead.
        // Check health immediately.
        // TODO(claude): BUGS. (1) A connect failure when the target is alive falls through to the next
        //   loop iteration, which keeps retrying (and logging) forever - AFL sees a hang instead of a
        //   clean failure. PARTIALLY RESOLVED: an exited/unknown target is now detected via
        //   check_target_state and aborts the proxy below; a live-but-unconnectable target still just
        //   retries on the next iteration.
        //   (2) RESOLVED: right after a crash waitpid(WNOHANG) used to return 0 and miss it; check_target_state
        //       now reads /proc exit flags and waits on the pidfd, so the crash is seen in this iteration.
        //   (3) RESOLVED: use utils::crash_proxy() ([noreturn], abort() fallback) instead of relying on a bare
        //       raise(SIGSEGV) to kill the process.
        //   (4) The dead target is never respawned; spec only says to crash.
        auto st = process::check_target_state(child_pid, target_pidfd, cfg.cleanup.force_kill_ms);
        switch (st.kind) {
        case process::TargetState::Kind::Crashed:
            PROXY_LOG_WARN("target {} after connect failure, crashing the proxy so AFL respawns it",
                           st.to_string());
            utils::crash_proxy();
            break;
        case process::TargetState::Kind::Exited:
        case process::TargetState::Kind::Unknown:
            PROXY_LOG_WARN("target {} after connect failure, aborting the proxy so AFL respawns it",
                           st.to_string());
            utils::abort_proxy();
            break;
        case process::TargetState::Kind::Alive:
            // Transient connect failure against a live target; retry next iteration.
            break;
        }
        return;
    }
    PROXY_LOG_TRACE("successfully connected");

    if (ex.send_error) {
        PROXY_LOG_ERROR("send failed: {}", ex.send_error->to_string());
    }

    PROXY_LOG_TRACE("Request (size={}): '{}'",
                        ex.request_size,
                        log::escape_bytes(payload_buf, 256));
    if (ex.wait_error) {
        PROXY_LOG_ERROR("waiting for response failed: {}", ex.wait_error->to_string());
    } else {
        PROXY_LOG_TRACE("Response (size={}): '{}'",
                        ex.response.size(),
                        log::escape_bytes(ex.response, 256));
    }

    PROXY_LOG_TRACE("one iteration done");

    // Post-response quiescence probe (network.probe). The target must service
    // a throwaway connection before this iteration ends; a serial server can
    // only do that once the previous connection is fully handled (post-response
    // cleanup included). If the target died during that cleanup, the probe
    // socket gets RST (also "readable"), and the health check below sees the
    // dying flags in the same iteration, so the crash stays attributed to the
    // input that caused it. The probe itself never decides: classification is
    // done by check_target_state() below.
    if (cfg.network.probe) {
        auto pr = network::probe_target(cfg.network);
        if (pr == network::ProbeOutcome::Refused) {
            PROXY_LOG_WARN("probe connection refused - target listener is gone (crashed or rate-limited?)");
        } else {
            PROXY_LOG_TRACE("probe: {}", network::probe_outcome_to_string(pr));
        }
    }

    // Health check (race-free). Replaces the old sleep_ms()+waitpid(WNOHANG)
    // heuristic: do_exit() closes the target's socket fds before it becomes a
    // waitable zombie, so a bare WNOHANG right after wait_response() could miss
    // a crash and attribute it to the NEXT input. check_target_state reads the
    // kernel's PF_EXITING/PF_SIGNALED flags from /proc and blocks on the pidfd
    // until the death materialises, so the crash is seen in THIS iteration.
    // TODO(claude): (1) still racy for a crash that happens AFTER this check
    //   returns Alive and after the probe was serviced (deferred timers / async
    //   work) - that needs idle detection (procfs syscall whitelist) or ptrace
    //   checkpoints, not a sleep. (2) crashes in worker children of the target
    //   (nginx workers, not the direct child) are still not detected here - only
    //   the direct child pid is watched (procfs/PF check is per-pid).
    auto st = process::check_target_state(child_pid, target_pidfd, cfg.cleanup.force_kill_ms);
    PROXY_LOG_TRACE("target state: {}", st.to_string());
    switch (st.kind) {
    case process::TargetState::Kind::Crashed:
        PROXY_LOG_WARN("target {}, crashing the proxy so AFL records the finding", st.to_string());
        utils::crash_proxy();
        break;
    case process::TargetState::Kind::Exited:
    case process::TargetState::Kind::Unknown:
        PROXY_LOG_WARN("target {}, aborting the proxy so AFL records the finding", st.to_string());
        utils::abort_proxy();
        break;
    case process::TargetState::Kind::Alive:
        break; // normal case, keep fuzzing
    }
    // TODO(claude): spec only covers WIFSIGNALED. RESOLVED: a target that exited (WIFEXITED, e.g. abort
    //   handled by its own exit(1), OOM watchdog, ASan exit code) now aborts the proxy via
    //   utils::abort_proxy() so AFL records the finding instead of spinning on ECONNREFUSED in later
    //   iterations; an Unknown (already reaped / not our child) target does the same. No respawn:
    //   spec only says to crash.
}

int run_proxy_mode(const Config& cfg, bool forward_output) {
    if (prctl(PR_SET_DUMPABLE, 0) != 0) {
        PROXY_LOG_WARN("prctl(PR_SET_DUMPABLE, 0) failed: {} (continuing)", std::strerror(errno));
    }

    // TODO(claude): spec 6.1 order: cleanup -> check __AFL_SHM_ID -> __AFL_INIT -> spawn. Here cleanup runs in
    //   main() before the env checks (ok), but see the next TODO on AFL_CASSOWIRE_FORCE_FINAL_LOC.
    // Check AFL SHM IDs
    if (!getenv("__AFL_SHM_ID")) {
        PROXY_LOG_ERROR("__AFL_SHM_ID not found in environment. Run with afl-fuzz.");
        return 1;
    }
    if (cfg.afl.enable_cmplog && !getenv("__AFL_CMPLOG_SHM_ID")) {
        PROXY_LOG_ERROR("enable_cmplog is true, but __AFL_CMPLOG_SHM_ID not found in environment.");
        return 1;
    }

    // AFL_CASSOWIRE_FORCE_FINAL_LOC is consumed by the target's AFL++ runtime to
    // force __afl_final_loc. In proxy mode it must be set and be a valid
    // uint64 integer.
    // TODO(claude): NOT IN SPEC. AFL_CASSOWIRE_FORCE_FINAL_LOC is a mandatory env var here (proxy refuses to start
    //   without it) but spec 3/6.1 only requires __AFL_SHM_ID (+ __AFL_CMPLOG_SHM_ID). It is also never
    //   forwarded to the target (see process.cpp), and value is only printed. Document in the spec or drop.
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

    // Initialize AFL persistent mode
    __AFL_INIT();

    // Spawn target
    auto prep_opt = process::prepare_target(cfg, process::SpawnMode::ProxyMode);
    if (!prep_opt) {
        PROXY_LOG_ERROR("failed to prepare target process.");
        return 1;
    }
    process::SpawnedTarget spawned = process::fork_target(cfg, *prep_opt, process::SpawnMode::ProxyMode,
                                                          forward_output, &g_child_pid);
    if (spawned.pid <= 0) {
        PROXY_LOG_ERROR("failed to spawn target process.");
        return 1;
    }
    process::handshake_tracer(spawned.pid, cfg);
    g_child_pid = spawned.pid;

    // Pollable pidfd for the target, used by the race-free health check
    // (process::check_target_state). Declared at function scope so it lives
    // for the whole AFL loop; closed when run_proxy_mode returns.
    utils::FdGuard target_pidfd{process::open_pidfd(spawned.pid)};
    if (target_pidfd.get() < 0) {
        PROXY_LOG_ERROR("pidfd_open failed for target pid {}: {} (requires kernel >= 5.3)",
                        static_cast<int>(spawned.pid), std::strerror(errno));
        timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
        return 1;
    }

    // Wait for port readiness
    auto port_res = network::wait_for_port(g_child_pid, cfg);
    if (std::holds_alternative<network::DetectError>(port_res)) {
        PROXY_LOG_ERROR("failed to detect port {}: {}",
                        cfg.network.port, std::get<network::DetectError>(port_res).to_string());

        // TODO: make a health check here maybe?
        timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
        return 1;
    }

    // Main AFL Loop
    // Scratch buffer reused every iteration to send prefix + fuzz data + suffix
    // (clear() keeps its capacity, so the hot loop does not reallocate).
    std::vector<uint8_t> payload_buf;
    payload_buf.reserve(cfg.payload.prefix.size() + cfg.payload.suffix.size() + 4096);

    while (__AFL_LOOP(cfg.afl.loop_count)) {
        run_fuzz_iteration(cfg, g_child_pid, target_pidfd.get(), payload_buf);
    }

    // Clean exit of AFL loop
    // TODO(claude): spec 5.1/6.1 says SIGTERM then wait force_kill_ms then SIGKILL; this uses plain SIGKILL
    //   (the correct call is commented out). A SIGKILL'd target leaves no chance to flush logs/coverage.
    //   Also the child is not reaped here.
    // timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
    kill_pgid(g_child_pid);
    PROXY_LOG_TRACE("kill {}", static_cast<int>(g_child_pid));
    return 0;
}

int run_test_mode(const Config& cfg, const std::string& input_path, bool forward_output) {
    if (input_path.empty()) {
        PROXY_LOG_ERROR("test mode requires --input <file> or '-'");
        return 1;
    }

    // --- Pass 1: Map Size Extraction ---
    // TODO(claude): setenv(AFL_DUMP_MAP_SIZE) on the PROXY's own environment is redundant (spawn_target already
    //   adds it via set_env_var when is_map_size_pass) and, with env_preserve: all, leaks into the proxy's
    //   environ; if spawn fails (early return below) it is never unset.
    setenv("AFL_DUMP_MAP_SIZE", "1", 1);
    auto prep_opt1 = process::prepare_target(cfg, process::SpawnMode::MapSizePass);
    if (!prep_opt1) {
        PROXY_LOG_ERROR("failed to prepare target for map size extraction.");
        unsetenv("AFL_DUMP_MAP_SIZE");
        return 1;
    }
    process::SpawnedTarget spawned1 = process::fork_target(cfg, *prep_opt1, process::SpawnMode::MapSizePass,
                                                           false, nullptr);
    if (spawned1.pid <= 0) {
        PROXY_LOG_ERROR("failed to spawn target for map size extraction.");
        unsetenv("AFL_DUMP_MAP_SIZE");
        return 1;
    }
    process::handshake_tracer(spawned1.pid, cfg);

    int status;
    // TODO(claude): BUG/spec: (1) blocking waitpid() with no timeout: a long-running target (nginx stays up
    //   forever) never exits by itself - with AFL_DUMP_MAP_SIZE the AFL runtime exits right after printing,
    //   but a target that is not instrumented will run (and hang the proxy) here. Spec says "Clean up the
    //   Pass 1 target process": it must be killed (SIGTERM->SIGKILL via timed_kill_pgid), not waited for.
    //   (2) g_child_pid is not set during Pass 1, so Ctrl+C during Pass 1 kills nothing. (3) The exit status
    //   is ignored.
    waitpid(spawned1.pid, &status, 0);
    
    // Collect map size from the pipe
    if (spawned1.map_size_fd >= 0) {
        process::collect_map_size(spawned1.map_size_fd);
    }
    unsetenv("AFL_DUMP_MAP_SIZE");

    // TODO(claude): stale/confusing comment (hedges "OR"); also Pass 1 failure (no/invalid map size) is NOT
    //   propagated - this always prints "completed" and goes on to Pass 2 even when the parse failed, in
    //   violation of spec 6.2 ("return an error"). Needs a real return value from spawn_target / a
    //   dedicated function returning std::optional<uint64_t>.
    // Map size parsing is handled internally by process::spawn_target returning via stdout
    // pipe which main reads, OR process::spawn_target handles it.
    // Assuming process::spawn_target in test_mode handles the pipe and logs the map size.
    PROXY_LOG_INFO("Pass 1 (Map Size) completed.");

    // --- Pass 2: Single Iteration ---
    // TODO(claude): ordering/stdin issue: reading the payload from stdin ("-") happens AFTER Pass 1 spawned
    //   the child, fine, but an empty regular file is reported as "failed to read" (see
    //   utils::read_input_file). Also spec 6.2 step 3 says the --input validation must be done BEFORE
    //   Pass 1; it is (input_path.empty() check), but the file itself is only opened after Pass 1 -
    //   validate readability up front to fail early.
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
        // TODO: yes, empty file is a file! It is not fail!
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
    process::SpawnedTarget spawned2 = process::fork_target(cfg, *prep_opt2, process::SpawnMode::PlainTest,
                                                           forward_output, &g_child_pid);
    if (spawned2.pid <= 0) {
        PROXY_LOG_ERROR("failed to spawn target for test iteration.");
        return 1;
    }
    process::handshake_tracer(spawned2.pid, cfg);
    g_child_pid = spawned2.pid;

    auto port_res2 = network::wait_for_port(g_child_pid, cfg);
    if (std::holds_alternative<network::DetectError>(port_res2)) {
        PROXY_LOG_ERROR("failed to detect port {}: {}",
                        cfg.network.port, std::get<network::DetectError>(port_res2).to_string());
        timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
        return 1;
    }

    // One-shot of the same connect -> send -> wait cycle the AFL loop runs.
    ExchangeOutcome ex = exchange_once(cfg, input_data.data(), input_data.size(), payload_buf);
    if (ex.connect_error) {
        PROXY_LOG_ERROR("failed to connect to {}:{}: {}",
                        cfg.network.host, cfg.network.port, ex.connect_error->to_string());
        timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
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

    pid_t res = waitpid(g_child_pid, &status, WNOHANG);
    PROXY_LOG_INFO("waitpid res {} status {:x}, signaled={}", res, status, WIFSIGNALED(status));
    
    // Clean exit
    timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
    return 0;
}

int main(int argc, char* argv[]) {
    // Initialize logging first so that CLI/config errors are reported through
    // the logger; --log-level reconfigures it after parsing.
    log::init(spdlog::level::info);

    // TODO(claude): CLI vs spec. (1) Spec says `proxy` is the DEFAULT mode; with argparse subparsers and no
    //   subcommand it works only because is_subcommand_used("test") is false - but `proxy` subcommand
    //   itself is never queried, and an unknown positional is rejected. (2) `-c/--config`, `--log-level` and
    //   `--child-output` are declared on the parent parser (src/args.cpp), so they must come BEFORE the
    //   subcommand (`afl_proxy -c x test`); `afl_proxy test -c x` is an error, which is surprising.
    //   `--input` is declared on the `test` subparser and must come AFTER it (`afl_proxy test --input f`).
    //   (3) `--input` is not enforced as mandatory in test mode by the parser (checked manually later, after
    //   config loading + stale cleanup killed processes!). (4) program name "afl_proxy" vs binary
    //   "afl-cassowire".
    auto args_res = args::parse_args(argc, argv);
    if (const auto* parse_err = std::get_if<args::ArgParseError>(&args_res)) {
        PROXY_LOG_ERROR("{}", parse_err->message);
        std::cerr << parse_err->usage;
        return 1;
    }
    const auto& parsed = std::get<args::ParsedArgs>(args_res);

    // parse_args() already validated the level name; this only converts it.
    auto log_level = log::parse_level(parsed.log_level);
    if (!log_level) {
        PROXY_LOG_ERROR("invalid --log-level '{}': expected trace, debug, info, warn, error, critical, or off",
                        parsed.log_level);
        return 1;
    }
    log::init(*log_level);

    // Load Configuration
    auto config_res = load_config(parsed.config_path);
    if (std::holds_alternative<ConfigError>(config_res)) {
        PROXY_LOG_ERROR("{}", std::get<ConfigError>(config_res).to_string());
        return 1;
    }

    Config cfg = std::get<Config>(config_res);

    // TODO(claude): spec 6.2 says test mode validates --input BEFORE running cleanup; here cleanup (which
    //   SIGTERM/SIGKILLs other processes and sleeps force_kill_ms) runs first and only then run_test_mode()
    //   rejects a missing --input. Also in proxy mode the env checks (__AFL_SHM_ID) happen after the kill.
    //   Also: `Config cfg = std::get<Config>(...)` copies instead of moving; the spec wants std::visit.
    // Stale Process Cleanup
    process::cleanup_stale_processes(cfg.cleanup);

    if (parsed.is_test_mode) {
        return run_test_mode(cfg, parsed.input_path, parsed.forward_output);
    } else {
        return run_proxy_mode(cfg, parsed.forward_output);
    }
}
