// src/main.cpp

#include <iostream>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <vector>
#include <variant>
#include <optional>
#include <cstdlib>
#include <csignal>
#include <cerrno>
#include <cstdint>
#include <filesystem>
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

int run_proxy_mode(const Config& cfg, bool forward_output) {
    // TODO(claude): spec 6.1 order: cleanup -> check __AFL_SHM_ID -> __AFL_INIT -> spawn. Here cleanup runs in
    //   main() before the env checks (ok), but see the next TODO on PROXY_AFL_FORCE_FINAL_LOC.
    // Check AFL SHM IDs
    if (!getenv("__AFL_SHM_ID")) {
        PROXY_LOG_ERROR("__AFL_SHM_ID not found in environment. Run with afl-fuzz.");
        return 1;
    }
    if (cfg.afl.enable_cmplog && !getenv("__AFL_CMPLOG_SHM_ID")) {
        PROXY_LOG_ERROR("enable_cmplog is true, but __AFL_CMPLOG_SHM_ID not found in environment.");
        return 1;
    }

    // PROXY_AFL_FORCE_FINAL_LOC is consumed by the target's AFL++ runtime to
    // force __afl_final_loc. In proxy mode it must be set and be a valid
    // uint64 integer.
    // TODO(claude): NOT IN SPEC. PROXY_AFL_FORCE_FINAL_LOC is a mandatory env var here (proxy refuses to start
    //   without it) but spec 3/6.1 only requires __AFL_SHM_ID (+ __AFL_CMPLOG_SHM_ID). It is also never
    //   forwarded to the target (see process.cpp), and value is only printed. Document in the spec or drop.
    const char* final_loc_str = getenv("PROXY_AFL_FORCE_FINAL_LOC");
    if (!final_loc_str) {
        PROXY_LOG_ERROR("PROXY_AFL_FORCE_FINAL_LOC not found in environment. Run with PROXY_AFL_FORCE_FINAL_LOC=<uint64>.");
        return 1;
    }

    uint64_t force_final_loc = 0;
    if (auto parsed = utils::parse_u64_strict(final_loc_str);
        std::holds_alternative<uint64_t>(parsed)) {
        force_final_loc = std::get<uint64_t>(parsed);
    } else {
        PROXY_LOG_ERROR("PROXY_AFL_FORCE_FINAL_LOC must be an integer (uint64), got: '{}'", final_loc_str);
        return 1;
    }

    PROXY_LOG_INFO("PROXY_AFL_FORCE_FINAL_LOC = {}", force_final_loc);

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
    // TODO(claude): __AFL_FUZZ_TESTCASE_BUF/LEN only work if the shmem testcase feature is enabled by the AFL
    //   toolchain; `buf` is used without a null check, and len == 0 still opens a connection and sends nothing.
    //   (The former per-iteration std::cout debug lines are now PROXY_LOG_TRACE, compiled out with
    //   -Dstrip_low_logs=true and filtered by --log-level otherwise.)
    // Scratch buffer reused every iteration to send prefix + fuzz data + suffix
    // (clear() keeps its capacity, so the hot loop does not reallocate).
    std::vector<uint8_t> payload_buf;
    payload_buf.reserve(cfg.payload.prefix.size() + cfg.payload.suffix.size() + 4096);

    while (__AFL_LOOP(cfg.afl.loop_count)) {
        PROXY_LOG_TRACE("loop beginning");
        int len = __AFL_FUZZ_TESTCASE_LEN;
        uint8_t* buf = __AFL_FUZZ_TESTCASE_BUF;

        auto conn = network::connect_target(cfg.network);
        if (std::holds_alternative<network::ConnectError>(conn)) {
            PROXY_LOG_ERROR("failed to connect to {}:{}: {}",
                            cfg.network.host, cfg.network.port,
                            std::get<network::ConnectError>(conn).to_string());
            // Connection failed, target might be dead.
            // Check health immediately.
            // TODO(claude): BUGS. (1) A connect failure when the target is alive (or exited normally, not
            //   signalled) falls through to `break`, which ends the whole fuzzing loop and returns 0 with no
            //   message - AFL then sees a clean exit instead of a hang/failure. (2) Right after a crash the
            //   target may not be reaped yet, so waitpid(WNOHANG) can return 0 and the crash is missed.
            //   (3) After raise(SIGSEGV) the code relies on the signal killing the process; use
            //   utils::crash_proxy(). (4) The dead target is never respawned; spec only says to crash.
            int status;
            if (waitpid(g_child_pid, &status, WNOHANG) == g_child_pid && WIFSIGNALED(status)) {
                PROXY_LOG_WARN("target crashed, crashing the proxy so AFL respawns it");
                
                // raise(SIGSEGV); // Crash proxy so AFL respawns
                PROXY_LOG_WARN("wtf, raise failed?");
            }
            continue;
        }
        utils::FdGuard sock = std::get<utils::FdGuard>(std::move(conn));
        PROXY_LOG_TRACE("sock {}", sock.get());
        PROXY_LOG_TRACE("successfully connected");

        // Final payload = configured prefix + fuzz data + configured suffix
        payload_buf.clear();
        payload_buf.insert(payload_buf.end(), cfg.payload.prefix.begin(), cfg.payload.prefix.end());
        payload_buf.insert(payload_buf.end(), buf, buf + len);
        payload_buf.insert(payload_buf.end(), cfg.payload.suffix.begin(), cfg.payload.suffix.end());

        if (auto send_res = network::send_all(sock.get(), payload_buf.data(), payload_buf.size(), cfg.network.timeout_ms);
            std::holds_alternative<network::SendError>(send_res)) {
            PROXY_LOG_ERROR("send failed: {}", std::get<network::SendError>(send_res).to_string());
        }

        shutdown(sock.get(), SHUT_WR);

        PROXY_LOG_DEBUG("Request (size={}): '{}'",
                            payload_buf.size(),
                            log::escape_bytes(payload_buf, 256));
        if (auto wait_res = network::wait_response(sock.get(), cfg.network.timeout_ms);
            std::holds_alternative<network::WaitError>(wait_res)) {
            PROXY_LOG_ERROR("waiting for response failed: {}",
                            std::get<network::WaitError>(wait_res).to_string());
        } else {
            // No local binding here: with -Dstrip_low_logs=true this
            // PROXY_LOG_DEBUG compiles out and the binding would be unused.
            PROXY_LOG_DEBUG("Response (size={}): '{}'",
                            std::get<std::vector<uint8_t>>(wait_res).size(),
                            log::escape_bytes(std::get<std::vector<uint8_t>>(wait_res), 256));
        }
        // The socket is closed when `sock` goes out of scope at the end of the iteration.

        PROXY_LOG_TRACE("one iteration done");

        // Health check
        // TODO(claude): health check is racy: a crash triggered by the payload may happen a bit AFTER
        //   wait_response() returns (timeout 200ms or recv EOF), so WNOHANG often returns 0 and the crash is
        //   noticed one iteration late and attributed to the WRONG input. Consider a short wait or checking
        //   again at the start of the next iteration. Also crashes in worker children of the target (nginx
        //   workers, not the master) are never detected at all - only the direct child pid is watched.
        int status;
    
        utils::sleep_ms(1);
        pid_t res = waitpid(g_child_pid, &status, WNOHANG);
        PROXY_LOG_TRACE("waitpid res={}, status={:x} signal={}", res, status, WIFSIGNALED(status));
        // TODO: what if g_child_pid is not equal to res?
        if (res == g_child_pid && WIFSIGNALED(status)) {
            // Target crashed
            PROXY_LOG_WARN("target crashed (signalled), crashing the proxy");
            raise(SIGSEGV);
        }
        // TODO: what if the target exited but not crashed
        // TODO(claude): spec only covers WIFSIGNALED. A target that exited (WIFEXITED, e.g. abort handled
        //   by its own exit(1), OOM watchdog, ASan exit code) is reaped here (waitpid consumed the status),
        //   `res == g_child_pid` is then never true again on later iterations, and subsequent iterations get
        //   ECONNREFUSED -> `break` above. Decide: respawn, crash the proxy, or exit with an error.
        PROXY_LOG_TRACE("waitpid res {}", res);
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

    // Final payload = configured prefix + input data + configured suffix
    std::vector<uint8_t> payload = cfg.payload.wrap(input_data.data(), input_data.size());

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

    auto conn = network::connect_target(cfg.network);
    if (std::holds_alternative<network::ConnectError>(conn)) {
        PROXY_LOG_ERROR("failed to connect to {}:{}: {}",
                        cfg.network.host, cfg.network.port,
                        std::get<network::ConnectError>(conn).to_string());
        timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
        return 1;
    }
    utils::FdGuard sock = std::get<utils::FdGuard>(std::move(conn));

    bool io_ok = true;
    if (auto send_res = network::send_all(sock.get(), payload.data(), payload.size(), cfg.network.timeout_ms);
        std::holds_alternative<network::SendError>(send_res)) {
        PROXY_LOG_ERROR("send failed: {}", std::get<network::SendError>(send_res).to_string());
        io_ok = false;
    }

    // Log the target's response in test mode (escaped, any binary safe).
    auto wait_res = network::wait_response(sock.get(), cfg.network.timeout_ms);
    if (std::holds_alternative<std::vector<uint8_t>>(wait_res)) {
        const auto& data = std::get<std::vector<uint8_t>>(wait_res);
        PROXY_LOG_INFO("Response: '{}'", log::escape_bytes(data));
    } else {
        PROXY_LOG_ERROR("waiting for response failed: {}",
                        std::get<network::WaitError>(wait_res).to_string());
        io_ok = false;
    }

    if (io_ok) {
        PROXY_LOG_INFO("Pass 2 (Single Iteration) completed successfully.");
    } else {
        PROXY_LOG_ERROR("Pass 2 (Single Iteration) failed.");
    }

    // TODO: wip, maybe remove that later
    utils::sleep_ms(500);

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
