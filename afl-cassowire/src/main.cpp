// src/main.cpp

#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <variant>
#include <optional>
#include <cstdlib>
#include <cstring>
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
#include <chrono>

#include <argparse/argparse.hpp>

#include "config.hpp"
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

// TODO: i guess we have to use logging library. Or at least make some useful workarounds
// NOTES: well, about log
// If we will use logging to logger we have to capture the output from the binaries
// And it must be configurable
// 
bool create_log_file(const std::string& path) {
    // TODO(claude): spec says stdout/stderr logs are optional "only for proxy mode" and creation failure
    //   must fail - OK, but if both paths are the same file, or the path is a dir/relative to a different
    //   cwd, nothing is detected. Also file is opened O_TRUNC here and again in the child (double truncation).
    if (path.empty()) return true;
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        std::cerr << "proxy: failed to create log file: " << path << " (" << strerror(errno) << ")\n";
        return false;
    }
    close(fd);
    return true;
}

int run_proxy_mode(const Config& cfg) {
    // TODO(claude): spec 6.1 order: cleanup -> check __AFL_SHM_ID -> __AFL_INIT -> spawn. Here cleanup runs in
    //   main() before the env checks (ok), but see the next TODO on PROXY_AFL_FORCE_FINAL_LOC.
    // Check AFL SHM IDs
    if (!getenv("__AFL_SHM_ID")) {
        std::cerr << "proxy: __AFL_SHM_ID not found in environment. Run with afl-fuzz.\n";
        return 1;
    }
    if (cfg.afl.enable_cmplog && !getenv("__AFL_CMPLOG_SHM_ID")) {
        std::cerr << "proxy: enable_cmplog is true, but __AFL_CMPLOG_SHM_ID not found in environment.\n";
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
        std::cerr << "proxy: PROXY_AFL_FORCE_FINAL_LOC not found in environment. Run with PROXY_AFL_FORCE_FINAL_LOC=<uint64>.\n";
        return 1;
    }

    uint64_t force_final_loc = 0;
    if (auto parsed = utils::parse_u64_strict(final_loc_str);
        std::holds_alternative<uint64_t>(parsed)) {
        force_final_loc = std::get<uint64_t>(parsed);
    } else {
        std::cerr << "proxy: PROXY_AFL_FORCE_FINAL_LOC must be an integer (uint64), got: '" << final_loc_str << "'\n";
        return 1;
    }

    std::cout << "proxy: PROXY_AFL_FORCE_FINAL_LOC = " << force_final_loc << std::endl;

    // Eager log file creation
    if (!create_log_file(cfg.target.log.stdout_path) || !create_log_file(cfg.target.log.stderr_path)) {
        return 1;
    }

    // Initialize AFL persistent mode
    __AFL_INIT();

    // Spawn target
    auto prep_opt = process::prepare_target(cfg, process::SpawnMode::ProxyMode);
    if (!prep_opt) {
        std::cerr << "proxy: failed to prepare target process.\n";
        return 1;
    }
    process::SpawnedTarget spawned = process::fork_target(cfg, *prep_opt, process::SpawnMode::ProxyMode, &g_child_pid);
    if (spawned.pid <= 0) {
        std::cerr << "proxy: failed to spawn target process.\n";
        return 1;
    }
    process::handshake_tracer(spawned.pid, cfg);
    g_child_pid = spawned.pid;

    // Wait for port readiness
    auto port_res = network::wait_for_port(g_child_pid, cfg);
    if (std::holds_alternative<network::DetectError>(port_res)) {
        std::cerr << "proxy: failed to detect port " << cfg.network.port << ": "
                  << std::get<network::DetectError>(port_res).to_string() << "\n";
        timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
        return 1;
    }

    // Main AFL Loop
    // TODO(claude): all the std::cout debug lines in the loop (system_clock::now() << ...) hit stdout on every
    //   iteration - very slow in a fuzz hot loop. Remove or gate behind a verbose flag. Also
    //   __AFL_FUZZ_TESTCASE_BUF/LEN only work if the shmem testcase feature is enabled by the AFL toolchain;
    //   `buf` is used without a null check, and len == 0 still opens a connection and sends nothing.
    // Scratch buffer reused every iteration to send prefix + fuzz data + suffix
    // (clear() keeps its capacity, so the hot loop does not reallocate).
    std::vector<uint8_t> payload_buf;
    payload_buf.reserve(cfg.payload.prefix.size() + cfg.payload.suffix.size() + 4096);

    while (__AFL_LOOP(cfg.afl.loop_count)) {
        std::cout << std::chrono::system_clock::now() << " loop beginning\n";
        int len = __AFL_FUZZ_TESTCASE_LEN;
        uint8_t* buf = __AFL_FUZZ_TESTCASE_BUF;

        auto conn = network::connect_target(cfg.network);
        if (std::holds_alternative<network::ConnectError>(conn)) {
            std::cerr << "proxy: failed to connect to " << cfg.network.host << ":" << cfg.network.port << ": "
                      << std::get<network::ConnectError>(conn).to_string() << "\n";
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
                std::cout << "Crash it\n";
                raise(SIGSEGV); // Crash proxy so AFL respawns
            }
            // continue;
            break;
        }
        utils::FdGuard sock = std::get<utils::FdGuard>(std::move(conn));
        std::cout << std::chrono::system_clock::now() << " sock " << sock.get() << "\n";
        std::cout <<  std::chrono::system_clock::now() << " Successfully connected\n";

        // Final payload = configured prefix + fuzz data + configured suffix
        payload_buf.clear();
        payload_buf.insert(payload_buf.end(), cfg.payload.prefix.begin(), cfg.payload.prefix.end());
        payload_buf.insert(payload_buf.end(), buf, buf + len);
        payload_buf.insert(payload_buf.end(), cfg.payload.suffix.begin(), cfg.payload.suffix.end());

        if (auto send_res = network::send_all(sock.get(), payload_buf.data(), payload_buf.size(), cfg.network.timeout_ms);
            std::holds_alternative<network::SendError>(send_res)) {
            std::cerr << "proxy: send failed: "
                      << std::get<network::SendError>(send_res).to_string() << "\n";
        }
        if (auto wait_res = network::wait_response(sock.get(), cfg.network.timeout_ms);
            std::holds_alternative<network::WaitError>(wait_res)) {
            std::cerr << "proxy: waiting for response failed: "
                      << std::get<network::WaitError>(wait_res).to_string() << "\n";
        }
        // The socket is closed when `sock` goes out of scope at the end of the iteration.

        std::cout <<  std::chrono::system_clock::now() << " One iteration\n";

        // Health check
        // TODO(claude): health check is racy: a crash triggered by the payload may happen a bit AFTER
        //   wait_response() returns (timeout 200ms or recv EOF), so WNOHANG often returns 0 and the crash is
        //   noticed one iteration late and attributed to the WRONG input. Consider a short wait or checking
        //   again at the start of the next iteration. Also crashes in worker children of the target (nginx
        //   workers, not the master) are never detected at all - only the direct child pid is watched.
        int status;
        pid_t res = waitpid(g_child_pid, &status, WNOHANG);
        if (res == g_child_pid && WIFSIGNALED(status)) {
            // Target crashed
            raise(SIGSEGV);
        }
        // TODO: what if the target exited but not crashed
        // TODO(claude): spec only covers WIFSIGNALED. A target that exited (WIFEXITED, e.g. abort handled
        //   by its own exit(1), OOM watchdog, ASan exit code) is reaped here (waitpid consumed the status),
        //   `res == g_child_pid` is then never true again on later iterations, and subsequent iterations get
        //   ECONNREFUSED -> `break` above. Decide: respawn, crash the proxy, or exit with an error.
        std::cout << std::chrono::system_clock::now() << " waitpid res " << res << "\n";
    }

    // Clean exit of AFL loop
    // TODO(claude): spec 5.1/6.1 says SIGTERM then wait force_kill_ms then SIGKILL; this uses plain SIGKILL
    //   (the correct call is commented out). A SIGKILL'd target leaves no chance to flush logs/coverage.
    //   Also the child is not reaped here, and the log message uses system_clock::now() streaming.
    // timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
    kill_pgid(g_child_pid);
    std::cout << std::chrono::system_clock::now() << " kill " << g_child_pid << "\n";
    return 0;
}

int run_test_mode(const Config& cfg, const std::string& input_path) {
    if (input_path.empty()) {
        std::cerr << "proxy: test mode requires --input <file> or '-'\n";
        return 1;
    }

    // --- Pass 1: Map Size Extraction ---
    // TODO(claude): setenv(AFL_DUMP_MAP_SIZE) on the PROXY's own environment is redundant (spawn_target already
    //   adds it via set_env_var when is_map_size_pass) and, with env_preserve: all, leaks into the proxy's
    //   environ; if spawn fails (early return below) it is never unset.
    setenv("AFL_DUMP_MAP_SIZE", "1", 1);
    auto prep_opt1 = process::prepare_target(cfg, process::SpawnMode::MapSizePass);
    if (!prep_opt1) {
        std::cerr << "proxy: failed to prepare target for map size extraction.\n";
        unsetenv("AFL_DUMP_MAP_SIZE");
        return 1;
    }
    process::SpawnedTarget spawned1 = process::fork_target(cfg, *prep_opt1, process::SpawnMode::MapSizePass, nullptr);
    if (spawned1.pid <= 0) {
        std::cerr << "proxy: failed to spawn target for map size extraction.\n";
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
    // Assuming process::spawn_target in test_mode handles the pipe and prints the map size to proxy's stdout.
    std::cout << "proxy: Pass 1 (Map Size) completed.\n";

    // --- Pass 2: Single Iteration ---
    // TODO(claude): ordering/stdin issue: reading the payload from stdin ("-") happens AFTER Pass 1 spawned
    //   the child, fine, but an empty regular file is reported as "failed to read" (see
    //   utils::read_input_file). Also spec 6.2 step 3 says the --input validation must be done BEFORE
    //   Pass 1; it is (input_path.empty() check), but the file itself is only opened after Pass 1 -
    //   validate readability up front to fail early.
    std::vector<uint8_t> input_data;
    if (auto input_res = utils::read_input_file(input_path);
        std::holds_alternative<std::error_code>(input_res)) {
        std::cerr << "proxy: failed to read payload from " << input_path << ": "
                  << std::get<std::error_code>(input_res).message() << "\n";
        return 1;
    } else {
        input_data = std::get<std::vector<uint8_t>>(std::move(input_res));
    }
    if (input_data.empty() && input_path != "-") {
        // TODO: yes, empty file is a file! It is not fail!
        std::cerr << "proxy: failed to read payload from " << input_path << "\n";
        return 1;
    }

    // Final payload = configured prefix + input data + configured suffix
    std::vector<uint8_t> payload = cfg.payload.wrap(input_data.data(), input_data.size());

    auto prep_opt2 = process::prepare_target(cfg, process::SpawnMode::PlainTest);
    if (!prep_opt2) {
        std::cerr << "proxy: failed to prepare target for test iteration.\n";
        return 1;
    }
    process::SpawnedTarget spawned2 = process::fork_target(cfg, *prep_opt2, process::SpawnMode::PlainTest, &g_child_pid);
    if (spawned2.pid <= 0) {
        std::cerr << "proxy: failed to spawn target for test iteration.\n";
        return 1;
    }
    process::handshake_tracer(spawned2.pid, cfg);
    g_child_pid = spawned2.pid;

    auto port_res2 = network::wait_for_port(g_child_pid, cfg);
    if (std::holds_alternative<network::DetectError>(port_res2)) {
        std::cerr << "proxy: failed to detect port " << cfg.network.port << ": "
                  << std::get<network::DetectError>(port_res2).to_string() << "\n";
        timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
        return 1;
    }

    auto conn = network::connect_target(cfg.network);
    if (std::holds_alternative<network::ConnectError>(conn)) {
        std::cerr << "proxy: failed to connect to " << cfg.network.host << ":" << cfg.network.port << ": "
                  << std::get<network::ConnectError>(conn).to_string() << "\n";
        timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
        return 1;
    }
    utils::FdGuard sock = std::get<utils::FdGuard>(std::move(conn));

    bool io_ok = true;
    if (auto send_res = network::send_all(sock.get(), payload.data(), payload.size(), cfg.network.timeout_ms);
        std::holds_alternative<network::SendError>(send_res)) {
        std::cerr << "proxy: send failed: "
                  << std::get<network::SendError>(send_res).to_string() << "\n";
        io_ok = false;
    }

    // Spec 6.2: print the target's response in test mode.
    auto wait_res = network::wait_response(sock.get(), cfg.network.timeout_ms);
    if (std::holds_alternative<std::vector<uint8_t>>(wait_res)) {
        const auto& data = std::get<std::vector<uint8_t>>(wait_res);
        std::cout.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!data.empty() && data.back() != '\n') std::cout << "\n";
    } else {
        std::cerr << "proxy: waiting for response failed: "
                  << std::get<network::WaitError>(wait_res).to_string() << "\n";
        io_ok = false;
    }

    if (io_ok) {
        std::cout << "proxy: Pass 2 (Single Iteration) completed successfully.\n";
    } else {
        std::cerr << "proxy: Pass 2 (Single Iteration) failed.\n";
    }
    
    // Clean exit
    timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
    return 0;
}

int main(int argc, char* argv[]) {
    // TODO(claude): CLI vs spec. (1) Spec says `proxy` is the DEFAULT mode; with argparse subparsers and no
    //   subcommand it works only because is_subcommand_used("test") is false - but `proxy` subcommand
    //   itself is never queried, and an unknown positional is rejected. (2) `-c/--config` and `--input` are
    //   declared on the parent parser, so they must come BEFORE the subcommand (`afl_proxy -c x test`);
    //   `afl_proxy test -c x` is an error, which is surprising. (3) `--input` is not enforced as mandatory in
    //   test mode by the parser (checked manually later, after config loading + stale cleanup killed
    //   processes!). (4) program name "afl_proxy" vs binary "afl-cassowire".
    argparse::ArgumentParser program("afl_proxy", "1.0");
    
    program.add_argument("-c", "--config")
        .help("Path to the YAML configuration file")
        .default_value(std::string("config.yaml"));

    program.add_argument("--input")
        .help("Input file for test mode (use '-' for stdin)");

    argparse::ArgumentParser proxy_cmd("proxy");
    proxy_cmd.add_description("Run in persistent AFL++ proxy mode (default).");

    argparse::ArgumentParser test_cmd("test");
    test_cmd.add_description("Run in test/debug mode.");

    program.add_subparser(proxy_cmd);
    program.add_subparser(test_cmd);

    try {
        program.parse_args(argc, argv);
    } catch (const std::runtime_error& err) {
        std::cerr << err.what() << "\n";
        std::cerr << program;
        return 1;
    }

    std::string config_path = program.get<std::string>("--config");
    bool is_test_mode = program.is_subcommand_used("test");
    std::string input_path = program.is_used("--input") ? program.get<std::string>("--input") : "";

    // Load Configuration
    auto config_res = load_config(config_path);
    if (std::holds_alternative<ConfigError>(config_res)) {
        std::cerr << std::get<ConfigError>(config_res).to_string() << "\n";
        return 1;
    }
    
    Config cfg = std::get<Config>(config_res);

    // TODO(claude): spec 6.2 says test mode validates --input BEFORE running cleanup; here cleanup (which
    //   SIGTERM/SIGKILLs other processes and sleeps force_kill_ms) runs first and only then run_test_mode()
    //   rejects a missing --input. Also in proxy mode the env checks (__AFL_SHM_ID) happen after the kill.
    //   Also: `Config cfg = std::get<Config>(...)` copies instead of moving; the spec wants std::visit.
    // Stale Process Cleanup
    process::cleanup_stale_processes(cfg.cleanup);

    if (is_test_mode) {
        return run_test_mode(cfg, input_path);
    } else {
        return run_proxy_mode(cfg);
    }
}
