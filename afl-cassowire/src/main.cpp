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

// TODO(claude): globals/handlers. (1) `g_force_kill_ms` is a plain int read from the signal handler - make it
//   volatile sig_atomic_t / std::atomic. (2) signal_handler() calls timed_kill_pgid() which loops with
//   nanosleep for up to force_kill_ms inside a signal handler and uses `errno` (not saved/restored) and
//   waitpid on the *group id* (works only because pgid == child pid). It also calls waitpid() on the
//   child while the main flow may be in waitpid() for the same pid -> racy reaping. Prefer: set a flag in the
//   handler, do the cleanup in the main loop. (3) the handler is installed AFTER load_config but before
//   cleanup_stale_processes() - fine - but SIGINT/SIGTERM are not blocked during fork, so g_child_pid==0
//   -> `pgid <= 0` makes the handler a no-op and exits immediately without killing a child that is
//   already forked but whose pid has not yet been stored in g_child_pid.
volatile sig_atomic_t g_child_pid = 0;
int g_force_kill_ms = 2000;

// TODO(claude): name is misleading: kill_pgid() sends SIGKILL (no SIGTERM, no wait, no reap). The spec
//   (5.1 "Signal Handling" + 6.1) wants SIGTERM -> wait force_kill_ms -> SIGKILL; the proxy-mode loop exit
//   uses this one (see the commented-out timed_kill_pgid in run_proxy_mode).
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
        // TODO(claude): `errno` is used but <cerrno> is not included in main.cpp (compiles only through
        //   transitive includes). Also if waitpid returns -1/EINTR or another error it is treated as "still
        //   running" and loops; and a tracee (ptrace mode) in a stop state will not exit on SIGTERM until
        //   resumed - SIGKILL after the timeout is then the only thing that works.
        if (res == pgid || (res == -1 && errno == ECHILD)) {
            return; // Process exited
        }
        
        clock_gettime(CLOCK_MONOTONIC, &now);
        long long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000LL + 
                               (now.tv_nsec - start.tv_nsec) / 1000000LL;
                               
        if (elapsed_ms >= ms) {
            // Timeout reached, send SIGKILL
            // TODO(claude): SIGKILL is sent but the child is never reaped (no final waitpid) -> zombie in
            //   test mode / when the proxy continues. Also when the group leader exits normally after SIGTERM,
            //   other members of the group (e.g. nginx workers) are NOT sent SIGKILL even if they ignore
            //   SIGTERM, since we only wait for the leader.
            kill(-pgid, SIGKILL);
            return;
        }
        
        // Short sleep to avoid busy-waiting (nanosleep is async-signal-safe)
        struct timespec req = {0, 10000000}; // 10ms
        nanosleep(&req, nullptr);
    }
}

void signal_handler(int signum) {
    timed_kill_pgid(g_child_pid, g_force_kill_ms);
    _exit(128 + signum);
}

void setup_signal_handlers() {
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // Do not use SA_RESTART so blocking calls exit on signal
    
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

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

std::vector<uint8_t> read_input_file(const std::string& path) {
    // TODO(claude): cannot distinguish "empty file / empty stdin" from "error": both return an empty vector.
    //   The caller then treats an empty regular file as a read failure (`payload.empty() && path != "-"`),
    //   but an empty stdin is accepted and a read() error (-1) from stdin is silently treated as EOF.
    //   Return std::optional<std::vector<uint8_t>> instead. EINTR on read() is also not handled.
    std::vector<uint8_t> buffer;
    if (path == "-") {
        // Read from stdin
        uint8_t chunk[4096];
        ssize_t bytes_read;
        while ((bytes_read = read(STDIN_FILENO, chunk, sizeof(chunk))) > 0) {
            buffer.insert(buffer.end(), chunk, chunk + bytes_read);
        }
    } else {
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) {
            std::cerr << "proxy: failed to open input file: " << path << "\n";
            return {};
        }
        uint8_t chunk[4096];
        size_t bytes_read;
        while ((bytes_read = fread(chunk, 1, sizeof(chunk), f)) > 0) {
            buffer.insert(buffer.end(), chunk, chunk + bytes_read);
        }
        fclose(f);
    }
    return buffer;
}

// Strictly parses a decimal unsigned 64-bit integer.
// Accepts only non-empty strings of ASCII digits that fit into uint64_t
// (no sign, no whitespace, no suffix, no overflow).
static bool parse_u64_strict(const char* s, uint64_t* out) {
    if (!s || *s == '\0') return false;
    for (const char* p = s; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
    }
    errno = 0;
    char* end = nullptr;
    unsigned long long value = strtoull(s, &end, 10);
    if (errno == ERANGE || end == s || (end && *end != '\0')) return false;
    *out = static_cast<uint64_t>(value);
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
    if (!parse_u64_strict(final_loc_str, &force_final_loc)) {
        std::cerr << "proxy: PROXY_AFL_FORCE_FINAL_LOC must be an integer (uint64), got: '" << final_loc_str << "'\n";
        return 1;
    }

    std::cout << "proxy: PROXY_AFL_FORCE_FINAL_LOC = " << force_final_loc << std::endl;

    // Eager log file creation
    if (!create_log_file(cfg.target.log.stdout_path) || !create_log_file(cfg.target.log.stderr_path)) {
        return 1;
    }

    // Initialize AFL persistent mode
    // TODO(claude): __AFL_INIT() is guarded by `#ifdef __AFL_HAVE_MANUAL_CONTROL`; if that macro is missing
    //   the forkserver is silently NOT initialised. Per spec it must be unconditional (afl_compat.hpp should
    //   #error instead). Also placement: spec 6.1 puts __AFL_INIT before spawning the target, which means the
    //   forkserver forks first and each forked child would spawn its own target - confirm this is intended
    //   (see question to the user).
    #ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
    #endif

    // Spawn target
    // TODO(claude): g_child_pid is assigned from the return value only after fork(); the signal handler can
    //   fire in between (see handler TODO). Block SIGINT/SIGTERM around spawn_target().
    g_child_pid = process::spawn_target(cfg, false, true);
    if (g_child_pid <= 0) {
        std::cerr << "proxy: failed to spawn target process.\n";
        return 1;
    }

    // Wait for port readiness
    if (!network::wait_for_port(g_child_pid, cfg)) {
        std::cerr << "proxy: target failed to bind to expected port within timeout.\n";
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

        int sock = network::connect_target(cfg.network);
        std::cout << std::chrono::system_clock::now() <<  " sock " << sock << "\n";
        if (sock < 0) {
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
        std::cout <<  std::chrono::system_clock::now() << " Successfully connected\n";

        // Final payload = configured prefix + fuzz data + configured suffix
        payload_buf.clear();
        payload_buf.insert(payload_buf.end(), cfg.payload.prefix.begin(), cfg.payload.prefix.end());
        payload_buf.insert(payload_buf.end(), buf, buf + len);
        payload_buf.insert(payload_buf.end(), cfg.payload.suffix.begin(), cfg.payload.suffix.end());

        network::send_all(sock, payload_buf.data(), payload_buf.size(), cfg.network.timeout_ms);
        network::wait_response(sock, cfg.network.timeout_ms);
        close(sock);

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
    //   adds it via set_env_var when is_map_size_pass) and, with env_preserve=true, leaks into the proxy's
    //   environ; if spawn fails (early return below) it is never unset.
    setenv("AFL_DUMP_MAP_SIZE", "1", 1);
    pid_t map_pid = process::spawn_target(cfg, true, false);
    if (map_pid <= 0) {
        std::cerr << "proxy: failed to spawn target for map size extraction.\n";
        return 1;
    }

    int status;
    // TODO(claude): BUG/spec: (1) blocking waitpid() with no timeout: a long-running target (nginx stays up
    //   forever) never exits by itself - with AFL_DUMP_MAP_SIZE the AFL runtime exits right after printing,
    //   but a target that is not instrumented will run (and hang the proxy) here. Spec says "Clean up the
    //   Pass 1 target process": it must be killed (SIGTERM->SIGKILL via timed_kill_pgid), not waited for.
    //   (2) g_child_pid is not set during Pass 1, so Ctrl+C during Pass 1 kills nothing. (3) The exit status
    //   is ignored.
    waitpid(map_pid, &status, 0);
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
    //   the child, fine, but an empty regular file is reported as "failed to read" (see read_input_file).
    //   Also spec 6.2 step 3 says the --input validation must be done BEFORE Pass 1; it is (input_path.empty()
    //   check), but the file itself is only opened after Pass 1 - validate readability up front to fail early.
    std::vector<uint8_t> payload = read_input_file(input_path);
    if (payload.empty() && input_path != "-") {
        std::cerr << "proxy: failed to read payload from " << input_path << "\n";
        return 1;
    }

    g_child_pid = process::spawn_target(cfg, false, false);
    if (g_child_pid <= 0) {
        std::cerr << "proxy: failed to spawn target for test iteration.\n";
        return 1;
    }

    if (!network::wait_for_port(g_child_pid, cfg)) {
        std::cerr << "proxy: target failed to bind to expected port.\n";
        timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
        return 1;
    }

    int sock = network::connect_target(cfg.network);
    if (sock < 0) {
        std::cerr << "proxy: failed to connect to target.\n";
        timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
        return 1;
    }

    // TODO(claude): return values of send_all()/wait_response() are ignored, so the "connection status" the
    //   spec asks to print in test mode (6.2 step 5) is never printed, and the response body is never shown
    //   (wait_response only prints "buf len = N"). The success message below is printed unconditionally.
    network::send_all(sock, payload.data(), payload.size(), cfg.network.timeout_ms);
    network::wait_response(sock, cfg.network.timeout_ms);
    close(sock);

    std::cout << "proxy: Pass 2 (Single Iteration) completed successfully.\n";
    
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
    g_force_kill_ms = cfg.cleanup.force_kill_ms;

    // Setup signal handlers
    setup_signal_handlers();

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
