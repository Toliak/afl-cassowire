// src/main.cpp

#include <iostream>
#include <string>
#include <string_view>
#include <vector>
#include <variant>
#include <optional>
#include <cstdlib>
#include <csignal>
#include <filesystem>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include <argparse/argparse.hpp>

#include "afl_compat.hpp"
#include "config.hpp"
#include "process.hpp"
#include "network.hpp"
#include "utils.hpp"

// Global state for signal handler
volatile sig_atomic_t g_child_pid = 0;
int g_force_kill_ms = 2000;

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
        if (res == pgid || (res == -1 && errno == ECHILD)) {
            return; // Process exited
        }
        
        clock_gettime(CLOCK_MONOTONIC, &now);
        long long elapsed_ms = (now.tv_sec - start.tv_sec) * 1000LL + 
                               (now.tv_nsec - start.tv_nsec) / 1000000LL;
                               
        if (elapsed_ms >= ms) {
            // Timeout reached, send SIGKILL
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

int run_proxy_mode(const Config& cfg) {
    // Check AFL SHM IDs
    if (!getenv("__AFL_SHM_ID")) {
        std::cerr << "proxy: __AFL_SHM_ID not found in environment. Run with afl-fuzz.\n";
        return 1;
    }
    if (cfg.afl.enable_cmplog && !getenv("__AFL_CMPLOG_SHM_ID")) {
        std::cerr << "proxy: enable_cmplog is true, but __AFL_CMPLOG_SHM_ID not found in environment.\n";
        return 1;
    }

    // Eager log file creation
    if (!create_log_file(cfg.target.log.stdout) || !create_log_file(cfg.target.log.stderr)) {
        return 1;
    }

    // Initialize AFL persistent mode
    __AFL_INIT();

    // Spawn target
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
    while (__AFL_LOOP(cfg.afl.loop_count)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        uint8_t* buf = __AFL_FUZZ_TESTCASE_BUF;

        int sock = network::connect_target(cfg.network);
        if (sock < 0) {
            // Connection failed, target might be dead.
            // Check health immediately.
            int status;
            if (waitpid(g_child_pid, &status, WNOHANG) == g_child_pid && WIFSIGNALED(status)) {
                raise(SIGSEGV); // Crash proxy so AFL respawns
            }
            continue;
        }

        network::send_all(sock, buf, len, cfg.network.timeout_ms);
        network::wait_response(sock, cfg.network.timeout_ms);
        close(sock);

        // Health check
        int status;
        pid_t res = waitpid(g_child_pid, &status, WNOHANG);
        if (res == g_child_pid && WIFSIGNALED(status)) {
            // Target crashed
            raise(SIGSEGV);
        }
    }

    // Clean exit of AFL loop
    timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
    return 0;
}

int run_test_mode(const Config& cfg, const std::string& input_path) {
    if (input_path.empty()) {
        std::cerr << "proxy: test mode requires --input <file> or '-'\n";
        return 1;
    }

    // --- Pass 1: Map Size Extraction ---
    setenv("AFL_DUMP_MAP_SIZE", "1", 1);
    pid_t map_pid = process::spawn_target(cfg, true, false);
    if (map_pid <= 0) {
        std::cerr << "proxy: failed to spawn target for map size extraction.\n";
        return 1;
    }

    int status;
    waitpid(map_pid, &status, 0);
    unsetenv("AFL_DUMP_MAP_SIZE");

    // Map size parsing is handled internally by process::spawn_target returning via stdout 
    // pipe which main reads, OR process::spawn_target handles it. 
    // Assuming process::spawn_target in test_mode handles the pipe and prints the map size to proxy's stdout.
    std::cout << "proxy: Pass 1 (Map Size) completed.\n";

    // --- Pass 2: Single Iteration ---
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

    network::send_all(sock, payload.data(), payload.size(), cfg.network.timeout_ms);
    network::wait_response(sock, cfg.network.timeout_ms);
    close(sock);

    std::cout << "proxy: Pass 2 (Single Iteration) completed successfully.\n";
    
    // Clean exit
    timed_kill_pgid(g_child_pid, cfg.cleanup.force_kill_ms);
    return 0;
}

int main(int argc, char* argv[]) {
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

    // Stale Process Cleanup
    process::cleanup_stale_processes(cfg.cleanup);

    if (is_test_mode) {
        return run_test_mode(cfg, input_path);
    } else {
        return run_proxy_mode(cfg);
    }
}