
# Development Specification: AFL++ Proxy Binary

## 1. Overview
The goal is to develop a robust, configurable C++ proxy binary that acts as a persistent harness for `afl-fuzz`. It manages the lifecycle of a slow-initializing target application (like NGINX), passes through AFL++ shared memory IDs, handles network communication, and monitors the target's health.

*   **Target Architectures:** Linux `x86_64`.
*   **Language Standard:** C++20 (excluding C++20 modules).
*   **Build System:** Meson.


## 2. Dependencies & Build System
*   **Meson**: Primary build system.
*   **yaml-cpp**: For parsing the YAML configuration file.
*   **p-ranav/argparse**: Header-only library for Command Line Interface (CLI) parsing. (This is to be added via a Meson wrap by the user).
*   **Standard Linux APIs**: `ptrace`, `seccomp`, `/proc` filesystem, POSIX signals, sockets.


The proxy must be compiled with AFL++ toolchains (e.g., `afl-clang-fast` or `afl-clang-lto`). To enforce this, use `#ifdef` / `#ifndef` checks in `afl_compat.hpp`.

`afl_compat.hpp`: It must fail at compile-time if built with standard compilers using, e.g. block like that
```c
#ifndef __AFL_LOOP
#error "AFL++ persistent mode macros not found. Compile with afl-clang-fast/afl-clang-lto."
#endif
```

## 3. Command Line Interface (CLI)
The binary will use `p-ranav/argparse` to handle arguments and subcommands/modes.

*   **Global Arguments:**
    *   `-c, --config <path>`: Path to the YAML configuration file (default: `config.yaml`).
    * `--input <file>`: mandatory argument when running in `test` mode, accepts a path to the file that will be passed as the input data to the target. A dash `-` can be specified to use stdin instead of the file content.
*   **Modes:**
    1.  `proxy` (Default): Runs the persistent AFL++ loop (`__AFL_LOOP`). Expects `__AFL_SHM_ID` (and optionally `__AFL_CMPLOG_SHM_ID`) in the environment.
    2.  `test`: Runs the target outside of AFL++ for debugging.
        *   Sets `AFL_DUMP_MAP_SIZE=1` in the environment to force the instrumented target to print its shared memory map size to `stdout`.
        *   (pass 1) Executes the target, captures and prints this integer map size.
        *   Accepts a single input via `--input <file>` or, if file is `-`, `stdin`.
        *   (pass 2) Executes exactly one network iteration (send/recv) and exits cleanly.

## 4. Configuration System
Configuration is handled via a YAML file. The loader returns a `std::variant<Config, ConfigError>` to enforce strict, pattern-matched error handling without exceptions.

### 4.1 Error Wrapper (`ConfigError`)

A dedicated class for structured validation errors with fields like those below:
```cpp
struct ConfigError {
    std::string path;     // e.g., "network.port"
    std::string message;  // Human readable error
    std::string expected; // e.g., "integer 1-65535"
    std::string actual;   // e.g., "string 'eighty'"
    std::string to_string() const;
};
```

### 4.2 YAML Schema & Validation
The loader strictly validates types, ranges, and required fields.
*   **`target`**:
    *   `binary` (string, required): Path to executable.
    *   `args` (list of strings): Arguments passed to `execv`, including `argv[0]` (because it can differ from the `binary`).
    * **`log`**:
        * `stdout`, `stderr` (string, optional) -- (only for `proxy` mode). The paths to the files where the target process's stdout and stderr will be redirected. If the log file cannot be created, fail.
*   **`network`**:
    *   `host` (string, default: `"127.0.0.1"`).
    *   `port` (integer, required, range: 1-65535).
    *   `timeout_ms` (integer, > 0, optional, default=200) -- sending packet network timeout.
    *   `initial_ms` (integer, >0, optional, default=200) -- port detection timeout.
*   **`afl`**:
    *   `loop_count` (integer, default: 50000).
    *   `enable_cmplog` (boolean, default: false). *Validation: If true, `__AFL_CMPLOG_SHM_ID` MUST exist in env, else runtime exit.*
*   **`port_detection`**:
    *   `primary` (string, enum: `"procfs"`, `"ptrace"`, `"seccomp"`).
        *   `"seccomp"`: Uses `PTRACE_TRACEME` + `PTRACE_O_TRACESECCOMP` with a BPF filter that triggers only on the `bind()` syscall. Significantly lower overhead than full `ptrace` syscall tracing.
*   **`cleanup`**:
    *   `force_kill_ms` (integer, > 0, optional, default: 2000) -- how many milliseconds to wait after sending `SIGTERM` before sending `SIGKILL`.
    *   `kill_pattern` (object or string, optional):
        * **Scalar String**: Treated as a comm match (e.g., `kill_pattern: "nginx"`).
        * **Comm Object**: Explicitly matches against `/proc/<pid>/comm` (e.g., `kill_pattern: { type: comm, value: "nginx" }`). All fields are required.
        * **Regexp Object**: Matches using standard C++ regex (e.g., `kill_pattern: { type: regexp, value: "^nginx.*worker", target: "comm" }`). All fields are required.
            * If target is `"comm"`: Match against `/proc/<pid>/comm`.
            *   `"argv0"`: Match against the first argument (the executable path) in `/proc/<pid>/cmdline`.
            *   `"argv"`: Match against the entire command line. All NUL (`\0`) characters are treated as spaces.

## 5. Core Subsystems

### 5.1 Process Management (`src/process.*`)

*   **Stale Process Cleanup**: If a process matches `kill_pattern`, it sends `SIGTERM`, waits `cleanup.force_kill_ms` milliseconds, and sends `SIGKILL`.
*   **Spawning**:
    *   Uses `fork()`.
    *   Sets up environment: `__AFL_SHM_ID`, `__AFL_CMPLOG_SHM_ID` (if enabled).
    *   Redirects standard streams (see Rules below).
    *   **Ptrace/Seccomp Integration**: The child process *must* only call `ptrace(PTRACE_TRACEME, 0, nullptr, nullptr)` followed by `raise(SIGSTOP)` immediately after `fork()` and before `execve()` if the `port_detection.primary` is `ptrace` or `seccomp`. 
        *   If `port_detection.primary == "ptrace"`, the parent catches the stop, sets `PTRACE_O_TRACESYSGOOD`, and resumes.
        *   If `port_detection.primary == "seccomp"`, the child additionally installs a seccomp BPF filter before `execve()` that returns `SECCOMP_RET_TRACE` for the `bind()` syscall. The parent catches the initial stop and sets `PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD`.
        * If `port_detection.primary == "procfs"`, the child must skip all ptrace/seccomp setup.
*   **Signal Handling**:
    *   The proxy catches `SIGINT`/`SIGTERM` (from Ctrl+C or AFL).
    *   Sends `SIGTERM` to the target process group.
    *   Waits up to `cleanup.force_kill_ms` milliseconds. If the target is still alive, sends `SIGKILL`.
*   **Health Checks**: Uses `waitpid(WNOHANG)` and `WIFSIGNALED` to detect if the target crashed (e.g., `SIGSEGV`, `SIGABRT`). If detected, triggers the proxy crash.

Standard Streams Redirection Rules:

* proxy mode: Redirect child stdin to `/dev/null`. Redirect child stdout and stderr to the configured `target.log.stdout` and `target.log.stderr`. The logfiles must be created before the process management.
* test mode (Pass 1 - Map Size): Create a pipe for child stdout to capture the map size. Redirect child stderr to `/dev/null` (to prevent log pollution from interfering with the integer parsing).
* test mode (Pass 2 - Single Iteration): Do not redirect child stdout or stderr; they must inherit the proxy's file descriptors so the user can see the target's console output directly. Redirect child stdin to `/dev/null`.

### 5.2 Port Detection (`src/network.*`)

The target process can call `bind` multiple times. For example, the target may bind multiple sockets.
We need that to verify that the captured `bind()` is the correct one. 

Configurable via `port_detection.primary`.
1.  **Procfs**: No ptrace and no syscall tracing. Parses `/proc/net/tcp` and `/proc/net/tcp6` looking for the target port in `TCP_LISTEN` (0x0A) state. (This is a global view, without direct PIDs, but it is enough for tha `procfs` method)
2.  **Ptrace**:
    *   Parent attaches to the stopped child.
    *   Traces syscalls (`PTRACE_SYSCALL`).
    *   Intercepts `bind()`.
    *   Reads the `sockaddr` struct from the child's memory via `process_vm_readv()` (replacing slower `PTRACE_PEEKDATA` loops) by first getting the pointer via `PTRACE_GETREGS`.
    *   Extracts the port. If it matches the target port, calls `PTRACE_DETACH` and marks the target as "ready".

3.  **Seccomp-Assisted Ptrace**:
    *   When `bind()` is invoked, the kernel delivers `PTRACE_EVENT_SECCOMP`. Because of `PTRACE_O_TRACESECCOMP`, the parent receives a `waitpid()` event with `status >> 8 == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))`.
    *   Parent reads registers (`PTRACE_GETREGS`) to extract the `sockaddr` pointer, reads child memory via `process_vm_readv()`, checks the port, and if matched, calls `PTRACE_DETACH`.
    *   If the port doesn’t match, the parent resumes with `PTRACE_CONT`.
    *   The BPF filter must be arch-aware.
    *   **Support check**: do not check the support, because if it is not supported, it will fail in runtime anyway.

*Note*: On `x86_64` `__NR_bind` is 49.

If the bound port is 0, log a warning to `stderr` (e.g., `"proxy: target requested ephemeral port (0), skipping..."`).

### 5.3 Network Client (`src/network.*`)
*   Non-blocking TCP connect with configurable timeout.
*   `send_all()`: Ensures the entire fuzz payload is sent.
*   `wait_response()`: Reads from the socket until EOF or timeout.

## 6. Execution Modes Implementation

### 6.1 `proxy` Mode
1.  Load and validate config (`std::visit`).
2.  Run stale process cleanup (`kill_pattern`).
3.  Check `__AFL_SHM_ID` (and `__AFL_CMPLOG_SHM_ID` if enabled).
4.  Initialize AFL persistent mode (`__AFL_INIT`).
5.  Spawn target, wait for port (see 5.2).
6.  Enter `__AFL_LOOP(cfg.afl.loop_count)`:
    *   Connect to target.
    *   Send fuzz buffer.
    *   Receive response.
    *   Check target health (`WIFSIGNALED`). If crashed, trigger proxy crash (`raise(SIGSEGV)`) so AFL registers the finding.

### 6.2 `test` Mode
1. Load config.
2. Run cleanup.
3.  **Validation:** Ensure `--input <file>` is provided.
4.  **Pass 1 (Map Size Extraction):** 
    *   Spawn the target with `AFL_DUMP_MAP_SIZE=1` in the environment.
    *   Capture `stdout` via pipe. Parse the stream strictly for a single integer (it must appear on the first line, without any extraneous/non-numeric characters). If extra text is present or no integer is found, return an error (assuming the target lacks proper AFL++ instrumentation).
    *   Print the extracted map size to the user's console.
    *   Clean up the Pass 1 target process.
5.  **Pass 2 (Single Iteration):**
    *   Spawn the target *without* the `AFL_DUMP_MAP_SIZE` variable.
    *   Wait for port readiness (using the configured `port_detection.primary` method).
    *   Read the payload from the file specified in `--input` (or from `stdin` if `-` was passed).
    *   Connect to the target, send the payload, and receive the response.
    *   Print the response and connection status to the user's console.
    *   Clean up the target and exit with status `0`.


## 7. File Structure
```text
├── meson.build
├── subprojects/
│   ├── yaml-cpp.wrap
│   └── argparse.wrap (to be added)
└── src/
    ├── main.cpp          // CLI parsing, mode routing, signal handlers, AFL loop
    ├── afl_compat.hpp    // Compile-time guard for AFL++ persistent-mode
    ├── config.hpp        // Config structs, ConfigError class
    ├── config.cpp        // YAML parsing, strict validation, std::variant return
    ├── process.hpp       // Process lifecycle, cleanup, health checks
    ├── process.cpp       // fork/exec, ptrace TRACEME setup, /proc iteration
    ├── network.hpp       // TCP client, port detection interfaces
    ├── network.cpp       // Procfs parsing, ptrace syscall tracing (x64)
    ├── utils.hpp         // Time, sleep, crash helpers
    └── utils.cpp
```

About `afl_compat.hpp`:
Compile-time guard for AFL++ persistent-mode support. If `__AFL_LOOP` is not defined, compilation must fail with a clear error.
