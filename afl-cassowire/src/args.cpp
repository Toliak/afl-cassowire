// src/args.cpp

#include "args.hpp"

#include <utility>

#include <argparse/argparse.hpp>

#include "log.hpp"

namespace args {

    std::string ArgParseError::to_string() const {
        return message;
    }

    ParseArgsResult parse_args(int argc, char* argv[]) {
        argparse::ArgumentParser program("afl-cassowire", "1.0");

        program.add_argument("-c", "--config")
            .help("Path to the YAML configuration file")
            .default_value(std::string("config.yaml"));

        program.add_argument("--log-level")
            .help("Log level: trace, debug, info, warn, error, critical, off")
            .default_value(std::string("info"));

        program.add_argument("--child-output")
            .help("Forward the target's stdout/stderr to the proxy's descriptors instead of /dev/null")
            .default_value(false)
            .implicit_value(true);

        program.add_argument("--data-dir")
            .help("Directory for crash/abort termination dumps (.msg/.data); created if missing")
            .default_value(std::string("afl-cassowire-data"));

        argparse::ArgumentParser proxy_cmd("proxy");
        proxy_cmd.add_description("Run in persistent AFL++ proxy mode (default).");

        argparse::ArgumentParser test_cmd("test");
        test_cmd.add_description("Run in test/debug mode.");

        // --input belongs to the `test` subcommand only: it is accepted as
        // `afl-cassowire test --input <file>` and rejected everywhere else.
        // Exactly one of --input/--replay is enforced below (argparse only
        // validates a subparser's arguments when that subcommand is used).
        test_cmd.add_argument("--input")
            .help("Input file for test mode (use '-' for stdin); one exchange");

        // Replay a dumped iteration history against one target instance:
        // <dir> holds the .input files of a single termination dump. They are
        // replayed in their original order (.-N, ..., .-1, current), which is
        // what multi-iteration state-dependent crashes (e.g. the test-target's
        // cache lottery) need to reproduce.
        test_cmd.add_argument("--replay")
            .help("Directory with the .input files of one dump; replays them in order");
        test_cmd.add_argument("--retries")
            .help("Fresh-target replay attempts for --replay (default 1)")
            .default_value(1)
            .scan<'i', int>();

        program.add_subparser(proxy_cmd);
        program.add_subparser(test_cmd);

        try {
            program.parse_args(argc, argv);
        } catch (const std::runtime_error& err) {
            return ArgParseError{err.what(), program.help().str()};
        }

        ParsedArgs parsed;
        parsed.config_path = program.get<std::string>("--config");
        parsed.log_level = program.get<std::string>("--log-level");
        parsed.forward_output = program.get<bool>("--child-output");
        parsed.data_dir = program.get<std::string>("--data-dir");
        parsed.is_test_mode = program.is_subcommand_used("test");
        if (parsed.is_test_mode) {
            const bool has_input = test_cmd.is_used("--input");
            const bool has_replay = test_cmd.is_used("--replay");
            if (has_input == has_replay) {
                return ArgParseError{
                    "test mode needs exactly one of --input <file> or --replay <dir>",
                    program.help().str()};
            }
            if (has_input) {
                parsed.input_path = test_cmd.get<std::string>("--input");
                if (test_cmd.is_used("--retries")) {
                    return ArgParseError{
                        "--retries is only valid with --replay (--input is a single exchange)",
                        program.help().str()};
                }
            } else {
                parsed.replay_dir = test_cmd.get<std::string>("--replay");
            }
            parsed.replay_retries = test_cmd.get<int>("--retries");
            if (parsed.replay_retries < 1 || parsed.replay_retries > 100) {
                return ArgParseError{
                    "invalid --retries '" + std::to_string(parsed.replay_retries) +
                        "': expected an integer 1-100",
                    program.help().str()};
            }
        }

        // Validate the level name here so the error path can still render the
        // usage text; main() only converts the (already valid) name.
        if (!casslog::parse_level(parsed.log_level)) {
            return ArgParseError{
                "invalid --log-level '" + parsed.log_level +
                    "': expected trace, debug, info, warn, error, critical, or off",
                program.help().str()};
        }

        return parsed;
    }

} // namespace args
