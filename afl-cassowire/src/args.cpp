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
        argparse::ArgumentParser program("afl_proxy", "1.0");

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

        argparse::ArgumentParser proxy_cmd("proxy");
        proxy_cmd.add_description("Run in persistent AFL++ proxy mode (default).");

        argparse::ArgumentParser test_cmd("test");
        test_cmd.add_description("Run in test/debug mode.");

        // --input belongs to the `test` subcommand only: it is accepted as
        // `afl_proxy test --input <file>` and rejected everywhere else.
        test_cmd.add_argument("--input")
            .help("Input file for test mode (use '-' for stdin)");

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
        parsed.is_test_mode = program.is_subcommand_used("test");
        if (parsed.is_test_mode && test_cmd.is_used("--input")) {
            parsed.input_path = test_cmd.get<std::string>("--input");
        }

        // Validate the level name here so the error path can still render the
        // usage text; main() only converts the (already valid) name.
        if (!log::parse_level(parsed.log_level)) {
            return ArgParseError{
                "invalid --log-level '" + parsed.log_level +
                    "': expected trace, debug, info, warn, error, critical, or off",
                program.help().str()};
        }

        return parsed;
    }

} // namespace args
