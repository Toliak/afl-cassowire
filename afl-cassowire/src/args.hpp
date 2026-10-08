// src/args.hpp

#pragma once

#include <string>
#include <variant>

namespace args {

    /**
     * @brief Command line arguments after a successful parse.
     */
    struct ParsedArgs {
        std::string config_path;  ///< -c/--config value (default: "config.yaml")
        std::string log_level;    ///< --log-level value (default: "info")
        bool forward_output;      ///< --child-output flag (default: false)
        std::string input_path;   ///< --input value; accepted by the `test` subcommand only
        bool is_test_mode;        ///< true when the `test` subcommand was used
    };

    /**
     * @brief CLI parsing failure: unknown/invalid arguments or an invalid
     *        --log-level value.
     */
    struct ArgParseError {
        std::string message;  ///< Human-readable reason
        std::string usage;    ///< Rendered help/usage text for the whole CLI

        /// @brief Human-readable description (the message).
        std::string to_string() const;
    };

    /// @brief Result of parse_args(): ParsedArgs on success, ArgParseError otherwise.
    using ParseArgsResult = std::variant<ParsedArgs, ArgParseError>;

    /**
     * @brief Builds the CLI parser and parses argc/argv.
     *
     * Global options (-c/--config, --log-level, --child-output) live on the
     * parent parser and must precede the subcommand; --input lives on the
     * `test` subparser and is therefore only accepted as
     * `afl-cassowire test --input <file>`. -h/--help and -v/--version are
     * handled internally by argparse (print and exit).
     *
     * @param argc Argument count from main().
     * @param argv Argument vector from main().
     * @return ParseArgsResult The parsed arguments, or an ArgParseError
     *         (message + rendered usage text).
     */
    [[nodiscard]] ParseArgsResult parse_args(int argc, char* argv[]);

} // namespace args
