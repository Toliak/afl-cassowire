// src/utils.hpp

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>
#include <unistd.h>
#include <variant>
#include <vector>

namespace utils {

    /**
     * @brief Move-only RAII wrapper around a file descriptor.
     *
     * Takes ownership of a raw descriptor and closes it on destruction
     * (unless it is negative or was moved away). Copying is disabled to
     * prevent double-close; ownership can only be transferred by moving.
     */
    class [[nodiscard]] FdGuard {
    public:
        /// @brief Creates an empty guard that owns no descriptor.
        FdGuard() noexcept : fd(-1) {}

        /// @brief Takes ownership of an existing descriptor (may be negative).
        explicit FdGuard(int f) noexcept : fd(f) {}

        FdGuard(const FdGuard&) = delete;
        FdGuard& operator=(const FdGuard&) = delete;

        /// @brief Transfers ownership from @p other, leaving it empty.
        FdGuard(FdGuard&& other) noexcept : fd(other.fd) { other.fd = -1; }

        /// @brief Transfers ownership from @p other, closing any owned fd first.
        FdGuard& operator=(FdGuard&& other) noexcept {
            if (this != &other) {
                reset();
                fd = other.fd;
                other.fd = -1;
            }
            return *this;
        }

        /// @brief Closes the owned descriptor, if any.
        ~FdGuard() {
            if (fd >= 0) ::close(fd);
        }

        /// @brief Returns the owned descriptor without releasing ownership.
        [[nodiscard]] int get() const noexcept { return fd; }

        /// @brief Closes the owned descriptor (if any) and leaves the guard empty.
        void reset() noexcept {
            if (fd >= 0) {
                ::close(fd);
                fd = -1;
            }
        }

    private:
        int fd;
    };

    /**
     * @brief Gets the current monotonic time in milliseconds.
     *
     * @return uint64_t Current time in ms.
     */
    uint64_t get_time_ms();

    /**
     * @brief Sleeps for a specified number of milliseconds.
     * 
     * @param ms The duration to sleep in milliseconds.
     */
    void sleep_ms(int ms);

    /**
     * @brief Crashes the proxy intentionally (e.g., to trigger AFL respawn).
     * Raises SIGSEGV.
     */
    [[noreturn]] void crash_proxy();

    /**
     * @brief Detail carried by ParseError: characters left unconsumed after a
     *        successful numeric conversion (e.g. "12abc").
     */
    enum class CustomParseError { TrailingCharacters };

    /**
     * @brief Parse failure detail: either a std::errc reported by
     *        std::from_chars (invalid input, out of range) or a trailing
     *        characters failure.
     */
    using ParseError = std::variant<std::errc, CustomParseError>;

    /**
     * @brief Result of parse_u64_strict(): the parsed value on success, a
     *        ParseError otherwise.
     */
    using ParseResult = std::variant<std::uint64_t, ParseError>;

    /// @brief Result of parse_u8_strict(): the parsed value or a ParseError.
    using U8ParseResult = std::variant<std::uint8_t, ParseError>;

    /// @brief Result of parse_u16_strict(): the parsed value or a ParseError.
    using U16ParseResult = std::variant<std::uint16_t, ParseError>;

    /// @brief Result of parse_u32_strict(): the parsed value or a ParseError.
    using U32ParseResult = std::variant<std::uint32_t, ParseError>;

    /**
     * @brief Strictly parses an unsigned decimal integer of the given width.
     *
     * Accepts only non-empty strings of ASCII digits in the given base
     * (2-36, default 10) that fit into the target type (no sign, no
     * whitespace, no "0x" prefix, no overflow). The entire string must be
     * consumed.
     *
     * @param s The string to parse.
     * @param base Numeric base accepted by std::from_chars (2-36).
     * @return ParseResult The parsed value, or a ParseError describing the
     *         failure.
     */
    [[nodiscard]] ParseResult parse_u64_strict(std::string_view s, int base = 10);

    /**
     * @brief Strictly parses an unsigned 8-bit integer (see parse_u64_strict).
     *
     * @param s The string to parse.
     * @param base Numeric base accepted by std::from_chars (2-36).
     * @return U8ParseResult The parsed value, or a ParseError.
     */
    [[nodiscard]] U8ParseResult parse_u8_strict(std::string_view s, int base = 10);

    /**
     * @brief Strictly parses an unsigned 16-bit integer (see parse_u64_strict).
     *
     * @param s The string to parse.
     * @param base Numeric base accepted by std::from_chars (2-36).
     * @return U16ParseResult The parsed value, or a ParseError.
     */
    [[nodiscard]] U16ParseResult parse_u16_strict(std::string_view s, int base = 10);

    /**
     * @brief Strictly parses an unsigned 32-bit integer (see parse_u64_strict).
     *
     * @param s The string to parse.
     * @param base Numeric base accepted by std::from_chars (2-36).
     * @return U32ParseResult The parsed value, or a ParseError.
     */
    [[nodiscard]] U32ParseResult parse_u32_strict(std::string_view s, int base = 10);

    /**
     * @brief Result of read_input_file(): the file/stdin contents on success,
     *        or an std::error_code describing the failure.
     */
    using ReadResult = std::variant<std::vector<uint8_t>, std::error_code>;

    /**
     * @brief Reads an input file into a buffer ("-" reads from stdin).
     *
     * Distinguishes read errors (returned as std::error_code) from a
     * successful but empty read (empty vector). EINTR on read() is retried.
     *
     * @param path File path, or "-" for stdin.
     * @param max_bytes Maximum number of bytes to read; exceeding it yields
     *        std::errc::file_too_large.
     * @return ReadResult The contents, or an std::error_code.
     */
    [[nodiscard]] ReadResult read_input_file(std::string_view path,
                                             size_t max_bytes = SIZE_MAX);

} // namespace utils