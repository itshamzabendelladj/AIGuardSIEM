#pragma once

#include "aiguard/syslog/syslog_collector.h"
#include <string_view>
#include <optional>
#include <array>

namespace aiguard {

/// High-performance syslog message parser
///
/// Supports both RFC 5424 and RFC 3164 syslog formats.
/// Uses zero-copy parsing where possible.
class SyslogParser {
public:
    /// Parse a syslog message
    /// @param data Raw message data
    /// @param len Message length
    /// @return Parsed syslog message or nullopt on parse error
    static std::optional<SyslogMessage> parse(const uint8_t* data, size_t len);

    /// Parse a syslog message (string view overload)
    static std::optional<SyslogMessage> parse(std::string_view data);

    /// Parse RFC 5424 format
    static std::optional<SyslogMessage> parse_rfc5424(std::string_view data);

    /// Parse RFC 3164 format
    static std::optional<SyslogMessage> parse_rfc3164(std::string_view data);

    /// Convert syslog facility to string
    static std::string_view facility_to_string(SyslogFacility f);

    /// Convert syslog severity to string
    static std::string_view severity_to_string(SyslogSeverity s);

    /// Map syslog severity to ECS severity
    static Severity map_severity(SyslogSeverity s);

    /// Parse structured data (RFC 5424)
    static std::map<std::string, std::string> parse_structured_data(std::string_view sd);

private:
    /// Parse priority field (<NN>)
    static int parse_priority(std::string_view& data);

    /// Skip whitespace
    static void skip_whitespace(std::string_view& data);

    /// Parse token up to delimiter
    static std::string_view parse_token(std::string_view& data, char delimiter);

    /// Parse timestamp (RFC 3339 for 5424, BSD for 3164)
    static std::string parse_timestamp(std::string_view& data, bool is_rfc5424);

    /// Facility from priority
    static SyslogFacility facility_from_priority(int priority) {
        return static_cast<SyslogFacility>(priority / 8);
    }

    /// Severity from priority
    static SyslogSeverity severity_from_priority(int priority) {
        return static_cast<SyslogSeverity>(priority % 8);
    }
};

} // namespace aiguard
