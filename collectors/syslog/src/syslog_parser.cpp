#include "aiguard/syslog/syslog_parser.h"
#include <spdlog/spdlog.h>
#include <charconv>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace aiguard {

std::optional<SyslogMessage> SyslogParser::parse(const uint8_t* data, size_t len) {
    return parse(std::string_view(reinterpret_cast<const char*>(data), len));
}

std::optional<SyslogMessage> SyslogParser::parse(std::string_view data) {
    if (data.empty()) return std::nullopt;

    // Try RFC 5424 first (starts with <PRI>VERSION)
    // Then fall back to RFC 3164 (starts with <PRI>TIMESTAMP)
    std::string_view view = data;

    // Parse priority
    int priority = parse_priority(view);
    if (priority < 0) return std::nullopt;

    // Check for RFC 5424 version digit
    if (!view.empty() && std::isdigit(static_cast<unsigned char>(view[0]))) {
        auto msg = parse_rfc5424(data);
        if (msg) {
            msg->priority = priority;
            msg->facility = facility_from_priority(priority);
            msg->severity = severity_from_priority(priority);
            return msg;
        }
    }

    // Fall back to RFC 3164
    auto msg = parse_rfc3164(data);
    if (msg) {
        msg->priority = priority;
        msg->facility = facility_from_priority(priority);
        msg->severity = severity_from_priority(priority);
        return msg;
    }

    return std::nullopt;
}

std::optional<SyslogMessage> SyslogParser::parse_rfc5424(std::string_view data) {
    // RFC 5424 format:
    // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID] MSG
    SyslogMessage msg;
    msg.raw_message = std::string(data);
    msg.version = 1;

    std::string_view view = data;

    // Skip priority
    int priority = parse_priority(view);
    if (priority < 0) return std::nullopt;

    // Version
    skip_whitespace(view);
    auto version_end = std::find_if(view.begin(), view.end(),
        [](char c) { return !std::isdigit(static_cast<unsigned char>(c)); });
    if (version_end == view.begin()) return std::nullopt;

    auto version_result = std::from_chars(view.data(), version_end, msg.version);
    if (version_result.ec != std::errc{}) return std::nullopt;
    view.remove_prefix(version_end - view.begin());

    // Timestamp
    skip_whitespace(view);
    msg.timestamp = parse_timestamp(view, true);

    // Hostname
    skip_whitespace(view);
    auto token = parse_token(view, ' ');
    msg.hostname = std::string(token);

    // App-name
    skip_whitespace(view);
    token = parse_token(view, ' ');
    msg.app_name = std::string(token);

    // ProcID
    skip_whitespace(view);
    token = parse_token(view, ' ');
    msg.proc_id = std::string(token);

    // MsgID
    skip_whitespace(view);
    token = parse_token(view, ' ');
    msg.msg_id = std::string(token);

    // Structured data
    skip_whitespace(view);
    if (!view.empty() && view[0] == '-') {
        // No structured data
        view.remove_prefix(1);
    } else if (!view.empty() && view[0] == '[') {
        // Parse structured data
        size_t end = view.find("] ");
        if (end != std::string_view::npos) {
            msg.structured_data = std::string(view.substr(0, end + 1));
            view.remove_prefix(end + 1);
        }
    }

    // Message
    skip_whitespace(view);
    msg.message = std::string(view);

    return msg;
}

std::optional<SyslogMessage> SyslogParser::parse_rfc3164(std::string_view data) {
    // RFC 3164 format:
    // <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
    // or <PRI>TIMESTAMP HOSTNAME MESSAGE
    SyslogMessage msg;
    msg.raw_message = std::string(data);
    msg.version = 0;

    std::string_view view = data;

    // Skip priority
    int priority = parse_priority(view);
    if (priority < 0) return std::nullopt;

    // Timestamp (BSD format: "Jan 15 10:30:00")
    skip_whitespace(view);
    msg.timestamp = parse_timestamp(view, false);

    // Hostname
    skip_whitespace(view);
    auto token = parse_token(view, ' ');
    msg.hostname = std::string(token);

    // Tag (app name) - everything up to first space or ':'
    skip_whitespace(view);
    auto tag_end = view.find_first_of(" \t:");
    if (tag_end != std::string_view::npos) {
        msg.app_name = std::string(view.substr(0, tag_end));
        view.remove_prefix(tag_end);

        // Skip optional ':' after tag
        if (!view.empty() && view[0] == ':') {
            view.remove_prefix(1);
        }
        // Optional PID in brackets
        if (!view.empty() && view[0] == '[') {
            auto pid_end = view.find(']');
            if (pid_end != std::string_view::npos) {
                msg.proc_id = std::string(view.substr(1, pid_end - 1));
                view.remove_prefix(pid_end + 1);
            }
        }
    }

    // Message
    skip_whitespace(view);
    msg.message = std::string(view);

    return msg;
}

int SyslogParser::parse_priority(std::string_view& data) {
    if (data.empty() || data[0] != '<') return -1;

    size_t end = data.find('>');
    if (end == std::string_view::npos || end > 4) return -1;

    int priority = 0;
    auto result = std::from_chars(data.data() + 1, data.data() + end, priority);
    if (result.ec != std::errc{}) return -1;

    data.remove_prefix(end + 1);
    return priority;
}

void SyslogParser::skip_whitespace(std::string_view& data) {
    while (!data.empty() && (data[0] == ' ' || data[0] == '\t')) {
        data.remove_prefix(1);
    }
}

std::string_view SyslogParser::parse_token(std::string_view& data, char delimiter) {
    auto end = data.find(delimiter);
    if (end == std::string_view::npos) {
        std::string_view token = data;
        data.remove_prefix(data.size());
        return token;
    }
    std::string_view token = data.substr(0, end);
    data.remove_prefix(end);
    return token;
}

std::string SyslogParser::parse_timestamp(std::string_view& data, bool is_rfc5424) {
    if (is_rfc5424) {
        // RFC 3339 timestamp: 2024-01-15T10:30:00.123Z
        // Find end of timestamp (space)
        auto end = data.find(' ');
        if (end == std::string_view::npos) {
            std::string ts{data};
            data.remove_prefix(data.size());
            return ts;
        }
        std::string ts{data.substr(0, end)};
        data.remove_prefix(end);
        return ts;
    } else {
        // BSD timestamp: "Jan 15 10:30:00"
        // Format: Mmm DD HH:MM:SS
        if (data.size() < 15) return "";

        std::string ts{data.substr(0, 15)};
        data.remove_prefix(15);
        return ts;
    }
}

std::string_view SyslogParser::facility_to_string(SyslogFacility f) {
    switch (f) {
        case SyslogFacility::Kernel:      return "kernel";
        case SyslogFacility::User:        return "user";
        case SyslogFacility::Mail:        return "mail";
        case SyslogFacility::Daemon:      return "daemon";
        case SyslogFacility::Auth:        return "auth";
        case SyslogFacility::Syslog:      return "syslog";
        case SyslogFacility::LinePrinter: return "line-printer";
        case SyslogFacility::News:        return "news";
        case SyslogFacility::UUCP:        return "uucp";
        case SyslogFacility::Cron:        return "cron";
        case SyslogFacility::AuthPriv:    return "auth-priv";
        case SyslogFacility::FTP:         return "ftp";
        case SyslogFacility::NTP:         return "ntp";
        case SyslogFacility::Audit:       return "audit";
        case SyslogFacility::Alert:       return "alert";
        case SyslogFacility::Clock:       return "clock";
        case SyslogFacility::Local0:      return "local0";
        case SyslogFacility::Local1:      return "local1";
        case SyslogFacility::Local2:      return "local2";
        case SyslogFacility::Local3:      return "local3";
        case SyslogFacility::Local4:      return "local4";
        case SyslogFacility::Local5:      return "local5";
        case SyslogFacility::Local6:      return "local6";
        case SyslogFacility::Local7:      return "local7";
        default:                          return "unknown";
    }
}

std::string_view SyslogParser::severity_to_string(SyslogSeverity s) {
    switch (s) {
        case SyslogSeverity::Emergency:     return "emergency";
        case SyslogSeverity::Alert:         return "alert";
        case SyslogSeverity::Critical:      return "critical";
        case SyslogSeverity::Error:         return "error";
        case SyslogSeverity::Warning:       return "warning";
        case SyslogSeverity::Notice:        return "notice";
        case SyslogSeverity::Informational: return "informational";
        case SyslogSeverity::Debug:         return "debug";
        default:                            return "unknown";
    }
}

Severity SyslogParser::map_severity(SyslogSeverity s) {
    switch (s) {
        case SyslogSeverity::Emergency:
        case SyslogSeverity::Alert:
        case SyslogSeverity::Critical:
            return Severity::Critical;
        case SyslogSeverity::Error:
            return Severity::High;
        case SyslogSeverity::Warning:
            return Severity::Medium;
        case SyslogSeverity::Notice:
        case SyslogSeverity::Informational:
            return Severity::Info;
        case SyslogSeverity::Debug:
            return Severity::Info;
        default:
            return Severity::Info;
    }
}

std::map<std::string, std::string> SyslogParser::parse_structured_data(std::string_view sd) {
    std::map<std::string, std::string> result;
    // Format: [id key="val" key2="val2"][id2 key="val"]
    while (!sd.empty() && sd[0] == '[') {
        auto end = sd.find(']');
        if (end == std::string_view::npos) break;

        auto element = sd.substr(1, end - 1);
        // Parse SD-ID and params
        auto space_pos = element.find(' ');
        if (space_pos != std::string_view::npos) {
            std::string sd_id{element.substr(0, space_pos)};
            std::string_view params = element.substr(space_pos + 1);

            // Parse key="value" pairs
            size_t pos = 0;
            while (pos < params.size()) {
                auto eq_pos = params.find('=', pos);
                if (eq_pos == std::string_view::npos) break;
                std::string key{params.substr(pos, eq_pos - pos)};

                auto quote_start = eq_pos + 1;
                if (quote_start >= params.size() || params[quote_start] != '"') break;
                auto quote_end = params.find('"', quote_start + 1);
                if (quote_end == std::string_view::npos) break;

                std::string value{params.substr(quote_start + 1, quote_end - quote_start - 1)};
                result[sd_id + "." + key] = value;
                pos = quote_end + 2;  // skip closing quote and space
            }
        }

        sd.remove_prefix(end + 1);
    }
    return result;
}

} // namespace aiguard
