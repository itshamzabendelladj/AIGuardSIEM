#include "aiguard/winlog/winlog_parser.h"
#include <spdlog/spdlog.h>
#include <algorithm>
#include <regex>

namespace aiguard {

std::string WinLogParser::extract_field(std::string_view xml, std::string_view tag) {
    std::string open_tag = "<" + std::string(tag) + ">";
    std::string close_tag = "</" + std::string(tag) + ">";

    auto start = xml.find(open_tag);
    if (start == std::string_view::npos) return "";
    start += open_tag.size();

    auto end = xml.find(close_tag, start);
    if (end == std::string_view::npos) return "";

    return std::string(xml.substr(start, end - start));
}

std::string WinLogParser::extract_attribute(std::string_view xml,
                                             std::string_view tag,
                                             std::string_view attr) {
    // Find the tag
    auto tag_pos = xml.find("<" + std::string(tag));
    if (tag_pos == std::string_view::npos) return "";

    // Find the attribute within the tag
    auto attr_pos = xml.find(attr, tag_pos);
    if (attr_pos == std::string_view::npos) return "";

    // Find the equals sign
    auto eq_pos = xml.find('=', attr_pos);
    if (eq_pos == std::string_view::npos) return "";

    // Find the opening quote
    auto quote_start = xml.find('"', eq_pos);
    if (quote_start == std::string_view::npos) return "";

    // Find the closing quote
    auto quote_end = xml.find('"', quote_start + 1);
    if (quote_end == std::string_view::npos) return "";

    return std::string(xml.substr(quote_start + 1, quote_end - quote_start - 1));
}

std::optional<WinLogRecord> WinLogParser::parse_xml(std::string_view xml) {
    if (xml.empty()) return std::nullopt;

    WinLogRecord record;
    record.raw_xml = std::string(xml);

    // Extract EventID
    std::string event_id_str = extract_field(xml, "EventID");
    if (!event_id_str.empty()) {
        try {
            record.event_id = static_cast<uint32_t>(std::stoul(event_id_str));
        } catch (...) {
            return std::nullopt;
        }
    }

    // Extract Channel
    record.channel = extract_field(xml, "Channel");

    // Extract Computer
    record.computer_name = extract_field(xml, "Computer");

    // Extract Provider Name
    record.provider_name = extract_attribute(xml, "Provider", "Name");
    record.provider_guid = extract_attribute(xml, "Provider", "Guid");

    // Extract TimeCreated
    std::string time_str = extract_attribute(xml, "TimeCreated", "SystemTime");
    if (!time_str.empty()) {
        record.time_created = Event::parse_iso8601(time_str);
    }

    // Extract Level
    std::string level_str = extract_field(xml, "Level");
    if (!level_str.empty()) {
        try {
            record.level_value = static_cast<uint16_t>(std::stoul(level_str));
        } catch (...) {}
    }

    // Map level
    switch (record.level_value) {
        case 0: record.level = "LogAlways"; break;
        case 1: record.level = "Critical"; break;
        case 2: record.level = "Error"; break;
        case 3: record.level = "Warning"; break;
        case 4: record.level = "Information"; break;
        case 5: record.level = "Verbose"; break;
        default: record.level = "Information"; break;
    }

    // Extract Task
    record.task_name = extract_field(xml, "Task");

    // Extract Opcode
    record.opcode_name = extract_field(xml, "Opcode");

    // Extract RecordID
    std::string record_id_str = extract_field(xml, "RecordID");
    if (!record_id_str.empty()) {
        try {
            record.record_id = std::stoull(record_id_str);
        } catch (...) {}
    }

    // Extract Execution ProcessID and ThreadID
    record.process_id = 0;
    std::string pid_str = extract_attribute(xml, "Execution", "ProcessID");
    if (!pid_str.empty()) {
        try {
            record.process_id = std::stoull(pid_str);
        } catch (...) {}
    }

    std::string tid_str = extract_attribute(xml, "Execution", "ThreadID");
    if (!tid_str.empty()) {
        try {
            record.thread_id = std::stoull(tid_str);
        } catch (...) {}
    }

    // Extract Security UserID
    record.user_sid = extract_attribute(xml, "Security", "UserID");

    // Extract message from rendering
    // In production, this would use EvtFormatMessage
    record.message = extract_field(xml, "RenderingDescription");

    // Extract EventData
    auto ed_start = xml.find("<EventData>");
    if (ed_start != std::string_view::npos) {
        auto ed_end = xml.find("</EventData>", ed_start);
        if (ed_end != std::string_view::npos) {
            std::string_view ed = xml.substr(ed_start, ed_end - ed_start);
            // Parse individual Data elements
            size_t pos = 0;
            std::regex data_regex(R"(<Data Name="([^"]+)">([^<]*)</Data>)");
            std::string ed_str(ed);
            auto begin = std::sregex_iterator(ed_str.begin(), ed_str.end(), data_regex);
            auto end_iter = std::sregex_iterator();
            for (auto it = begin; it != end_iter; ++it) {
                record.event_data[(*it)[1].str()] = (*it)[2].str();
            }
        }
    }

    return record;
}

Severity WinLogParser::map_level(uint16_t level) {
    switch (level) {
        case 1: return Severity::Critical;  // Critical
        case 2: return Severity::High;      // Error
        case 3: return Severity::Medium;    // Warning
        case 4: return Severity::Info;      // Information
        case 5: return Severity::Info;      // Verbose
        default: return Severity::Info;
    }
}

std::string WinLogParser::get_category(const std::string& channel, uint32_t event_id) {
    // Security channel categories
    if (channel == "Security") {
        if (event_id >= 4624 && event_id <= 4634) return "authentication";
        if (event_id >= 4648 && event_id <= 4672) return "authorization";
        if (event_id >= 4688 && event_id <= 4690) return "process";
        if (event_id >= 4700 && event_id <= 4799) return "policy";
        if (event_id >= 4800 && event_id <= 4899) return "account";
        if (event_id >= 4900 && event_id <= 4999) return "system";
        return "security";
    }
    // Sysmon categories
    if (channel.find("Sysmon") != std::string::npos) {
        switch (event_id) {
            case 1:  return "process_creation";
            case 2:  return "file_creation_time";
            case 3:  return "network_connection";
            case 4:  return "sysmon_service_state";
            case 5:  return "process_terminated";
            case 6:  return "driver_loaded";
            case 7:  return "image_loaded";
            case 8:  return "create_remote_thread";
            case 9:  return "raw_access_read";
            case 10: return "process_access";
            case 11: return "file_create";
            case 12: return "registry_event";
            case 13: return "registry_event";
            case 14: return "registry_event";
            case 15: return "file_create_stream_hash";
            case 16: return "sysmon_config_change";
            case 17: return "pipe_created";
            case 18: return "pipe_created";
            case 19: return "wmi_filter";
            case 20: return "wmi_consumer";
            case 21: return "wmi_binding";
            case 22: return "dns_query";
            case 23: return "file_delete";
            case 24: return "clipboard_change";
            case 25: return "process_tampering";
            case 26: return "file_delete_detected";
            default: return "sysmon";
        }
    }
    if (channel == "System") return "system";
    if (channel == "Application") return "application";
    return "log";
}

} // namespace aiguard
