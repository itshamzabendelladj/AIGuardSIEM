#pragma once

#include "aiguard/winlog/winlog_collector.h"
#include <optional>
#include <string_view>

namespace aiguard {

/// Windows Event Log XML parser
class WinLogParser {
public:
    /// Parse Windows Event XML to WinLogRecord
    static std::optional<WinLogRecord> parse_xml(std::string_view xml);

    /// Extract field from XML
    static std::string extract_field(std::string_view xml, std::string_view tag);

    /// Extract attribute from XML tag
    static std::string extract_attribute(std::string_view xml,
                                          std::string_view tag,
                                          std::string_view attr);

    /// Map Windows event level to ECS severity
    static Severity map_level(uint16_t level);

    /// Get event category from channel and event ID
    static std::string get_category(const std::string& channel, uint32_t event_id);
};

} // namespace aiguard
