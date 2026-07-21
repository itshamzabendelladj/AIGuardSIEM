#pragma once

#include "aiguard/common/event.h"
#include <string>
#include <string_view>
#include <unordered_map>
#include <functional>
#include <vector>
#include <memory>

namespace aiguard {

/// ECS (Elastic Common Schema) field definitions
///
/// Maps source-specific fields to ECS canonical field names
/// for normalization across all data sources.
struct ECSFieldMapping {
    std::string ecs_field;
    std::string source_field;
    std::function<FieldValue(std::string_view)> transform;
};

/// ECS schema normalizer - converts raw events to ECS format
class ECSNormalizer {
public:
    ECSNormalizer();
    ~ECSNormalizer() = default;

    /// Register a source-specific field mapping
    void register_mapping(const std::string& source_type,
                          const std::string& source_field,
                          const std::string& ecs_field,
                          std::function<FieldValue(std::string_view)> transform = nullptr);

    /// Normalize a raw event to ECS format
    void normalize(Event& event, const std::string& source_type) const;

    /// Get ECS field mappings for a source type
    [[nodiscard]] std::vector<ECSFieldMapping> get_mappings(const std::string& source_type) const;

    /// Check if a field is a valid ECS field
    [[nodiscard]] bool is_ecs_field(std::string_view field) const;

    /// Get all registered source types
    [[nodiscard]] std::vector<std::string> get_source_types() const;

private:
    void initialize_default_mappings();

    // source_type -> list of field mappings
    std::unordered_map<std::string, std::vector<ECSFieldMapping>> mappings_;

    // Set of valid ECS field names
    std::unordered_map<std::string, bool> ecs_fields_;
};

/// Common ECS field names
namespace ecs_fields {
    // Event fields
    constexpr auto EVENT_ID          = "event.id";
    constexpr auto EVENT_KIND        = "event.kind";
    constexpr auto EVENT_CATEGORY    = "event.category";
    constexpr auto EVENT_TYPE        = "event.type";
    constexpr auto EVENT_ACTION      = "event.action";
    constexpr auto EVENT_OUTCOME     = "event.outcome";
    constexpr auto EVENT_SEVERITY    = "event.severity";
    constexpr auto EVENT_CREATED     = "event.created";
    constexpr auto EVENT_MODULE      = "event.module";
    constexpr auto EVENT_DATASET     = "event.dataset";

    // Source fields
    constexpr auto SOURCE_IP         = "source.ip";
    constexpr auto SOURCE_PORT       = "source.port";
    constexpr auto SOURCE_HOST_NAME  = "source.host.name";

    // Destination fields
    constexpr auto DEST_IP           = "destination.ip";
    constexpr auto DEST_PORT         = "destination.port";
    constexpr auto DEST_HOST_NAME    = "destination.host.name";

    // Network fields
    constexpr auto NETWORK_TRANSPORT = "network.transport";
    constexpr auto NETWORK_PROTOCOL  = "network.protocol";
    constexpr auto NETWORK_BYTES     = "network.bytes";
    constexpr auto NETWORK_PACKETS   = "network.packets";

    // User fields
    constexpr auto USER_ID           = "user.id";
    constexpr auto USER_NAME         = "user.name";

    // Process fields
    constexpr auto PROCESS_PID       = "process.pid";
    constexpr auto PROCESS_NAME      = "process.name";
    constexpr auto PROCESS_CMD_LINE  = "process.command_line";

    // Host fields
    constexpr auto HOST_ID           = "host.id";
    constexpr auto HOST_NAME         = "host.name";
    constexpr auto HOST_OS_NAME      = "host.os.name";

    // Timestamp
    constexpr auto TIMESTAMP         = "@timestamp";
}

} // namespace aiguard
