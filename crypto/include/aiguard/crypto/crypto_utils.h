#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

namespace aiguard {

/// Utility functions for encoding and hashing
class CryptoUtils {
public:
    /// Base64 encode
    static std::string base64_encode(const uint8_t* data, size_t len);
    static std::string base64_encode(std::string_view data);

    /// Base64 decode
    static std::vector<uint8_t> base64_decode(std::string_view encoded);

    /// Hex encode
    static std::string hex_encode(const uint8_t* data, size_t len);
    static std::string hex_encode(std::string_view data);

    /// Hex decode
    static std::vector<uint8_t> hex_decode(std::string_view hex);

    /// URL-safe base64 encode
    static std::string base64url_encode(const uint8_t* data, size_t len);

    /// URL-safe base64 decode
    static std::vector<uint8_t> base64url_decode(std::string_view encoded);
};

} // namespace aiguard
