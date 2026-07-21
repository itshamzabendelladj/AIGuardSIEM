#include "aiguard/crypto/crypto_utils.h"
#include <stdexcept>

namespace aiguard {

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string CryptoUtils::base64_encode(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve((len + 2) / 3 * 4);

    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = data[i] << 16;
        if (i + 1 < len) n |= data[i + 1] << 8;
        if (i + 2 < len) n |= data[i + 2];

        result += b64_table[(n >> 18) & 0x3F];
        result += b64_table[(n >> 12) & 0x3F];
        result += (i + 1 < len) ? b64_table[(n >> 6) & 0x3F] : '=';
        result += (i + 2 < len) ? b64_table[n & 0x3F] : '=';
    }

    return result;
}

std::string CryptoUtils::base64_encode(std::string_view data) {
    return base64_encode(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::vector<uint8_t> CryptoUtils::base64_decode(std::string_view encoded) {
    static int8_t decode_table[256];
    static bool initialized = false;
    if (!initialized) {
        std::fill(decode_table, decode_table + 256, -1);
        for (int i = 0; i < 64; ++i) {
            decode_table[static_cast<uint8_t>(b64_table[i])] = static_cast<int8_t>(i);
        }
        initialized = true;
    }

    std::vector<uint8_t> result;
    result.reserve(encoded.size() * 3 / 4);

    uint32_t accum = 0;
    int bits = 0;

    for (char c : encoded) {
        if (c == '=') break;
        int8_t val = decode_table[static_cast<uint8_t>(c)];
        if (val < 0) continue;

        accum = (accum << 6) | val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            result.push_back(static_cast<uint8_t>((accum >> bits) & 0xFF));
        }
    }

    return result;
}

std::string CryptoUtils::hex_encode(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result += hex[(data[i] >> 4) & 0x0F];
        result += hex[data[i] & 0x0F];
    }
    return result;
}

std::string CryptoUtils::hex_encode(std::string_view data) {
    return hex_encode(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::vector<uint8_t> CryptoUtils::hex_decode(std::string_view hex) {
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);

    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = hex_val(hex[i]);
        int lo = hex_val(hex[i + 1]);
        if (hi < 0 || lo < 0) break;
        result.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return result;
}

std::string CryptoUtils::base64url_encode(const uint8_t* data, size_t len) {
    std::string result = base64_encode(data, len);
    for (auto& c : result) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    // Remove padding
    while (!result.empty() && result.back() == '=') result.pop_back();
    return result;
}

std::vector<uint8_t> CryptoUtils::base64url_decode(std::string_view encoded) {
    std::string s(encoded);
    for (auto& c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    // Add padding
    while (s.size() % 4 != 0) s += '=';
    return base64_decode(s);
}

} // namespace aiguard
