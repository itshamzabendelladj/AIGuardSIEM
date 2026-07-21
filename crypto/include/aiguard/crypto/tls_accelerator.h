#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <cstdint>
#include <atomic>

namespace aiguard {

/// AES-256-GCM encrypted data
struct EncryptedData {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;       // 16-byte GCM tag
    std::vector<uint8_t> iv;        // 12-byte nonce
    bool success{false};
};

/// TLS accelerator configuration
struct TLSConfig {
    std::string cert_file;
    std::string key_file;
    std::string ca_file;
    std::string cipher_suites{"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"};
    int min_version{0x0304};  // TLS 1.3
    int max_version{0x0304};
    bool enable_aes_ni{true};
    bool enable_avx2{true};
    bool enable_session_resumption{true};
    size_t session_cache_size{10000};
};

/// Hardware-accelerated cryptography module
///
/// Features:
/// - AES-256-GCM with AES-NI hardware acceleration
/// - SHA-256/SHA-3 hashing
/// - TLS 1.3 termination
/// - Key rotation
/// - Zero-copy encryption where possible
class TLSAccelerator {
public:
    TLSAccelerator();
    ~TLSAccelerator();

    /// Initialize with configuration
    bool initialize(const TLSConfig& config);

    /// AES-256-GCM encryption with hardware acceleration
    EncryptedData encrypt_aes_gcm(const std::vector<uint8_t>& plaintext,
                                   const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& aad = {});

    /// AES-256-GCM decryption
    std::vector<uint8_t> decrypt_aes_gcm(const EncryptedData& encrypted,
                                          const std::vector<uint8_t>& key,
                                          const std::vector<uint8_t>& aad = {});

    /// SHA-256 hash
    static std::vector<uint8_t> sha256(const uint8_t* data, size_t len);
    static std::vector<uint8_t> sha256(std::string_view data);

    /// SHA-3 (SHA3-256) hash
    static std::vector<uint8_t> sha3_256(const uint8_t* data, size_t len);
    static std::vector<uint8_t> sha3_256(std::string_view data);

    /// HMAC-SHA256
    static std::vector<uint8_t> hmac_sha256(const uint8_t* data, size_t len,
                                             const uint8_t* key, size_t key_len);

    /// Generate random bytes
    static std::vector<uint8_t> random_bytes(size_t count);

    /// Generate AES-256 key
    static std::vector<uint8_t> generate_aes_key();

    /// Generate IV (12 bytes for GCM)
    static std::vector<uint8_t> generate_iv();

    /// Derive key using PBKDF2
    static std::vector<uint8_t> derive_key(const std::string& password,
                                            const std::vector<uint8_t>& salt,
                                            int iterations = 100000,
                                            size_t key_len = 32);

    /// Constant-time comparison
    static bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len);

    /// Check if AES-NI is available
    [[nodiscard]] static bool has_aes_ni();

    /// Check if AVX2 is available
    [[nodiscard]] static bool has_avx2();

    /// Check if AVX-512 is available
    [[nodiscard]] static bool has_avx512();

private:
    TLSConfig config_;
    std::atomic<bool> initialized_{false};

    /// AES-NI accelerated GCM encrypt
    bool aes_gcm_encrypt_ni(const uint8_t* plaintext, size_t plen,
                             const uint8_t* key, size_t key_len,
                             const uint8_t* iv, size_t iv_len,
                             const uint8_t* aad, size_t aad_len,
                             uint8_t* ciphertext, uint8_t* tag);

    /// AES-NI accelerated GCM decrypt
    bool aes_gcm_decrypt_ni(const uint8_t* ciphertext, size_t clen,
                             const uint8_t* key, size_t key_len,
                             const uint8_t* iv, size_t iv_len,
                             const uint8_t* aad, size_t aad_len,
                             const uint8_t* tag,
                             uint8_t* plaintext);
};

/// Key rotation manager
class KeyRotationManager {
public:
    KeyRotationManager();
    ~KeyRotationManager() = default;

    /// Set rotation interval (seconds)
    void set_rotation_interval(int seconds);

    /// Get current key
    std::vector<uint8_t> get_current_key() const;

    /// Rotate key
    void rotate();

    /// Check if rotation is needed
    [[nodiscard]] bool needs_rotation() const;

private:
    int rotation_interval_seconds_{3600};  // 1 hour default
    std::vector<uint8_t> current_key_;
    std::vector<uint8_t> previous_key_;
    std::chrono::steady_clock::time_point last_rotation_;
    mutable std::mutex mutex_;
};

} // namespace aiguard
