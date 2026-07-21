#include "aiguard/crypto/tls_accelerator.h"
#include <spdlog/spdlog.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <cstring>
#include <chrono>

#ifdef __x86_64__
#include <cpuid.h>
#endif

namespace aiguard {

TLSAccelerator::TLSAccelerator() {
    // Initialize OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}

TLSAccelerator::~TLSAccelerator() {
    EVP_cleanup();
    ERR_free_strings();
}

bool TLSAccelerator::initialize(const TLSConfig& config) {
    config_ = config;

    if (config_.enable_aes_ni && !has_aes_ni()) {
        spdlog::warn("AES-NI not available, using software fallback");
    }

    initialized_.store(true);
    spdlog::info("TLS accelerator initialized (AES-NI: {}, AVX2: {}, AVX-512: {})",
                 has_aes_ni(), has_avx2(), has_avx512());
    return true;
}

bool TLSAccelerator::has_aes_ni() {
#ifdef __x86_64__
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & bit_AESNI) != 0;
    }
    return false;
#else
    return false;
#endif
}

bool TLSAccelerator::has_avx2() {
#ifdef __x86_64__
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return (ebx & bit_AVX2) != 0;
    }
    return false;
#else
    return false;
#endif
}

bool TLSAccelerator::has_avx512() {
#ifdef __x86_64__
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return (ebx & bit_AVX512F) != 0;
    }
    return false;
#else
    return false;
#endif
}

EncryptedData TLSAccelerator::encrypt_aes_gcm(const std::vector<uint8_t>& plaintext,
                                               const std::vector<uint8_t>& key,
                                               const std::vector<uint8_t>& aad) {
    EncryptedData result;

    if (key.size() != 32) {
        spdlog::error("AES-256-GCM requires 256-bit (32-byte) key");
        return result;
    }

    // Generate IV
    result.iv = generate_iv();

    // Prepare ciphertext buffer
    result.ciphertext.resize(plaintext.size());
    result.tag.resize(16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        spdlog::error("Failed to create EVP cipher context");
        return result;
    }

    bool success = true;

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        success = false;
        goto cleanup;
    }

    // Set IV length (12 bytes for GCM)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
        success = false;
        goto cleanup;
    }

    // Set key and IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), result.iv.data()) != 1) {
        success = false;
        goto cleanup;
    }

    // Add AAD if provided
    if (!aad.empty()) {
        int aad_len;
        if (EVP_EncryptUpdate(ctx, nullptr, &aad_len, aad.data(), aad.size()) != 1) {
            success = false;
            goto cleanup;
        }
    }

    // Encrypt plaintext
    int out_len;
    if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &out_len,
                          plaintext.data(), plaintext.size()) != 1) {
        success = false;
        goto cleanup;
    }

    int final_len;
    if (EVP_EncryptFinal_ex(ctx, result.ciphertext.data() + out_len, &final_len) != 1) {
        success = false;
        goto cleanup;
    }

    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, result.tag.data()) != 1) {
        success = false;
        goto cleanup;
    }

    result.success = true;

cleanup:
    EVP_CIPHER_CTX_free(ctx);

    if (!success) {
        spdlog::error("AES-256-GCM encryption failed");
        result.success = false;
    }

    return result;
}

std::vector<uint8_t> TLSAccelerator::decrypt_aes_gcm(const EncryptedData& encrypted,
                                                      const std::vector<uint8_t>& key,
                                                      const std::vector<uint8_t>& aad) {
    if (!encrypted.success || key.size() != 32) {
        return {};
    }

    std::vector<uint8_t> plaintext(encrypted.ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    bool success = true;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        success = false;
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
        success = false;
        goto cleanup;
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), encrypted.iv.data()) != 1) {
        success = false;
        goto cleanup;
    }

    if (!aad.empty()) {
        int aad_len;
        if (EVP_DecryptUpdate(ctx, nullptr, &aad_len, aad.data(), aad.size()) != 1) {
            success = false;
            goto cleanup;
        }
    }

    int out_len;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                          encrypted.ciphertext.data(), encrypted.ciphertext.size()) != 1) {
        success = false;
        goto cleanup;
    }

    // Set tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                             const_cast<uint8_t*>(encrypted.tag.data())) != 1) {
        success = false;
        goto cleanup;
    }

    int final_len;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &final_len) != 1) {
        success = false;
        goto cleanup;
    }

    plaintext.resize(out_len + final_len);

cleanup:
    EVP_CIPHER_CTX_free(ctx);

    if (!success) {
        spdlog::error("AES-256-GCM decryption failed");
        return {};
    }

    return plaintext;
}

std::vector<uint8_t> TLSAccelerator::sha256(const uint8_t* data, size_t len) {
    std::vector<uint8_t> hash(32);
    SHA256(data, len, hash.data());
    return hash;
}

std::vector<uint8_t> TLSAccelerator::sha256(std::string_view data) {
    return sha256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::vector<uint8_t> TLSAccelerator::sha3_256(const uint8_t* data, size_t len) {
    std::vector<uint8_t> hash(32);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};

    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int hash_len;
    EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
    EVP_MD_CTX_free(ctx);

    return hash;
}

std::vector<uint8_t> TLSAccelerator::sha3_256(std::string_view data) {
    return sha3_256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::vector<uint8_t> TLSAccelerator::hmac_sha256(const uint8_t* data, size_t len,
                                                  const uint8_t* key, size_t key_len) {
    std::vector<uint8_t> mac(32);
    unsigned int mac_len;
    HMAC(EVP_sha256(), key, static_cast<int>(key_len), data, len, mac.data(), &mac_len);
    mac.resize(mac_len);
    return mac;
}

std::vector<uint8_t> TLSAccelerator::random_bytes(size_t count) {
    std::vector<uint8_t> bytes(count);
    RAND_bytes(bytes.data(), static_cast<int>(count));
    return bytes;
}

std::vector<uint8_t> TLSAccelerator::generate_aes_key() {
    return random_bytes(32);  // 256-bit key
}

std::vector<uint8_t> TLSAccelerator::generate_iv() {
    return random_bytes(12);  // 96-bit IV for GCM
}

std::vector<uint8_t> TLSAccelerator::derive_key(const std::string& password,
                                                 const std::vector<uint8_t>& salt,
                                                 int iterations, size_t key_len) {
    std::vector<uint8_t> key(key_len);
    PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                      salt.data(), static_cast<int>(salt.size()),
                      iterations, EVP_sha256(),
                      static_cast<int>(key_len), key.data());
    return key;
}

bool TLSAccelerator::constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; ++i) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

bool TLSAccelerator::aes_gcm_encrypt_ni(const uint8_t* plaintext, size_t plen,
                                         const uint8_t* key, size_t key_len,
                                         const uint8_t* iv, size_t iv_len,
                                         const uint8_t* aad, size_t aad_len,
                                         uint8_t* ciphertext, uint8_t* tag) {
    // OpenSSL uses AES-NI automatically when available
    // This method is a wrapper that could use direct intrinsics for even better performance
    (void)plaintext; (void)plen; (void)key; (void)key_len;
    (void)iv; (void)iv_len; (void)aad; (void)aad_len;
    (void)ciphertext; (void)tag;
    return false;  // Use OpenSSL path instead
}

bool TLSAccelerator::aes_gcm_decrypt_ni(const uint8_t* ciphertext, size_t clen,
                                         const uint8_t* key, size_t key_len,
                                         const uint8_t* iv, size_t iv_len,
                                         const uint8_t* aad, size_t aad_len,
                                         const uint8_t* tag, uint8_t* plaintext) {
    (void)ciphertext; (void)clen; (void)key; (void)key_len;
    (void)iv; (void)iv_len; (void)aad; (void)aad_len;
    (void)tag; (void)plaintext;
    return false;
}

// KeyRotationManager
KeyRotationManager::KeyRotationManager() {
    current_key_ = TLSAccelerator::generate_aes_key();
    previous_key_ = current_key_;
    last_rotation_ = std::chrono::steady_clock::now();
}

void KeyRotationManager::set_rotation_interval(int seconds) {
    rotation_interval_seconds_ = seconds;
}

std::vector<uint8_t> KeyRotationManager::get_current_key() const {
    return current_key_;
}

void KeyRotationManager::rotate() {
    previous_key_ = current_key_;
    current_key_ = TLSAccelerator::generate_aes_key();
    last_rotation_ = std::chrono::steady_clock::now();
    spdlog::info("Encryption key rotated");
}

bool KeyRotationManager::needs_rotation() const {
    auto elapsed = std::chrono::steady_clock::now() - last_rotation_;
    return std::chrono::duration_cast<std::chrono::seconds>(elapsed).count() >= rotation_interval_seconds_;
}

} // namespace aiguard
