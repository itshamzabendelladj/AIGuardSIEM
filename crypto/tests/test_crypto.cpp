#include <gtest/gtest.h>
#include "aiguard/crypto/tls_accelerator.h"
#include "aiguard/crypto/crypto_utils.h"
#include <string>

using namespace aiguard;

TEST(CryptoTest, AES256GCMEncryptDecrypt) {
    TLSAccelerator crypto;

    auto key = TLSAccelerator::generate_aes_key();
    ASSERT_EQ(key.size(), 32);

    std::string plaintext = "Hello, AIGuardSIEM! This is a test message.";
    std::vector<uint8_t> pt(plaintext.begin(), plaintext.end());

    auto encrypted = crypto.encrypt_aes_gcm(pt, key);
    EXPECT_TRUE(encrypted.success);
    EXPECT_FALSE(encrypted.ciphertext.empty());
    EXPECT_EQ(encrypted.tag.size(), 16);
    EXPECT_EQ(encrypted.iv.size(), 12);

    auto decrypted = crypto.decrypt_aes_gcm(encrypted, key);
    EXPECT_EQ(decrypted.size(), pt.size());
    EXPECT_EQ(std::string(decrypted.begin(), decrypted.end()), plaintext);
}

TEST(CryptoTest, SHA256) {
    auto hash = TLSAccelerator::sha256("test");
    EXPECT_EQ(hash.size(), 32);

    // Known SHA-256 of "test"
    std::string expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    std::string actual = CryptoUtils::hex_encode(hash);
    EXPECT_EQ(actual, expected);
}

TEST(CryptoTest, SHA3_256) {
    auto hash = TLSAccelerator::sha3_256("test");
    EXPECT_EQ(hash.size(), 32);
}

TEST(CryptoTest, HMACSHA256) {
    std::string data = "message";
    std::string key = "secret_key";
    auto mac = TLSAccelerator::hmac_sha256(
        reinterpret_cast<const uint8_t*>(data.data()), data.size(),
        reinterpret_cast<const uint8_t*>(key.data()), key.size());
    EXPECT_EQ(mac.size(), 32);
}

TEST(CryptoTest, RandomBytes) {
    auto bytes1 = TLSAccelerator::random_bytes(32);
    auto bytes2 = TLSAccelerator::random_bytes(32);
    EXPECT_EQ(bytes1.size(), 32);
    EXPECT_EQ(bytes2.size(), 32);
    EXPECT_NE(bytes1, bytes2);
}

TEST(CryptoTest, Base64EncodeDecode) {
    std::string data = "Hello World!";
    std::string encoded = CryptoUtils::base64_encode(data);
    auto decoded = CryptoUtils::base64_decode(encoded);
    EXPECT_EQ(std::string(decoded.begin(), decoded.end()), data);
}

TEST(CryptoTest, HexEncodeDecode) {
    std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    std::string hex = CryptoUtils::hex_encode(data.data(), data.size());
    EXPECT_EQ(hex, "48656c6c6f");

    auto decoded = CryptoUtils::hex_decode(hex);
    EXPECT_EQ(decoded, data);
}

TEST(CryptoTest, Base64URLEncodeDecode) {
    std::vector<uint8_t> data = {0xfb, 0xff, 0xbf};
    std::string encoded = CryptoUtils::base64url_encode(data.data(), data.size());
    auto decoded = CryptoUtils::base64url_decode(encoded);
    EXPECT_EQ(decoded, data);
}

TEST(CryptoTest, ConstantTimeCompare) {
    std::string a = "password123";
    std::string b = "password123";
    std::string c = "password456";

    EXPECT_TRUE(TLSAccelerator::constant_time_compare(
        reinterpret_cast<const uint8_t*>(a.data()),
        reinterpret_cast<const uint8_t*>(b.data()), a.size()));
    EXPECT_FALSE(TLSAccelerator::constant_time_compare(
        reinterpret_cast<const uint8_t*>(a.data()),
        reinterpret_cast<const uint8_t*>(c.data()), a.size()));
}

TEST(CryptoTest, KeyDerivation) {
    auto key = TLSAccelerator::derive_key("password", {0x01, 0x02, 0x03}, 1000, 32);
    EXPECT_EQ(key.size(), 32);
}

TEST(CryptoTest, KeyRotationManager) {
    KeyRotationManager manager;
    auto key1 = manager.get_current_key();
    EXPECT_FALSE(key1.empty());

    manager.rotate();
    auto key2 = manager.get_current_key();
    EXPECT_NE(key1, key2);
}
