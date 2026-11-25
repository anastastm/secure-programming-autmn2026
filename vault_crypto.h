#pragma once

#include "secret_cleanup.h"
#include "vault_file.h"
#include <string_view>
#include <vector>

// Version 3 vaults use the stronger "moderate" Argon2id cost (about 256 MiB of
// memory per guess). Versions 1 and 2 keep the cost they were created with,
// because their key cannot be re-derived without the master password.
constexpr int CURRENT_VAULT_VERSION = 3;

inline void keyDerivationCost(int version, unsigned long long& operations, std::size_t& memory)
{
    if (version >= 3)
    {
        operations = crypto_pwhash_OPSLIMIT_MODERATE;
        memory = crypto_pwhash_MEMLIMIT_MODERATE;
    }
    else
    {
        operations = crypto_pwhash_OPSLIMIT_INTERACTIVE;
        memory = crypto_pwhash_MEMLIMIT_INTERACTIVE;
    }
}

// Derives the vault key and always wipes the master password.
inline bool deriveVaultKey(std::string& masterPassword, const unsigned char salt[], int version, VaultKey& key)
{
    unsigned long long operations = 0;
    std::size_t memory = 0;
    keyDerivationCost(version, operations, memory);
    const int result = crypto_pwhash(
        key, sizeof key, masterPassword.c_str(),
        static_cast<unsigned long long>(masterPassword.size()), salt,
        operations, memory, crypto_pwhash_ALG_ARGON2ID13);
    clearString(masterPassword);
    if (result != 0) sodium_memzero(key, sizeof key);
    return result == 0;
}

inline std::string toHex(const unsigned char* data, std::size_t size)
{
    std::string hex(size * 2 + 1, '\0');
    sodium_bin2hex(hex.data(), hex.size(), data, size);
    hex.resize(size * 2);
    return hex;
}

// Encrypts and authenticates the record text with XChaCha20-Poly1305 and a
// fresh random nonce. The binding (owner account) is authenticated data: it is
// not stored secretly, but any other value makes decryption fail.
inline bool sealVaultData(std::string_view plain, const VaultKey& key, const std::string& binding,
    std::string& nonceHex, std::string& encryptedHex)
{
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof nonce);

    std::vector<unsigned char> encrypted(plain.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long encryptedLength = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
        encrypted.data(), &encryptedLength,
        reinterpret_cast<const unsigned char*>(plain.data()),
        static_cast<unsigned long long>(plain.size()),
        reinterpret_cast<const unsigned char*>(binding.data()), binding.size(),
        nullptr, nonce, key) != 0)
    {
        return false;
    }
    nonceHex = toHex(nonce, sizeof nonce);
    encryptedHex = toHex(encrypted.data(), static_cast<std::size_t>(encryptedLength));
    return true;
}

struct VaultBytes
{
    std::vector<unsigned char> salt = std::vector<unsigned char>(crypto_pwhash_SALTBYTES);
    std::vector<unsigned char> nonce = std::vector<unsigned char>(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    std::vector<unsigned char> encrypted;
};

// Converts the hexadecimal fields of an already parsed vault file to bytes.
inline bool decodeVaultFile(const VaultFile& header, VaultBytes& bytes)
{
    bytes.encrypted.assign(header.encrypted.size() / 2, 0);
    std::size_t saltLength = 0;
    std::size_t nonceLength = 0;
    std::size_t encryptedLength = 0;
    return sodium_hex2bin(bytes.salt.data(), bytes.salt.size(), header.salt.c_str(), header.salt.size(),
            nullptr, &saltLength, nullptr) == 0 &&
        sodium_hex2bin(bytes.nonce.data(), bytes.nonce.size(), header.nonce.c_str(), header.nonce.size(),
            nullptr, &nonceLength, nullptr) == 0 &&
        sodium_hex2bin(bytes.encrypted.data(), bytes.encrypted.size(),
            header.encrypted.c_str(), header.encrypted.size(), nullptr, &encryptedLength, nullptr) == 0 &&
        saltLength == bytes.salt.size() && nonceLength == bytes.nonce.size() &&
        encryptedLength == bytes.encrypted.size() &&
        bytes.encrypted.size() >= crypto_aead_xchacha20poly1305_ietf_ABYTES;
}

// Verifies the authentication tag before any plaintext is accepted. The caller
// guards plain with StringWiper; on failure it is wiped and left empty.
inline bool openVaultData(const VaultBytes& bytes, const VaultKey& key, const std::string& binding,
    std::string& plain)
{
    clearString(plain);
    plain.assign(bytes.encrypted.size(), '\0');
    unsigned long long plainLength = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char*>(plain.data()), &plainLength, nullptr,
        bytes.encrypted.data(), static_cast<unsigned long long>(bytes.encrypted.size()),
        reinterpret_cast<const unsigned char*>(binding.data()), binding.size(),
        bytes.nonce.data(), key) != 0)
    {
        clearString(plain);
        return false;
    }
    sodium_memzero(plain.data() + static_cast<std::size_t>(plainLength), plain.size() - static_cast<std::size_t>(plainLength));
    plain.resize(static_cast<std::size_t>(plainLength));
    return true;
}
