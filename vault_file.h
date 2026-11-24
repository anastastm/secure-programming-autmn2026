#pragma once

#include "local_files.h"
#include <sstream>

constexpr std::size_t MAX_VAULT_FILE_SIZE = 16U * 1024U * 1024U;

struct VaultFile
{
    int version = 0;
    std::string salt;
    std::string nonce;
    std::string encrypted;
};

inline void skipVaultWhitespace(std::istream& in)
{
    int c = in.peek();
    while (c == ' ' || c == '\t' || c == '\r' || c == '\n')
    {
        in.get();
        c = in.peek();
    }
}

inline bool takeVaultChar(std::istream& in, char expected)
{
    skipVaultWhitespace(in);
    return in.get() == expected;
}

// Both supported versions use plain ASCII field names and hexadecimal string values.
inline bool readVaultString(std::istream& in, std::string& value)
{
    if (!takeVaultChar(in, '"')) return false;
    value.clear();
    return static_cast<bool>(std::getline(in, value, '"')) && !in.eof();
}

inline bool isHex(const std::string& value)
{
    return value.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
}

inline bool parseVaultFile(const std::string& data, VaultFile& header)
{
    std::istringstream in(data);
    VaultFile parsed;
    if (!takeVaultChar(in, '{')) return false;
    for (int field = 0; field < 4; ++field)
    {
        if (field > 0 && !takeVaultChar(in, ',')) return false;
        std::string name;
        if (!readVaultString(in, name) || !takeVaultChar(in, ':')) return false;
        if (name == "version")
        {
            if (parsed.version != 0) return false;
            skipVaultWhitespace(in);
            int digit = in.get();
            if (digit != '1' && digit != '2') return false;
            parsed.version = digit - '0';
        }
        else
        {
            std::string* value = nullptr;
            if (name == "salt") value = &parsed.salt;
            else if (name == "nonce") value = &parsed.nonce;
            else if (name == "encrypted_data") value = &parsed.encrypted;
            if (!value || !value->empty() || !readVaultString(in, *value) ||
                value->empty() || !isHex(*value)) return false;
        }
    }
    if (!takeVaultChar(in, '}')) return false;
    skipVaultWhitespace(in);
    if (!in.eof() || parsed.version == 0 || parsed.salt.size() != crypto_pwhash_SALTBYTES * 2 ||
        parsed.nonce.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES * 2 ||
        parsed.encrypted.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES * 2 ||
        parsed.encrypted.size() % 2 != 0) return false;
    header = std::move(parsed);
    return true;
}

inline std::string formatVaultFile(const std::string& salt, const char* nonce, const char* encrypted, int version = 1)
{
    return "{\n  \"version\": " + std::to_string(version) + ",\n  \"salt\": \"" + salt +
        "\",\n  \"nonce\": \"" + nonce + "\",\n  \"encrypted_data\": \"" + encrypted + "\"\n}\n";
}
