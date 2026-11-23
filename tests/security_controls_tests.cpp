#include "unlock_limit.h"
#include "vault_file.h"
#include <iostream>

int failures = 0;
void check(bool ok, const char* label)
{
    if (!ok)
    {
        ++failures;
        std::cerr << "Failed: " << label << '\n';
    }
}

void testVaultFormat()
{
    const std::string salt(32, 'a'), nonce(48, 'b'), cipher(32, 'c');
    const std::string good = formatVaultFile(salt, nonce.c_str(), cipher.c_str());
    VaultFile header;
    check(parseVaultFile(good, header) && header.salt == salt && header.encrypted == cipher,
        "version 1 round trip");
    const std::string reordered = "{\"nonce\":\"" + nonce + "\",\"encrypted_data\":\"" + cipher +
        "\",\"version\":1,\"salt\":\"" + salt + "\"}";
    check(parseVaultFile(reordered, header), "normal JSON whitespace and reordered fields");
    check(!parseVaultFile(good + "x", header), "extra data");
    check(!parseVaultFile(good + "\v", header), "invalid JSON whitespace");
    auto changed = good;
    changed.replace(changed.find("1,"), 1, "10");
    check(!parseVaultFile(changed, header), "wrong version");
    changed = good;
    changed.replace(changed.find("nonce"), 5, "salt");
    check(!parseVaultFile(changed, header), "duplicate field");
    changed = good;
    changed.replace(changed.find("nonce"), 5, "extra");
    check(!parseVaultFile(changed, header), "unknown field");
    check(!parseVaultFile("{}", header), "missing fields");
    check(!parseVaultFile(formatVaultFile(salt, nonce.c_str(), "gg"), header), "non-hex input");
    check(!parseVaultFile(formatVaultFile(salt, nonce.c_str(), "00"), header), "missing tag");
    check(!parseVaultFile(formatVaultFile(salt, nonce.c_str(), (cipher + "0").c_str()), header), "odd hex");
}

void testLimit()
{
    UnlockLimit limit;
    check(limit.load() && limit.attempts == 0, "first use");
    for (int i = 1; i <= UnlockLimit::maxAttempts; ++i)
    {
        check(limit.reserve(100), "reserve before checking");
        UnlockLimit reopened;
        check(reopened.load() && reopened.attempts == i, "restart keeps each attempt");
    }
    for (int i = 0; i < 15; ++i) check(!limit.reserve(101), "blocked request");
    check(limit.blocked(159) && !limit.blocked(160), "cooldown boundary");
    check(limit.reserve(160) && limit.attempts == 1 && !limit.blocked(160), "first attempt after expiry");
    check(limit.reset(), "successful unlock clears history");
    UnlockLimit reopened;
    check(reopened.load() && reopened.attempts == 0, "reset survives restart");
    check(replaceLocalFile("vault.attempts", "4 999\n") && !reopened.load(), "invalid cooldown");
    check(replaceLocalFile("vault.attempts", "0 0 trailing") && !reopened.load(), "trailing garbage");
    check(replaceLocalFile("vault.attempts", std::string(1000, '9')) && !reopened.load(), "oversized state");
    check(!writeNewFile("vault.attempts", "0 0"), "exclusive creation preserves existing files");
}

int main()
{
    if (sodium_init() < 0) return 1;
    const auto original = std::filesystem::current_path();
    unsigned char random[16];
    char name[sizeof random * 2 + 1];
    randombytes_buf(random, sizeof random);
    sodium_bin2hex(name, sizeof name, random, sizeof random);
    const auto temp = std::filesystem::temp_directory_path() / (std::string("vault-test-") + name);
    if (!std::filesystem::create_directory(temp)) return 1;
    std::filesystem::current_path(temp);
    testVaultFormat();
    testLimit();
    std::filesystem::current_path(original);
    std::filesystem::remove_all(temp);
    if (failures == 0) std::cout << "Security controls tests passed\n";
    return failures == 0 ? 0 : 1;
}
