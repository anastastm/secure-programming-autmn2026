#include "unlock_limit.h"
#include "vault_file.h"
#include "audit_log.h"
#include <fstream>
#include <sstream>
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
    check(parseVaultFile(formatVaultFile(salt, nonce.c_str(), cipher.c_str(), 2), header) &&
        header.version == 2, "account-bound version 2 envelope");
    check(parseVaultFile(formatVaultFile(salt, nonce.c_str(), cipher.c_str(), 3), header) &&
        header.version == 3, "version 3 envelope with stronger key derivation");
    check(!parseVaultFile(formatVaultFile(salt, nonce.c_str(), cipher.c_str(), 4), header), "unknown version 4");
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
    check(limit.load() && limit.attempts == 0 && limit.missing, "first use reports a missing counter");
    for (int i = 1; i <= UnlockLimit::maxAttempts; ++i)
    {
        check(limit.reserve(100), "reserve before checking");
        UnlockLimit reopened;
        check(reopened.load() && reopened.attempts == i && !reopened.missing, "restart keeps each attempt");
    }
    for (int i = 0; i < 15; ++i) check(!limit.reserve(101), "blocked request");
    check(limit.blocked(159) && !limit.blocked(160), "first cooldown is 60 seconds");
    check(limit.reserve(160) && limit.attempts == 1 && !limit.blocked(160) && limit.lockouts == 1,
        "first attempt after expiry keeps the lockout count");

    std::int64_t now = 160;
    for (int i = 2; i <= UnlockLimit::maxAttempts; ++i) check(limit.reserve(now), "second round");
    check(limit.lockouts == 2 && limit.blockedUntil == now + 120, "second lockout waits 2 minutes");
    UnlockLimit reopened;
    check(reopened.load() && reopened.lockouts == 2 && reopened.blocked(now + 119), "escalation survives restart");
    check(UnlockLimit::cooldownFor(3) == 240 && UnlockLimit::cooldownFor(7) == 3600 &&
        UnlockLimit::cooldownFor(50) == 3600, "cooldown doubling and cap");

    check(limit.reset(), "successful unlock clears history");
    check(reopened.load() && reopened.attempts == 0 && reopened.lockouts == 0, "reset survives restart");

    std::filesystem::remove("vault.attempts");
    check(reopened.load() && reopened.missing, "deleted counter is reported");
    check(reopened.lockBecauseMissing(500) && reopened.blocked(559) && !reopened.blocked(560),
        "deleted counter starts a lockout");
    UnlockLimit afterDelete;
    check(afterDelete.load() && !afterDelete.missing && afterDelete.blocked(500), "lockout is persisted");

    check(replaceLocalFile("vault.attempts", "5 200\n") && reopened.load() && reopened.lockouts == 1,
        "previous two-field format is still read");
    check(replaceLocalFile("vault.attempts", "4 999\n") && !reopened.load(), "invalid cooldown");
    check(replaceLocalFile("vault.attempts", "5 999 0\n") && !reopened.load(), "cooldown without a lockout");
    check(replaceLocalFile("vault.attempts", "0 0 -1\n") && !reopened.load(), "negative lockouts");
    check(replaceLocalFile("vault.attempts", "0 0 trailing") && !reopened.load(), "trailing garbage");
    check(replaceLocalFile("vault.attempts", "0 0 0 0") && !reopened.load(), "extra field");
    check(replaceLocalFile("vault.attempts", std::string(1000, '9')) && !reopened.load(), "oversized state");
    check(!writeNewFile("vault.attempts", "0 0"), "exclusive creation preserves existing files");
}

std::string readAll(const char* path)
{
    std::ifstream in(path, std::ios::binary);
    std::ostringstream out;
    out << in.rdbuf();
    return out.str();
}

void testAuditChain()
{
    std::string last;
    check(verifyAuditChain("", last) && last == firstAuditHash(), "empty log is a valid chain");
    logEvent("session_start", "success");
    logEvent("vault_unlock", "failure");
    logEvent("vault_unlock", "failure");
    const std::string log = readAll("vault.audit.log");
    check(verifyAuditChain(log, last) && last == auditState().lastHash, "written log verifies");
    check(log.find("\"prev\":\"" + firstAuditHash() + "\"") != std::string::npos, "first line links to zeros");

    const auto second = log.find('\n') + 1;
    const auto third = log.find('\n', second) + 1;
    check(!verifyAuditChain(log.substr(0, second) + log.substr(third), last), "deleted line is detected");
    std::string edited = log;
    edited.replace(edited.find("failure"), 7, "success");
    check(!verifyAuditChain(edited, last), "edited result is detected");
    check(!verifyAuditChain(log.substr(0, log.size() - 1), last), "partial last line is detected");
    check(!verifyAuditChain("{\"event\":\"legacy\"}\n", last), "line without a link is detected");

    check(replaceLocalFile("vault.audit.log", edited), "write tampered log");
    auditState() = {};
    logEvent("session_start", "success");
    const std::string fresh = readAll("vault.audit.log");
    bool kept = false;
    for (const auto& item : std::filesystem::directory_iterator("."))
    {
        const auto name = item.path().filename().string();
        if (name.rfind("vault.audit.log.unverified-", 0) == 0) kept = readAll(item.path().string().c_str()) == edited;
    }
    check(kept, "tampered log is kept for investigation");
    check(verifyAuditChain(fresh, last) && fresh.find("\"event\":\"audit_log\",\"result\":\"integrity_failed\"") !=
        std::string::npos, "new log starts with an integrity event");
    check(log.find("password") == std::string::npos, "no secret-like content in the log");
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
    testAuditChain();
    std::filesystem::current_path(original);
    std::filesystem::remove_all(temp);
    if (failures == 0) std::cout << "Security controls tests passed\n";
    return failures == 0 ? 0 : 1;
}
