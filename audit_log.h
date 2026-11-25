#pragma once

#include "local_files.h"
#include <ctime>
#include <iostream>
#include <string_view>
#ifdef _WIN32
#include <sddl.h>
#endif

constexpr std::size_t MAX_AUDIT_LOG_SIZE = 16U * 1024U * 1024U;
constexpr std::size_t AUDIT_HASH_HEX_LENGTH = crypto_generichash_BYTES * 2;

inline std::string auditActor()
{
#ifdef _WIN32
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return "unknown";
    alignas(TOKEN_USER) unsigned char buffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE];
    DWORD length;
    const BOOL ok = GetTokenInformation(token, TokenUser, buffer, sizeof buffer, &length);
    CloseHandle(token);
    LPSTR sid = nullptr;
    if (!ok || !ConvertSidToStringSidA(reinterpret_cast<TOKEN_USER*>(buffer)->User.Sid, &sid))
        return "unknown";
    std::string actor(sid);
    LocalFree(sid);
    return actor;
#else
    return "uid-" + std::to_string(getuid());
#endif
}

inline bool appendAuditLine(const std::string& line)
{
#ifdef _WIN32
    HANDLE file = CreateFileW(L"vault.audit.log", FILE_APPEND_DATA | FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
        nullptr, OPEN_ALWAYS, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info{};
    DWORD count = 0;
    bool ok = GetFileType(file) == FILE_TYPE_DISK && GetFileInformationByHandle(file, &info) &&
        !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
        info.nNumberOfLinks == 1 && WriteFile(file, line.data(), static_cast<DWORD>(line.size()), &count, nullptr) &&
        count == line.size();
    return CloseHandle(file) && ok;
#else
    int fd = open("vault.audit.log", O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0) return false;
    struct stat info{};
    bool ok = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == geteuid() &&
        info.st_nlink == 1 && fchmod(fd, 0600) == 0 &&
        write(fd, line.data(), line.size()) == static_cast<ssize_t>(line.size());
    return close(fd) == 0 && ok;
#endif
}

inline std::string auditLineHash(std::string_view line)
{
    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash, sizeof hash, reinterpret_cast<const unsigned char*>(line.data()),
        static_cast<unsigned long long>(line.size()), nullptr, 0);
    char hex[sizeof hash * 2 + 1];
    sodium_bin2hex(hex, sizeof hex, hash, sizeof hash);
    return hex;
}

inline std::string firstAuditHash()
{
    return std::string(AUDIT_HASH_HEX_LENGTH, '0');
}

inline bool verifyAuditChain(const std::string& text, std::string& lastHash)
{
    static const std::string_view marker = ",\"prev\":\"";
    lastHash = firstAuditHash();
    std::size_t position = 0;
    while (position < text.size())
    {
        const auto end = text.find('\n', position);
        if (end == std::string::npos) return false;
        const std::string_view line(text.data() + position, end - position);
        const std::size_t tail = marker.size() + AUDIT_HASH_HEX_LENGTH + 2;
        if (line.size() < tail || line.front() != '{' ||
            line.substr(line.size() - tail, marker.size()) != marker ||
            line.substr(line.size() - 2) != "\"}" ||
            line.substr(line.size() - AUDIT_HASH_HEX_LENGTH - 2, AUDIT_HASH_HEX_LENGTH) != lastHash)
        {
            return false;
        }
        lastHash = auditLineHash(line);
        position = end + 1;
    }
    return true;
}

struct AuditState
{
    bool ready = false;
    std::string lastHash;
};

inline AuditState& auditState()
{
    static AuditState state;
    return state;
}

inline std::string auditTimestamp(const char* format)
{
    const auto now = std::time(nullptr);
    std::tm utc{};
#ifdef _WIN32
    bool valid = gmtime_s(&utc, &now) == 0;
#else
    bool valid = gmtime_r(&now, &utc) != nullptr;
#endif
    char text[32]{};
    if (valid) std::strftime(text, sizeof text, format, &utc);
    return text;
}

inline void logEvent(const char* event, const char* result);

inline void startAuditChain()
{
    AuditState& state = auditState();
    state.ready = true;
    state.lastHash = firstAuditHash();

    std::error_code error;
    const auto status = std::filesystem::symlink_status("vault.audit.log", error);
    if (status.type() == std::filesystem::file_type::not_found) return;

    std::string text;
    if (!error && readLocalFile("vault.audit.log", MAX_AUDIT_LOG_SIZE, text) &&
        verifyAuditChain(text, state.lastHash))
    {
        return;
    }

    const std::string kept = "vault.audit.log.unverified-" + auditTimestamp("%Y%m%dT%H%M%SZ");
    std::filesystem::rename("vault.audit.log", kept, error);
    state.lastHash = firstAuditHash();
    if (error)
    {
        std::cout << "Warning: the audit log could not be verified or replaced.\n";
        logEvent("audit_log", "integrity_failed");
        return;
    }
    std::cout << "Warning: the audit log was changed outside this application or could not be read. "
        "It was kept as " << kept << " and a new log was started.\n";
    logEvent("audit_log", "integrity_failed");
}

inline void logEvent(const char* event, const char* result)
{
    AuditState& state = auditState();
    if (!state.ready) startAuditChain();

    static const std::string actor = auditActor();
    const std::string body = "{\"timestamp\":\"" + auditTimestamp("%Y-%m-%dT%H:%M:%SZ") +
        "\",\"actor\":\"" + actor + "\",\"event\":\"" + event + "\",\"result\":\"" + result +
        "\",\"prev\":\"" + state.lastHash + "\"}";
    if (appendAuditLine(body + "\n"))
    {
        state.lastHash = auditLineHash(body);
        return;
    }
    std::clog << "Audit file unavailable. Event written to standard error.\n" << body << '\n';
}
