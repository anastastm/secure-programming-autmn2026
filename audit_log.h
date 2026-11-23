#pragma once

#include "local_files.h"
#include <ctime>
#include <iostream>
#ifdef _WIN32
#include <sddl.h>
#endif

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

// Callers supply fixed event/result labels. Record contents never enter the log API.
inline void logEvent(const char* event, const char* result)
{
    const auto now = std::time(nullptr);
    std::tm utc{};
#ifdef _WIN32
    bool valid = gmtime_s(&utc, &now) == 0;
#else
    bool valid = gmtime_r(&now, &utc) != nullptr;
#endif
    char time[32]{};
    if (valid) std::strftime(time, sizeof time, "%Y-%m-%dT%H:%M:%SZ", &utc);
    static const std::string actor = auditActor();
    const std::string line = std::string("{\"timestamp\":\"") + time + "\",\"actor\":\"" + actor +
        "\",\"event\":\"" + event + "\",\"result\":\"" + result + "\"}\n";
    if (!appendAuditLine(line))
        std::clog << "Audit file unavailable. Event written to standard error.\n";
    std::clog << line;
}
