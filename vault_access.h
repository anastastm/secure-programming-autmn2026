#pragma once

#include "audit_log.h"
#ifdef _WIN32
#include <aclapi.h>
#endif

inline bool knownAccount(const std::string& account)
{
    return !account.empty() && account != "unknown";
}

inline bool ownerMatches(const std::string& owner, const std::string& account)
{
    return knownAccount(owner) && owner == account;
}

inline bool authorizeRecords(const std::string& owner, const char* event)
{
    if (ownerMatches(owner, auditActor())) return true;
    logEvent(event, "access_denied");
    std::cout << "Access denied. Unlock the vault as its owner.\n";
    return false;
}

inline std::string ownerBinding(const std::string& account)
{
    return "password-manager/v2/" + account;
}

// Version 1 had no authenticated owner. Verify file ownership and bytes on
// the same handle before admitting a legacy vault to the current session.
inline bool ownsLegacyVault(const std::string& expected, const std::string& account)
{
    if (!knownAccount(account) || expected.empty()) return false;
    std::string bytes(expected.size(), '\0');
#ifdef _WIN32
    HANDLE file = CreateFileW(L"vault.json", GENERIC_READ | READ_CONTROL, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info{};
    PSECURITY_DESCRIPTOR security = nullptr;
    PSID owner = nullptr;
    LPSTR ownerText = nullptr;
    DWORD count = 0;
    bool ok = GetFileType(file) == FILE_TYPE_DISK && GetFileInformationByHandle(file, &info) &&
        !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) &&
        info.nFileSizeHigh == 0 && info.nFileSizeLow == bytes.size() &&
        GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner,
            nullptr, nullptr, nullptr, &security) == ERROR_SUCCESS &&
        ConvertSidToStringSidA(owner, &ownerText) && account == ownerText &&
        ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) &&
        count == bytes.size();
    LocalFree(ownerText);
    LocalFree(security);
    CloseHandle(file);
#else
    int file = open("vault.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (file < 0) return false;
    struct stat info{};
    bool ok = fstat(file, &info) == 0 && S_ISREG(info.st_mode) &&
        account == "uid-" + std::to_string(info.st_uid) &&
        info.st_size == static_cast<off_t>(bytes.size());
    std::size_t pos = 0;
    while (ok && pos < bytes.size())
    {
        const auto count = read(file, bytes.data() + pos, bytes.size() - pos);
        if (count <= 0) ok = false;
        else pos += static_cast<std::size_t>(count);
    }
    close(file);
#endif
    return ok && bytes == expected;
}
