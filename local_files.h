#pragma once

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <sodium.h>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

// Keep one writer per vault directory. The OS releases the lock on process exit.
class VaultDirectoryLock
{
public:
    VaultDirectoryLock() = default;
    VaultDirectoryLock(const VaultDirectoryLock&) = delete;
    VaultDirectoryLock& operator=(const VaultDirectoryLock&) = delete;

    bool acquire()
    {
#ifdef _WIN32
        handle = CreateFileW(L"vault.lock", GENERIC_READ | GENERIC_WRITE, 0,
            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        return handle != INVALID_HANDLE_VALUE;
#else
        fd = open("vault.lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_NONBLOCK, 0600);
        struct stat info{};
        return fd >= 0 && fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
            flock(fd, LOCK_EX | LOCK_NB) == 0;
#endif
    }

    ~VaultDirectoryLock()
    {
#ifdef _WIN32
        if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
#else
        if (fd >= 0) close(fd);
#endif
    }

private:
#ifdef _WIN32
    HANDLE handle = INVALID_HANDLE_VALUE;
#else
    int fd = -1;
#endif
};

inline bool readLocalFile(const std::filesystem::path& path, std::size_t limit, std::string& data)
{
    std::error_code error;
    if (!std::filesystem::is_regular_file(std::filesystem::symlink_status(path, error))) return false;
    const auto size = std::filesystem::file_size(path, error);
    if (error || size > limit) return false;

    std::ifstream file(path, std::ios::binary);
    if (!file) return false;
    data.resize(static_cast<std::size_t>(size));
    file.read(data.data(), static_cast<std::streamsize>(size));
    return file && file.peek() == std::char_traits<char>::eof() && !file.bad();
}

inline bool writeNewFile(const std::filesystem::path& path, const std::string& data)
{
#ifdef _WIN32
    HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD count = 0;
    const bool wrote = WriteFile(file, data.data(), static_cast<DWORD>(data.size()), &count, nullptr) &&
        count == data.size();
    const bool closed = CloseHandle(file) != 0;
#else
    const int fd = open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) return false;
    FILE* file = fdopen(fd, "wb");
    if (!file)
    {
        close(fd);
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
        return false;
    }
    const bool wrote = std::fwrite(data.data(), 1, data.size(), file) == data.size();
    const bool closed = std::fclose(file) == 0;
#endif
    if (wrote && closed) return true;
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    return false;
}

inline bool replaceLocalFile(const std::filesystem::path& path, const std::string& data)
{
    unsigned char random[16];
    char suffix[sizeof random * 2 + 1];
    randombytes_buf(random, sizeof random);
    sodium_bin2hex(suffix, sizeof suffix, random, sizeof random);
    auto temp = path;
    temp += std::string(".") + suffix + ".tmp";
    if (!writeNewFile(temp, data)) return false;

    std::error_code error;
    std::filesystem::rename(temp, path, error);
    if (!error) return true;
    std::filesystem::remove(temp, error);
    return false;
}
