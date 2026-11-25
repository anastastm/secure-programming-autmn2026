#pragma once

#include "input_validation.h"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#endif

using VaultKey = unsigned char[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

class VaultKeyWiper
{
public:
    explicit VaultKeyWiper(VaultKey& key) noexcept : key_(key) {}

    VaultKeyWiper(const VaultKeyWiper&) = delete;
    VaultKeyWiper& operator=(const VaultKeyWiper&) = delete;

    ~VaultKeyWiper() noexcept
    {
        if (wipeOnExit_)
        {
            sodium_memzero(key_, sizeof key_);
        }
    }

    void keepForSession() noexcept
    {
        wipeOnExit_ = false;
    }

private:
    VaultKey& key_;
    bool wipeOnExit_ = true;
};

class StringWiper
{
public:
    explicit StringWiper(std::string& value) noexcept : value_(value) {}

    StringWiper(const StringWiper&) = delete;
    StringWiper& operator=(const StringWiper&) = delete;

    ~StringWiper() noexcept
    {
        clearString(value_);
    }

private:
    std::string& value_;
};

class MemoryLock
{
public:
    MemoryLock(void* address, std::size_t length) noexcept
        : address_(address), length_(length), locked_(sodium_mlock(address, length) == 0) {}

    MemoryLock(const MemoryLock&) = delete;
    MemoryLock& operator=(const MemoryLock&) = delete;

    ~MemoryLock() noexcept
    {
        if (locked_) sodium_munlock(address_, length_);
    }

    bool locked() const noexcept { return locked_; }

private:
    void* address_;
    std::size_t length_;
    bool locked_;
};

inline bool hardenProcess() noexcept
{
#ifdef _WIN32
    SetErrorMode(GetErrorMode() | SEM_NOGPFAULTERRORBOX);
    return true;
#else
    struct rlimit noCore{0, 0};
    bool ok = setrlimit(RLIMIT_CORE, &noCore) == 0;
#ifdef __linux__
    ok = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 && ok;
#endif
    return ok;
#endif
}
