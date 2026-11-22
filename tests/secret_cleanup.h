#pragma once

#include "input_validation.h"

using VaultKey = unsigned char[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

// The referenced array must outlive its guard.
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

    // After a successful unlock, the session's outer guard still owns cleanup.
    void keepForSession() noexcept
    {
        wipeOnExit_ = false;
    }

private:
    VaultKey& key_;
    bool wipeOnExit_ = true;
};

// Declare the guard after the string so the string is still alive during cleanup.
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
