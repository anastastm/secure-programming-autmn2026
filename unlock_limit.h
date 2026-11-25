#pragma once

#include "local_files.h"
#include <cstdint>
#include <sstream>

struct UnlockLimit
{
    static constexpr int maxAttempts = 5;
    static constexpr std::int64_t firstCooldownSeconds = 60;
    static constexpr std::int64_t maxCooldownSeconds = 60 * 60;
    static constexpr std::int64_t maxLockouts = 1000000;
    int attempts = 0;
    std::int64_t blockedUntil = 0;
    std::int64_t lockouts = 0;
    bool missing = false;

    static std::int64_t cooldownFor(std::int64_t lockout)
    {
        std::int64_t seconds = firstCooldownSeconds;
        for (std::int64_t i = 1; i < lockout && seconds < maxCooldownSeconds; ++i) seconds *= 2;
        return seconds < maxCooldownSeconds ? seconds : maxCooldownSeconds;
    }

    bool load()
    {
        *this = {};
        std::error_code error;
        auto status = std::filesystem::symlink_status("vault.attempts", error);
        if (status.type() == std::filesystem::file_type::not_found &&
            (!error || error == std::errc::no_such_file_or_directory))
        {
            missing = true;
            return true;
        }
        std::string text;
        if (error || !readLocalFile("vault.attempts", 64, text)) return false;
        std::istringstream in(text);
        if (!(in >> attempts >> blockedUntil)) return false;
        in >> std::ws;
        if (in.eof())
        {
            lockouts = blockedUntil > 0 ? 1 : 0;
        }
        else
        {
            if (!(in >> lockouts)) return false;
            in >> std::ws;
            if (!in.eof()) return false;
        }
        return attempts >= 0 && attempts <= maxAttempts &&
            blockedUntil >= 0 && ((attempts == maxAttempts) == (blockedUntil > 0)) &&
            lockouts >= 0 && lockouts <= maxLockouts && (blockedUntil == 0 || lockouts >= 1);
    }

    bool save() const
    {
        return replaceLocalFile("vault.attempts",
            std::to_string(attempts) + " " + std::to_string(blockedUntil) + " " +
            std::to_string(lockouts) + "\n");
    }

    bool blocked(std::int64_t now) const { return blockedUntil > now; }

    bool lockBecauseMissing(std::int64_t now)
    {
        *this = {};
        attempts = maxAttempts;
        lockouts = 1;
        blockedUntil = now + cooldownFor(lockouts);
        return save();
    }

    bool reserve(std::int64_t now)
    {
        if (blocked(now)) return false;
        if (blockedUntil != 0)
        {
            attempts = 0;
            blockedUntil = 0;
        }
        missing = false;
        ++attempts;
        if (attempts == maxAttempts)
        {
            if (lockouts < maxLockouts) ++lockouts;
            blockedUntil = now + cooldownFor(lockouts);
        }
        return save();
    }

    bool reset()
    {
        *this = {};
        return save();
    }
};
