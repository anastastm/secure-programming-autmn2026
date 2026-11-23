#pragma once

#include "local_files.h"
#include <cstdint>
#include <sstream>

struct UnlockLimit
{
    static constexpr int maxAttempts = 5;
    static constexpr int cooldownSeconds = 60;
    int attempts = 0;
    std::int64_t blockedUntil = 0;

    bool load()
    {
        std::error_code error;
        auto status = std::filesystem::symlink_status("vault.attempts", error);
        if (status.type() == std::filesystem::file_type::not_found &&
            (!error || error == std::errc::no_such_file_or_directory))
        {
            *this = {};
            return true;
        }
        std::string text;
        if (error || !readLocalFile("vault.attempts", 64, text)) return false;
        std::istringstream in(text);
        if (!(in >> attempts >> blockedUntil)) return false;
        in >> std::ws;
        return in.eof() && attempts >= 0 && attempts <= maxAttempts &&
            blockedUntil >= 0 && ((attempts == maxAttempts) == (blockedUntil > 0));
    }

    bool save() const
    {
        return replaceLocalFile("vault.attempts",
            std::to_string(attempts) + " " + std::to_string(blockedUntil) + "\n");
    }

    bool blocked(std::int64_t now) const { return blockedUntil > now; }

    // Persist before checking the password, so quitting mid-check still costs an attempt.
    bool reserve(std::int64_t now)
    {
        if (blocked(now)) return false;
        if (blockedUntil != 0) *this = {};
        ++attempts;
        if (attempts == maxAttempts) blockedUntil = now + cooldownSeconds;
        return save();
    }

    bool reset()
    {
        *this = {};
        return save();
    }
};
