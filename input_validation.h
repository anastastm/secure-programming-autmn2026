#pragma once

#include <cstddef>
#include <istream>
#include <string>
#include <string_view>
#include <sodium.h>

constexpr std::size_t MIN_MASTER_PASSWORD_LENGTH = 15;
constexpr std::size_t MAX_PASSWORD_LENGTH = 256;
constexpr std::size_t MAX_SERVICE_LENGTH = 100;
constexpr std::size_t MAX_WEBSITE_LENGTH = 2048;
constexpr std::size_t MAX_USERNAME_LENGTH = 256;
constexpr std::size_t MAX_NOTES_LENGTH = 2048;

inline void clearString(std::string& value)
{
    if (!value.empty())
    {
        sodium_memzero(value.data(), value.size());
        value.clear();
    }
}

inline bool isValidField(
    const std::string& value,
    std::size_t maxLength,
    bool required)
{
    if (value.size() > maxLength)
    {
        return false;
    }

    bool hasNonSpace = false;

    for (unsigned char character : value)
    {
        if (character < 32 || character == 127)
        {
            return false;
        }

        if (character != ' ')
        {
            hasNonSpace = true;
        }
    }

    return !required || hasNonSpace;
}

inline bool isValidPassword(const std::string& value)
{
    if (!isValidField(value, MAX_PASSWORD_LENGTH, true))
    {
        return false;
    }

    for (unsigned char character : value)
    {
        if (character > 126)
        {
            return false;
        }
    }

    return true;
}

inline bool isSequenceRun(const std::string& lower)
{
    static const char* const sequences[] = {
        "0123456789", "abcdefghijklmnopqrstuvwxyz",
        "qwertyuiopasdfghjklzxcvbnm", "!@#$%^&*()"
    };
    for (const char* sequence : sequences)
    {
        const std::string forward(sequence);
        const std::string backward(forward.rbegin(), forward.rend());
        for (const std::string& cycle : {forward, backward})
        {
            std::string repeated;
            while (repeated.size() < lower.size() + cycle.size()) repeated += cycle;
            if (repeated.find(lower) != std::string::npos) return true;
        }
    }
    return false;
}

inline bool isWeakMasterPassword(const std::string& value)
{
    bool seen[128]{};
    std::size_t distinct = 0;
    std::string lower;
    lower.reserve(value.size());
    for (unsigned char character : value)
    {
        if (character < 128 && !seen[character])
        {
            seen[character] = true;
            ++distinct;
        }
        lower.push_back(static_cast<char>(character >= 'A' && character <= 'Z' ? character + 32 : character));
    }
    if (distinct < 5)
    {
        clearString(lower);
        return true;
    }

    for (std::size_t unit = 1; unit <= lower.size() / 2; ++unit)
    {
        if (lower.size() % unit != 0) continue;
        bool repeated = true;
        for (std::size_t i = unit; i < lower.size() && repeated; ++i)
        {
            repeated = lower[i] == lower[i - unit];
        }
        if (repeated)
        {
            clearString(lower);
            return true;
        }
    }

    if (isSequenceRun(lower))
    {
        clearString(lower);
        return true;
    }

    static const char* const commonWords[] = {
        "administrator", "masterpassword", "passphrase", "password", "iloveyou",
        "football", "baseball", "princess", "sunshine", "superman", "whatever",
        "changeme", "trustno", "letmein", "welcome", "freedom", "monkey", "dragon",
        "shadow", "master", "secret", "qwerty", "qwertz", "azerty", "admin",
        "login", "hello", "guest", "default", "test", "user", "root", "abc"
    };
    const auto sameLetter = [](char typed, char letter) {
        switch (typed)
        {
        case '0': return letter == 'o';
        case '1': case '!': return letter == 'i' || letter == 'l';
        case '3': return letter == 'e';
        case '4': case '@': return letter == 'a';
        case '5': case '$': return letter == 's';
        case '7': return letter == 't';
        default: return typed == letter;
        }
    };
    std::string rest;
    rest.reserve(lower.size());
    bool foundWord = false;
    for (std::size_t i = 0; i < lower.size();)
    {
        std::size_t matched = 0;
        for (const char* word : commonWords)
        {
            const std::string_view candidate(word);
            if (candidate.size() > lower.size() - i) continue;
            std::size_t j = 0;
            while (j < candidate.size() && sameLetter(lower[i + j], candidate[j])) ++j;
            if (j == candidate.size())
            {
                matched = j;
                break;
            }
        }
        if (matched > 0)
        {
            foundWord = true;
            i += matched;
        }
        else
        {
            rest.push_back(lower[i++]);
        }
    }
    clearString(lower);

    bool weak = false;
    if (foundWord)
    {
        bool restSeen[128]{};
        std::size_t restDistinct = 0;
        for (unsigned char character : rest)
        {
            if (character < 128 && !restSeen[character])
            {
                restSeen[character] = true;
                ++restDistinct;
            }
        }
        weak = rest.size() < 10 || restDistinct < 5 || isSequenceRun(rest);
    }
    clearString(rest);
    return weak;
}

inline bool isValidNewMasterPassword(const std::string& value)
{
    return value.size() >= MIN_MASTER_PASSWORD_LENGTH &&
        isValidPassword(value) && !isWeakMasterPassword(value);
}

enum class InputResult
{
    success,
    tooLong,
    endOfInput
};

inline InputResult readBoundedLine(
    std::istream& input,
    std::string& value,
    std::size_t maxLength)
{
    clearString(value);
    value.reserve(maxLength);
    bool tooLong = false;
    int character;

    while ((character = input.get()) != std::char_traits<char>::eof())
    {
        if (character == '\n')
        {
            if (tooLong)
            {
                clearString(value);
                return InputResult::tooLong;
            }

            return InputResult::success;
        }

        if (value.size() < maxLength)
        {
            value.push_back(static_cast<char>(character));
        }
        else
        {
            tooLong = true;
        }
    }

    clearString(value);
    return InputResult::endOfInput;
}
