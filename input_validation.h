#pragma once

#include <cstddef>
#include <istream>
#include <string>
#include <sodium.h>

constexpr std::size_t MIN_MASTER_PASSWORD_LENGTH = 15;
constexpr std::size_t MAX_PASSWORD_LENGTH = 256;

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

inline bool isValidNewMasterPassword(const std::string& value)
{
    return value.size() >= MIN_MASTER_PASSWORD_LENGTH &&
        isValidPassword(value);
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
