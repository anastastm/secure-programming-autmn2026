#pragma once

#include <algorithm>
#include <array>
#include <deque>
#include <string_view>
#include "input_validation.h"

struct Entry
{
    std::string service;
    std::string website;
    std::string username;
    std::string password;
    std::string notes;

    Entry() = default;
    Entry(const Entry&) = delete;
    Entry& operator=(const Entry&) = delete;

    Entry(Entry&& other) noexcept { swapFields(other); }
    Entry& operator=(Entry&& other) noexcept
    {
        swapFields(other);
        return *this;
    }

    void swapFields(Entry& other) noexcept
    {
        service.swap(other.service);
        website.swap(other.website);
        username.swap(other.username);
        password.swap(other.password);
        notes.swap(other.notes);
    }

    ~Entry()
    {
        clearString(service);
        clearString(website);
        clearString(username);
        clearString(password);
        clearString(notes);
    }
};

inline std::array<std::string_view, 5> recordFields(const Entry& entry)
{
    return {entry.service, entry.website, entry.username, entry.password, entry.notes};
}

inline bool needsRecordEscape(char character)
{
    return character == '"' || character == '\\';
}

// The caller owns the guarded buffer. Reserve before writing any plaintext so
// growth cannot leave an old allocation containing a partial record.
inline void serializeEntries(const std::deque<Entry>& entries, std::string& output)
{
    clearString(output);
    std::size_t bytes = 0;
    for (const Entry& entry : entries)
    {
        for (std::string_view field : recordFields(entry))
        {
            // Two quotes and one separator (a space or the final newline).
            bytes += 3 + field.size() + std::count_if(field.begin(), field.end(), needsRecordEscape);
        }
    }
    output.reserve(bytes);

    for (const Entry& entry : entries)
    {
        for (std::string_view field : recordFields(entry))
        {
            output.push_back('"');
            for (char character : field)
            {
                if (needsRecordEscape(character))
                {
                    output.push_back('\\');
                }
                output.push_back(character);
            }
            output.append("\" ");
        }
        output.back() = '\n';
    }
}

inline bool takePrefix(std::string_view& input, char expected)
{
    if (input.empty() || input.front() != expected)
    {
        return false;
    }
    input.remove_prefix(1);
    return true;
}

// Scan the quoted field before allocating. The only escapes written by the
// vault format are an escaped quote and an escaped backslash.
inline bool readStoredField(std::string_view& input, std::string& field, std::size_t limit)
{
    clearString(field);
    if (!takePrefix(input, '"'))
    {
        return false;
    }

    std::size_t decodedLength = 0;
    for (std::size_t i = 0; i < input.size(); ++i)
    {
        if (input[i] == '"')
        {
            const std::string_view encoded = input.substr(0, i);
            field.reserve(decodedLength);
            for (std::size_t j = 0; j < encoded.size(); ++j)
            {
                if (encoded[j] == '\\')
                {
                    ++j;
                }
                field.push_back(encoded[j]);
            }
            input.remove_prefix(i + 1);
            return true;
        }
        if (input[i] == '\\')
        {
            ++i;
            if (i == input.size() || !needsRecordEscape(input[i]))
            {
                return false;
            }
        }
        if (++decodedLength > limit)
        {
            return false;
        }
    }
    return false;
}

inline bool parseEntries(std::string_view data, std::deque<Entry>& entries)
{
    if (data == "[]")
    {
        entries.clear();
        return true;
    }

    std::deque<Entry> loadedEntries;
    while (!data.empty())
    {
        const auto end = data.find('\n');
        std::string_view row = data.substr(0, end);
        data.remove_prefix(end == std::string_view::npos ? data.size() : end + 1);
        if (end != std::string_view::npos && !row.empty() && row.back() == '\r')
        {
            row.remove_suffix(1);
        }

        Entry& entry = loadedEntries.emplace_back();
        if (!readStoredField(row, entry.service, MAX_SERVICE_LENGTH) || !takePrefix(row, ' ') ||
            !readStoredField(row, entry.website, MAX_WEBSITE_LENGTH) || !takePrefix(row, ' ') ||
            !readStoredField(row, entry.username, MAX_USERNAME_LENGTH) || !takePrefix(row, ' ') ||
            !readStoredField(row, entry.password, MAX_PASSWORD_LENGTH) || !takePrefix(row, ' ') ||
            !readStoredField(row, entry.notes, MAX_NOTES_LENGTH) || !row.empty())
        {
            return false;
        }
        if (!isValidField(entry.service, MAX_SERVICE_LENGTH, true) ||
            !isValidField(entry.website, MAX_WEBSITE_LENGTH, false) ||
            !isValidField(entry.username, MAX_USERNAME_LENGTH, false) ||
            !isValidPassword(entry.password) ||
            !isValidField(entry.notes, MAX_NOTES_LENGTH, false))
        {
            return false;
        }
    }

    entries.swap(loadedEntries);
    return true;
}
