#pragma once

#include <deque>
#include <iomanip>
#include <sstream>
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

    ~Entry()
    {
        clearString(service);
        clearString(website);
        clearString(username);
        clearString(password);
        clearString(notes);
    }
};

inline std::string serializeEntries(const std::deque<Entry>& entries)
{
    std::ostringstream output;

    for (const Entry& entry : entries)
    {
        output << std::quoted(entry.service) << ' '
            << std::quoted(entry.website) << ' '
            << std::quoted(entry.username) << ' '
            << std::quoted(entry.password) << ' '
            << std::quoted(entry.notes) << '\n';
    }

    return output.str();
}

inline bool parseEntries(
    const std::string& data,
    std::deque<Entry>& entries)
{
    std::deque<Entry> loadedEntries;

    if (data == "[]")
    {
        entries.clear();
        return true;
    }

    std::istringstream input(data);
    input >> std::ws;
    while (!input.eof())
    {
        Entry& entry = loadedEntries.emplace_back();
        if (!(input >> std::quoted(entry.service)
            >> std::quoted(entry.website)
            >> std::quoted(entry.username)
            >> std::quoted(entry.password)
            >> std::quoted(entry.notes)))
        {
            return false;
        }

        if (!isValidField(entry.service, 100, true) ||
            !isValidField(entry.website, 2048, false) ||
            !isValidField(entry.username, 256, false) ||
            !isValidField(entry.notes, 2048, false) ||
            !isValidField(entry.password, MAX_PASSWORD_LENGTH, true))
        {
            return false;
        }

        input >> std::ws;
    }

    entries.swap(loadedEntries);
    return true;
}
