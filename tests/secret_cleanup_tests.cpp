#include "../secret_cleanup.h"
#include "vault_records.h"
#include <algorithm>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <type_traits>
#include <utility>

static_assert(!std::is_copy_constructible_v<VaultKeyWiper>);
static_assert(!std::is_move_constructible_v<VaultKeyWiper>);
static_assert(!std::is_copy_constructible_v<StringWiper>);
static_assert(!std::is_copy_constructible_v<Entry>);

bool allBytesEqual(const VaultKey& key, unsigned char value)
{
    return std::all_of(std::begin(key), std::end(key),
        [value](unsigned char byte) { return byte == value; });
}

void leaveEarly(VaultKey& key, bool cancel)
{
    VaultKeyWiper guard(key);
    if (cancel)
    {
        return;
    }
    guard.keepForSession();
}

bool checkStringCleanup(std::string& value)
{
    {
        StringWiper guard(value);
        value = "test phrase";
    }
    if (!value.empty())
    {
        return false;
    }

    try
    {
        StringWiper guard(value);
        value.assign(MAX_PASSWORD_LENGTH, 'x');
        throw std::runtime_error("test unwind");
    }
    catch (const std::runtime_error&)
    {
        return value.empty();
    }
}

bool checkRecordLoading()
{
    std::deque<Entry> saved;
    Entry& first = saved.emplace_back();
    first.service = "example";
    first.password = R"( spaced "quoted" )";
    first.notes = "folder\\name";
    Entry& second = saved.emplace_back();
    second.service = "other";
    second.password.assign(MAX_PASSWORD_LENGTH, 'x');

    std::string data;
    StringWiper wipeData(data);
    serializeEntries(saved, data);

    // This is the exact layout written by the original std::quoted serializer.
    const std::string expected =
        R"("example" "" "" " spaced \"quoted\" " "folder\\name")" "\n" +
        std::string(R"("other" "" "" ")") + second.password + "\" \"\"\n";
    if (data != expected)
    {
        std::cerr << "Saved bytes differ from the existing vault format.\n";
        return false;
    }
    std::deque<Entry> loaded;
    if (!parseEntries(data, loaded) || loaded.size() != 2 ||
        loaded.front().service != first.service || loaded.front().password != first.password ||
        loaded.front().notes != first.notes || loaded.back().password != second.password)
    {
        std::cerr << "Saved entries did not survive a round trip.\n";
        return false;
    }
    if (parseEntries(data + "\"unfinished", loaded) || loaded.size() != 2 ||
        loaded.front().password != first.password || loaded.back().password != second.password)
    {
        std::cerr << "A partial record replaced the current entries.\n";
        return false;
    }
    saved.clear();
    serializeEntries(saved, data);
    if (!data.empty() || !parseEntries(data, loaded) || !loaded.empty())
    {
        std::cerr << "Serializing an empty vault retained record data.\n";
        return false;
    }
    if (!parseEntries("[]", loaded) || !loaded.empty())
    {
        std::cerr << "Could not load an empty vault.\n";
        return false;
    }
    return true;
}

bool checkStoredFieldValidation()
{
    std::deque<Entry> loaded;
    const std::string good = R"("original" "" "" "p" "")";
    if (!parseEntries(good + "\r\n", loaded) || loaded.size() != 1)
    {
        std::cerr << "Could not read a CRLF record.\n";
        return false;
    }

    const std::string invalidRows[] = {
        R"("" "" "" "p" "")",                         // Missing service
        R"("s" "" "" " " "")",                       // Blank password
        R"("s" "" "" ")" + std::string(1, char(0x80)) + R"(" "")",
        R"("s" "" "" "p" "bad\q")",                  // Unknown escape
        R"("s" "" "" "p" "unfinished\)",              // Incomplete escape
        R"(unquoted "" "" "p" "")",
        R"("s" "" """p" "")",                        // Missing separator
        R"("s" "" "" "p")",                          // Missing field
        R"("s" "" "" "p" "" "extra")",
        R"("s" "" "" "p" ")" + std::string(1, '\0') + R"(")"
    };
    for (const std::string& invalid : invalidRows)
    {
        if (parseEntries(good + "\n" + invalid, loaded) ||
            loaded.size() != 1 || loaded.front().service != "original")
        {
            std::cerr << "Invalid row accepted or existing entries replaced.\n";
            return false;
        }
    }

    // Each limit counts decoded bytes, even when every character needs escaping.
    std::deque<Entry> rows;
    Entry& row = rows.emplace_back();
    row.service = "s";
    row.password = "p";
    const std::pair<std::string*, std::size_t> fields[] = {
        {&row.service, MAX_SERVICE_LENGTH}, {&row.website, MAX_WEBSITE_LENGTH},
        {&row.username, MAX_USERNAME_LENGTH}, {&row.password, MAX_PASSWORD_LENGTH},
        {&row.notes, MAX_NOTES_LENGTH}
    };
    std::string data;
    StringWiper guard(data);
    for (const auto& [field, limit] : fields)
    {
        field->assign(limit, '"');
        serializeEntries(rows, data);
        if (!parseEntries(data, loaded) || loaded.size() != 1 ||
            recordFields(loaded.front()) != recordFields(row))
        {
            std::cerr << "Could not round-trip a field at its limit.\n";
            return false;
        }
        field->push_back('"');
        serializeEntries(rows, data);
        if (parseEntries(data, loaded))
        {
            std::cerr << "Accepted an oversized stored field.\n";
            return false;
        }
        field->assign(1, 'x');
    }
    return true;
}

int main()
{
    VaultKey key{};
    const unsigned char marker = 0xA5;
    std::fill(std::begin(key), std::end(key), marker);
    leaveEarly(key, true);
    if (!allBytesEqual(key, 0))
    {
        std::cerr << "Early return left key bytes behind.\n";
        return 1;
    }

    try
    {
        VaultKeyWiper guard(key);
        std::fill(std::begin(key), std::end(key), marker);
        throw std::runtime_error("test unwind");
    }
    catch (const std::runtime_error&)
    {
        if (!allBytesEqual(key, 0))
        {
            std::cerr << "Exception unwinding left key bytes behind.\n";
            return 1;
        }
    }

    {
        VaultKeyWiper sessionGuard(key);
        std::fill(std::begin(key), std::end(key), marker);
        leaveEarly(key, false);
        if (!allBytesEqual(key, marker))
        {
            std::cerr << "Successful unlock guard cleared the active key.\n";
            return 1;
        }
    }
    if (!allBytesEqual(key, 0))
    {
        std::cerr << "Leaving the session left key bytes behind.\n";
        return 1;
    }

    std::string password;
    if (!checkStringCleanup(password))
    {
        std::cerr << "Password string retained its contents after cleanup.\n";
        return 1;
    }
    if (!checkRecordLoading() || !checkStoredFieldValidation())
    {
        return 1;
    }
    std::cout << "Key cleanup, password cleanup, and record validation checks passed\n";
    return 0;
}
