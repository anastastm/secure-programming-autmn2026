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
static_assert(std::is_nothrow_move_constructible_v<Entry>);

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
        R"("" "" "" "p" "")",              
        R"("s" "" "" " " "")",                      
        R"("s" "" "" ")" + std::string(1, char(0x80)) + R"(" "")",
        R"("s" "" "" "p" "bad\q")",                 
        R"("s" "" "" "p" "unfinished\)",            
        R"(unquoted "" "" "p" "")",
        R"("s" "" """p" "")",                        
        R"("s" "" "" "p")",                         
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

bool checkEntryMoves()
{
    std::deque<Entry> rows;
    for (const char* name : {"a", "b", "c"})
    {
        Entry& row = rows.emplace_back();
        row.service = name;
        row.password = std::string("pw-") + name;
    }
    Entry removed(std::move(rows[1]));
    if (!rows[1].service.empty() || !rows[1].password.empty()) return false;
    rows.erase(rows.begin() + 1);
    if (rows.size() != 2 || rows[0].service != "a" || rows[1].service != "c" ||
        rows[1].password != "pw-c" || removed.password != "pw-b")
    {
        return false;
    }
    rows.emplace(rows.begin() + 1, std::move(removed));
    return rows.size() == 3 && rows[1].service == "b" && removed.service.empty();
}

int main()
{
    if (!checkEntryMoves())
    {
        std::cerr << "Moving entries lost or duplicated data.\n";
        return 1;
    }
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

    {
        VaultKey lockedKey{};
        {
            MemoryLock lock(lockedKey, sizeof lockedKey);
            std::fill(std::begin(lockedKey), std::end(lockedKey), marker);
            if (lock.locked() && !allBytesEqual(lockedKey, marker))
            {
                std::cerr << "Locked key memory was not usable.\n";
                return 1;
            }
            if (!lock.locked())
            {
                std::cerr << "Note: memory locking is not available here (OS limit).\n";
                sodium_memzero(lockedKey, sizeof lockedKey);
            }
        }
        if (!allBytesEqual(lockedKey, 0))
        {
            std::cerr << "Unlocking key memory left key bytes behind.\n";
            return 1;
        }
    }
    static_assert(!std::is_copy_constructible_v<MemoryLock>);

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
    std::cout << "Key cleanup, memory lock, password cleanup, and record validation checks passed\n";
    return 0;
}
