#include "../secret_cleanup.h"
#include "vault_records.h"
#include <algorithm>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <type_traits>

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

    const std::string data = serializeEntries(saved);
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
    if (!parseEntries("[]", loaded) || !loaded.empty())
    {
        std::cerr << "Could not load an empty vault.\n";
        return false;
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
    if (!checkRecordLoading())
    {
        return 1;
    }
    std::cout << "4 key cleanup, 2 password string, and 3 record checks passed\n";
    return 0;
}
