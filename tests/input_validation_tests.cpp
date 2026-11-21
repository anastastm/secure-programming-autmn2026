#include "input_validation.h"
#include <iostream>
#include <sstream>

int checks = 0;
int failures = 0;

void check(bool passed, const char* description)
{
    ++checks;
    if (!passed)
    {
        ++failures;
        std::cerr << "FAIL: " << description << '\n';
    }
}

int main()
{
    if (sodium_init() < 0)
    {
        std::cerr << "Could not initialize libsodium.\n";
        return 1;
    }

    check(!isValidField("", 100, true), "required field rejects empty input");
    check(!isValidField("   ", 100, true), "required field rejects only spaces");
    check(isValidField("", 100, false), "optional field accepts empty input");
    check(isValidField("   ", 100, false), "optional field preserves spaces");
    check(isValidField(" a ", 100, true), "field preserves surrounding spaces");
    check(isValidField("https://example.test/a?b=c&d=e", 2048, false), "URL punctuation is allowed");
    check(isValidField("quotes: \"hello\" and \\ paths", 2048, false), "quotes and backslashes are preserved");

    for (std::size_t limit : {100U, 256U, 2048U})
    {
        check(isValidField(std::string(limit, 'a'), limit, true), "field accepts exact length limit");
        check(!isValidField(std::string(limit + 1, 'a'), limit, true), "field rejects one byte over limit");
    }

    for (int character = 0; character < 32; ++character)
    {
        std::string value = "before";
        value.push_back(static_cast<char>(character));
        value += "after";
        check(!isValidField(value, 100, false), "field rejects every ASCII control character");
        check(!isValidPassword(value), "password rejects every ASCII control character");
    }
    check(!isValidField(std::string(1, 127), 100, false), "field rejects DEL");
    check(!isValidPassword(std::string(1, 127)), "password rejects DEL");

    check(!isValidPassword(""), "password rejects empty input");
    check(!isValidPassword("   "), "password rejects only spaces");
    check(isValidPassword("x"), "entry password and legacy unlock allow a short existing password");
    check(isValidPassword(" leading and trailing "), "password spaces are preserved");
    check(isValidPassword(std::string(256, 'x')), "password accepts 256 characters");
    check(!isValidPassword(std::string(257, 'x')), "password rejects 257 characters");
    check(!isValidPassword(std::string(1, static_cast<char>(0x80))), "password rejects non-ASCII bytes");
    check(!isValidNewMasterPassword(std::string(14, 'a')), "new master password rejects 14 characters");
    check(isValidNewMasterPassword("a long passphrase"), "new master password permits a passphrase without composition rules");
    check(isValidNewMasterPassword(std::string(15, 'a')), "new master password accepts length boundary");
    check(isValidNewMasterPassword(std::string(256, 'a')), "new master password accepts upper boundary");
    check(!isValidNewMasterPassword(std::string(257, 'a')), "new master password rejects upper boundary plus one");
    check(!isValidNewMasterPassword(std::string(20, ' ')), "new master password rejects only spaces");

    std::string value;
    std::istringstream exact("abc\n");
    check(readBoundedLine(exact, value, 3) == InputResult::success && value == "abc", "bounded input accepts exact limit");
    std::istringstream empty("\n");
    check(readBoundedLine(empty, value, 3) == InputResult::success && value.empty(), "bounded input reads an empty line");
    std::istringstream oversized(std::string(100000, 'x') + "\nok\n");
    check(readBoundedLine(oversized, value, 3) == InputResult::tooLong && value.empty(), "oversized input is rejected without retaining a prefix");
    check(readBoundedLine(oversized, value, 3) == InputResult::success && value == "ok", "oversized input is drained before the next read");
    std::istringstream menu("12\n2\n");
    check(readBoundedLine(menu, value, 1) == InputResult::tooLong && value.empty(), "menu rejects multiple characters");
    check(readBoundedLine(menu, value, 1) == InputResult::success && value == "2", "menu recovers after invalid input");
    std::istringstream ended;
    check(readBoundedLine(ended, value, 3) == InputResult::endOfInput && value.empty(), "EOF clears old input");
    std::istringstream partial("abc");
    check(readBoundedLine(partial, value, 3) == InputResult::endOfInput && value.empty(), "EOF rejects a partial line");
    std::istringstream zeroLimit("x\n\n");
    check(readBoundedLine(zeroLimit, value, 0) == InputResult::tooLong, "zero limit rejects nonempty input");
    check(readBoundedLine(zeroLimit, value, 0) == InputResult::success && value.empty(), "zero limit permits an empty line");
    std::istringstream broken("unused\n");
    broken.setstate(std::ios::badbit);
    check(readBoundedLine(broken, value, 10) == InputResult::endOfInput && value.empty(), "stream errors end input safely");

    std::string secret = "temporary password";
    clearString(secret);
    check(secret.empty(), "clearString leaves no logical password contents");
    clearString(secret);
    check(secret.empty(), "clearing an empty string is safe");

    std::cout << checks << " checks, " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
