#include <iostream>
#include <charconv>
#include <string>
#include <vector>
#include <deque>
#include <filesystem>
#include <sodium.h>
#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif
#include <fstream>
#include <cstddef>
#include <system_error>

#include "input_validation.h"
#include "secret_cleanup.h"
#include "vault_records.h"
#include "audit_log.h"
#include "console_control.h"
#include "unlock_limit.h"
#include "vault_file.h"
#include "vault_access.h"
#include "vault_crypto.h"
#include "clipboard.h"

struct VaultSnapshot
{
    std::string owner;
    std::string bytes;
    std::string salt;
    int version = 0;
};

void readPassword(const char* prompt, std::string& password)
{
    clearString(password);
    bool tooLong = false;
    bool invalidCharacter = false;
    password.reserve(MAX_PASSWORD_LENGTH);

#ifndef _WIN32
    termios originalSettings{};
    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &originalSettings) != 0)
    {
        std::cout << "Password input requires an interactive terminal.\n";
        return;
    }

    termios hiddenSettings = originalSettings;
    hiddenSettings.c_lflag &= static_cast<tcflag_t>(~(ECHO | ICANON));
    hiddenSettings.c_cc[VMIN] = 1;
    hiddenSettings.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hiddenSettings) != 0)
    {
        std::cout << "Could not configure hidden password input.\n";
        return;
    }
#endif

    std::cout << prompt << std::flush;
    while (!interrupted())
    {
#ifdef _WIN32
        int key = _getch();
#else
        int key = std::cin.get();
#endif
        if (interrupted() || key == EOF
#ifdef _WIN32
            || key == 26
#else
            || key == 4
#endif
            )
        {
            clearString(password);
            std::cin.setstate(std::ios::eofbit);
            break;
        }

#ifdef _WIN32
        if (key == 3)
        {
            InterlockedExchange(&stopRequested, 1);
            break;
        }
#endif
        if (key == '\r' || key == '\n')
        {
            break;
        }
        else if (key == '\b' || key == 127)
        {
            if (!password.empty())
            {
                sodium_memzero(&password.back(), 1);
                password.pop_back();
                std::cout << "\b \b" << std::flush;
            }
        }
#ifdef _WIN32
        else if (key == 0 || key == 224)
        {
            _getch();
            invalidCharacter = true;
        }
#endif
        else if (key >= 32 && key <= 126)
        {
            if (password.size() < MAX_PASSWORD_LENGTH)
            {
                password.push_back(static_cast<char>(key));
                std::cout << '*' << std::flush;
            }
            else
            {
                tooLong = true;
            }
        }
        else
        {
            invalidCharacter = true;
        }
    }

#ifndef _WIN32
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &originalSettings);
#endif
    std::cout << '\n';

    if (interrupted())
    {
        clearString(password);
        std::cin.setstate(std::ios::eofbit);
        return;
    }

    if (tooLong)
    {
        clearString(password);
        std::cout << "Password is too long. Maximum length is 256 characters.\n";
        return;
    }

    if (invalidCharacter)
    {
        clearString(password);
        std::cout << "Use printable ASCII characters and spaces for passwords.\n";
    }
}

bool saveVault(
    const std::deque<Entry>& entries,
    const VaultKey& vaultKey,
    VaultSnapshot& snapshot)
{
    if (!authorizeRecords(snapshot.owner, "vault_save")) return false;
    const auto binding = ownerBinding(snapshot.owner);
    std::string plainData;
    StringWiper wipePlainData(plainData);
    serializeEntries(entries, plainData);

    std::string nonceHex;
    std::string encryptedHex;
    const bool sealed = sealVaultData(plainData, vaultKey, binding, nonceHex, encryptedHex);
    clearString(plainData);
    if (!sealed)
    {
        std::cout << "Could not encrypt the entries.\n";
        return false;
    }

    if (encryptedHex.size() > MAX_VAULT_FILE_SIZE - 256)
    {
        std::cout << "The vault is too large to save.\n";
        return false;
    }

    const int version = snapshot.version == 1 ? 2 : snapshot.version;
    std::string updated = formatVaultFile(snapshot.salt, nonceHex.c_str(), encryptedHex.c_str(), version);
    std::string current;
    if (!readLocalFile("vault.json", MAX_VAULT_FILE_SIZE, current) || current != snapshot.bytes)
    {
        std::cout << "The vault changed since unlock. Lock and reopen it before saving.\n";
        logEvent("vault_save", "file_changed");
        return false;
    }
    if (interrupted() || !replaceLocalFile("vault.json", updated)) return false;
    snapshot.bytes.swap(updated);
    snapshot.version = version;
    return true;
}

bool unlockVault(
    std::string& masterPassword,
    VaultKey& vaultKey,
    std::deque<Entry>& entries,
    VaultSnapshot& snapshot)
{
    VaultKeyWiper wipeOnFailure(vaultKey);

    std::string bytes;
    VaultFile header;
    if (!readLocalFile("vault.json", MAX_VAULT_FILE_SIZE, bytes) || !parseVaultFile(bytes, header))
    {
        clearString(masterPassword);
        std::cout << "Could not read a valid vault file.\n";
        return false;
    }

    const auto account = auditActor();
    if (!knownAccount(account) || (header.version == 1 && !ownsLegacyVault(bytes, account)))
    {
        clearString(masterPassword);
        logEvent("vault_unlock", "access_denied");
        std::cout << "Could not authorize this account for the vault.\n";
        return false;
    }
    const std::string binding = header.version >= 2 ? ownerBinding(account) : "";

    VaultBytes decoded;
    if (!decodeVaultFile(header, decoded))
    {
        clearString(masterPassword);
        std::cout << "The vault file contains invalid data.\n";
        return false;
    }

    if (!deriveVaultKey(masterPassword, decoded.salt.data(), header.version, vaultKey))
    {
        std::cout << "Could not create the encryption key.\n";
        return false;
    }

    std::string plainData;
    StringWiper wipePlainData(plainData);
    if (!openVaultData(decoded, vaultKey, binding, plainData))
    {
        std::cout << "Incorrect password, or the vault file is damaged.\n";
        return false;
    }

    if (parseEntries(plainData, entries) == false)
    {
        std::cout << "The decrypted vault data is invalid.\n";
        return false;
    }

    snapshot.owner = account;
    snapshot.bytes.swap(bytes);
    snapshot.salt.swap(header.salt);
    snapshot.version = header.version;
    wipeOnFailure.keepForSession();
    return true;
}

bool readEntryField(
    const char* prompt,
    std::string& value,
    std::size_t maxLength,
    bool required)
{
    std::cout << prompt << std::flush;
    InputResult result = readBoundedLine(std::cin, value, maxLength);

    if (interrupted() || result == InputResult::endOfInput)
    {
        return false;
    }

    if (result == InputResult::tooLong ||
        !isValidField(value, maxLength, required))
    {
        clearString(value);
        std::cout << "Invalid field. Maximum length: " << maxLength
            << " bytes. Control characters are not allowed.";
        if (required)
        {
            std::cout << " A non-blank value is required.";
        }
        std::cout << '\n';
        return false;
    }

    return true;
}

bool readNewEntry(Entry& entry)
{
    if (!readEntryField("Service name: ", entry.service, MAX_SERVICE_LENGTH, true) ||
        !readEntryField("Website: ", entry.website, MAX_WEBSITE_LENGTH, false) ||
        !readEntryField("Username: ", entry.username, MAX_USERNAME_LENGTH, false))
    {
        logEvent("entry_add", "input_rejected");
        return false;
    }

    readPassword("Password: ", entry.password);
    if (!std::cin.good() || interrupted())
    {
        return false;
    }

    if (!isValidPassword(entry.password))
    {
        std::cout << "The entry password must contain 1-256 printable ASCII characters, not only spaces.\n";
        logEvent("entry_add", "validation_failed");
        return false;
    }

    if (!readEntryField("Notes: ", entry.notes, MAX_NOTES_LENGTH, false))
    {
        logEvent("entry_add", "input_rejected");
        return false;
    }

    return true;
}

void addEntry(std::deque<Entry>& entries, const VaultKey& vaultKey, VaultSnapshot& snapshot)
{
    if (!authorizeRecords(snapshot.owner, "entry_add")) return;
    if (!readNewEntry(entries.emplace_back()))
    {
        entries.pop_back();
        return;
    }

    if (!saveVault(entries, vaultKey, snapshot))
    {
        entries.pop_back();
        std::cout << "Could not save the entry. It was not added.\n";
        logEvent("entry_add", "save_failed");
        return;
    }
    std::cout << "Entry added and saved to the encrypted vault.\n";
    logEvent("entry_add", "success");
}

void viewEntries(const std::deque<Entry>& entries, const VaultSnapshot& snapshot)
{
    if (!authorizeRecords(snapshot.owner, "entry_view")) return;
    logEvent("entry_view", "success");
    if (entries.empty())
    {
        std::cout << "There are no entries in this session.\n";
        return;
    }

    for (std::size_t i = 0; i < entries.size(); i++)
    {
        std::cout << "\nEntry " << i + 1 << "\n";
        std::cout << "Service: " << entries[i].service << "\n";
        std::cout << "Website: " << entries[i].website << "\n";
        std::cout << "Username: " << entries[i].username << "\n";
        std::cout << "Password: [hidden]\n";
        std::cout << "Notes: " << entries[i].notes << "\n";
    }
}

std::size_t readEntryNumber(const char* action, std::size_t count)
{
    std::cout << "Entry number to " << action << " (1-" << count << "): " << std::flush;
    std::string input;
    if (readBoundedLine(std::cin, input, 20) != InputResult::success || interrupted()) return 0;
    std::size_t number = 0;
    const auto end = input.data() + input.size();
    const auto parsed = std::from_chars(input.data(), end, number);
    if (parsed.ec != std::errc{} || parsed.ptr != end || number == 0 || number > count)
    {
        std::cout << "Invalid entry number.\n";
        return 0;
    }
    return number;
}

bool confirmWithYes(const std::string& question)
{
    std::cout << question << " Type yes: " << std::flush;
    std::string input;
    return readBoundedLine(std::cin, input, 3) == InputResult::success && input == "yes" && !interrupted();
}

bool readEditedField(const char* prompt, std::string& value, std::size_t maxLength, bool required, bool& changed)
{
    std::string input;
    StringWiper wipeInput(input);
    std::cout << prompt << std::flush;
    const InputResult result = readBoundedLine(std::cin, input, maxLength);
    if (interrupted() || result == InputResult::endOfInput) return false;
    if (input.empty()) return true;
    if (result == InputResult::tooLong || !isValidField(input, maxLength, required))
    {
        std::cout << "Invalid field. Maximum length: " << maxLength
            << " bytes. Control characters are not allowed.";
        if (required) std::cout << " A non-blank value is required.";
        std::cout << '\n';
        return false;
    }
    value.swap(input);
    changed = true;
    return true;
}

void editEntry(std::deque<Entry>& entries, const VaultKey& vaultKey, VaultSnapshot& snapshot)
{
    if (!authorizeRecords(snapshot.owner, "entry_edit")) return;
    if (entries.empty())
    {
        std::cout << "There are no entries in this session.\n";
        return;
    }
    const std::size_t number = readEntryNumber("edit", entries.size());
    if (number == 0) return;
    Entry& current = entries[number - 1];

    Entry edited;
    edited.service = current.service;
    edited.website = current.website;
    edited.username = current.username;
    edited.password = current.password;
    edited.notes = current.notes;

    std::cout << "Editing " << current.service << ". Press Enter to keep a value.\n";
    bool changed = false;
    if (!readEditedField("Service name: ", edited.service, MAX_SERVICE_LENGTH, true, changed) ||
        !readEditedField("Website: ", edited.website, MAX_WEBSITE_LENGTH, false, changed) ||
        !readEditedField("Username: ", edited.username, MAX_USERNAME_LENGTH, false, changed))
    {
        if (!interrupted()) logEvent("entry_edit", "input_rejected");
        return;
    }

    std::string newPassword;
    StringWiper wipePassword(newPassword);
    readPassword("New password (Enter keeps the current one): ", newPassword);
    if (!std::cin.good() || interrupted()) return;
    if (!newPassword.empty())
    {
        if (!isValidPassword(newPassword))
        {
            std::cout << "The entry password must contain 1-256 printable ASCII characters, not only spaces.\n";
            logEvent("entry_edit", "validation_failed");
            return;
        }
        edited.password.swap(newPassword);
        changed = true;
    }

    if (!readEditedField("Notes: ", edited.notes, MAX_NOTES_LENGTH, false, changed))
    {
        if (!interrupted()) logEvent("entry_edit", "input_rejected");
        return;
    }
    if (!changed)
    {
        std::cout << "Nothing was changed.\n";
        return;
    }

    current.swapFields(edited);
    if (!saveVault(entries, vaultKey, snapshot))
    {
        current.swapFields(edited);
        std::cout << "Could not save the change. The entry was not changed.\n";
        logEvent("entry_edit", "save_failed");
        return;
    }
    std::cout << "Entry updated and saved to the encrypted vault.\n";
    logEvent("entry_edit", "success");
}

void deleteEntry(std::deque<Entry>& entries, const VaultKey& vaultKey, VaultSnapshot& snapshot)
{
    if (!authorizeRecords(snapshot.owner, "entry_delete")) return;
    if (entries.empty())
    {
        std::cout << "There are no entries in this session.\n";
        return;
    }
    const std::size_t number = readEntryNumber("delete", entries.size());
    if (number == 0) return;
    if (!confirmWithYes("Delete the entry for " + entries[number - 1].service + "?"))
    {
        std::cout << "Delete cancelled.\n";
        return;
    }

    const auto position = entries.begin() + static_cast<std::ptrdiff_t>(number - 1);
    Entry removed(std::move(*position));
    entries.erase(position);
    if (!saveVault(entries, vaultKey, snapshot))
    {
        entries.emplace(entries.begin() + static_cast<std::ptrdiff_t>(number - 1), std::move(removed));
        std::cout << "Could not save the change. The entry was not deleted.\n";
        logEvent("entry_delete", "save_failed");
        return;
    }
    std::cout << "Entry deleted and the encrypted vault saved.\n";
    logEvent("entry_delete", "success");
}

void copyPassword(const std::deque<Entry>& entries, const VaultSnapshot& snapshot, ClipboardGuard& clipboard)
{
    if (!authorizeRecords(snapshot.owner, "password_copy")) return;
    if (entries.empty())
    {
        std::cout << "There are no entries in this session.\n";
        return;
    }
    const std::size_t number = readEntryNumber("copy", entries.size());
    if (number == 0) return;
    const Entry& entry = entries[number - 1];
    if (!isValidPassword(entry.password))
    {
        std::cout << "Could not copy this password.\n";
        logEvent("password_copy", "invalid_record");
        return;
    }
    if (!clipboard.copy(entry.password))
    {
        std::cout << "Could not use the clipboard. The password was not shown or copied.\n";
        logEvent("password_copy", "clipboard_unavailable");
        return;
    }
    std::cout << "Password for " << entry.service << " copied to the clipboard. It will be cleared in "
        << CLIPBOARD_CLEAR_SECONDS << " seconds.\n";
    logEvent("password_copy", "success");
}

int runManager()
{
    if (sodium_init() < 0)
    {
        std::cout << "Could not start the crypto library.\n";
        return 1;
    }

    const bool hardened = hardenProcess();
    ConsoleControl console;
    VaultDirectoryLock directoryLock;
    if (!console.start() || !directoryLock.acquire())
    {
        std::cout << "Could not start a session. Check for another open instance or an unavailable vault directory.\n";
        return 1;
    }
    logEvent("session_start", "success");
    if (!hardened) logEvent("process_hardening", "partial");
    VaultSnapshot snapshot;
    std::cout << "Crypto library is ready.\n";
    bool userWantsToExit = false;
    bool vaultUnlocked = false;

    {
        VaultKey sessionVaultKey{};
        VaultKeyWiper wipeOnExit(sessionVaultKey);
        MemoryLock lockSessionKey(sessionVaultKey, sizeof sessionVaultKey);
        if (!lockSessionKey.locked()) logEvent("memory_lock", "unavailable");
        ClipboardGuard clipboard;

        bool vaultFileExists = std::filesystem::exists("vault.json");
        std::deque<Entry> entries;
        std::string menuChoice;

        while (!userWantsToExit && !interrupted() && std::cin)
        {
            if (vaultFileExists == false)
            {
                std::cout << "\nNo vault file found\n";
                std::cout << "1. Create vault\n";
                std::cout << "2. Exit\n";
                std::cout << "Choose an option: ";

                if (readBoundedLine(std::cin, menuChoice, 1) == InputResult::endOfInput || interrupted())
                {
                    break;
                }

                if (menuChoice == "1")
                {
                    const auto account = auditActor();
                    if (!knownAccount(account))
                    {
                        std::cout << "Could not identify the vault owner.\n";
                        logEvent("vault_create", "access_denied");
                        continue;
                    }
                    const auto binding = ownerBinding(account);
                    std::string masterPassword;
                    StringWiper wipeMaster(masterPassword);
                    readPassword("Choose a master password: ", masterPassword);
                    if (!std::cin.good() || interrupted())
                    {
                        break;
                    }

                    if (!isValidNewMasterPassword(masterPassword))
                    {
                        clearString(masterPassword);
                        std::cout << "Use 15-256 printable ASCII characters. Avoid repeated characters, sequences "
                            "such as 12345 or qwerty, and common words. A long, unique passphrase is recommended.\n";
                        logEvent("vault_create", "validation_failed");
                        continue;
                    }

                    std::string confirmPassword;
                    StringWiper wipeConfirmation(confirmPassword);
                    readPassword("Type it again: ", confirmPassword);
                    if (!std::cin.good() || interrupted())
                    {
                        break;
                    }

                    bool passwordsMatch = masterPassword == confirmPassword;
                    clearString(confirmPassword);
                    if (!passwordsMatch)
                    {
                        logEvent("vault_create", "confirmation_failed");
                        std::cout << "The passwords do not match. No vault was created.\n";
                    }
                    else
                    {
                        unsigned char salt[crypto_pwhash_SALTBYTES];
                        VaultKey vaultKey{};
                        VaultKeyWiper wipeAfterCreate(vaultKey);
                        MemoryLock lockCreateKey(vaultKey, sizeof vaultKey);

                        randombytes_buf(salt, sizeof salt);

                        std::string nonceHex;
                        std::string encryptedHex;
                        if (!deriveVaultKey(masterPassword, salt, CURRENT_VAULT_VERSION, vaultKey))
                        {
                            std::cout << "Could not create the encryption key.\n";
                        }
                        else if (!sealVaultData("[]", vaultKey, binding, nonceHex, encryptedHex))
                        {
                            std::cout << "Could not encrypt the vault data.\n";
                        }
                        else
                        {
                            const std::string data = formatVaultFile(toHex(salt, sizeof salt),
                                nonceHex.c_str(), encryptedHex.c_str(), CURRENT_VAULT_VERSION);
                            if (!interrupted() && writeNewFile("vault.json", data))
                            {
                                vaultFileExists = true;
                                UnlockLimit freshLimit;
                                if (!freshLimit.reset()) logEvent("unlock_limit", "write_failed");
                                std::cout << "Encrypted vault saved to vault.json.\n";
                                logEvent("vault_create", "success");
                            }
                            else
                            {
                                std::cout << "Could not create the vault file.\n";
                                logEvent("vault_create", "write_failed");
                            }
                        }
                    }
                }
                else if (menuChoice == "2")
                {
                    userWantsToExit = true;
                }
                else
                {
                    std::cout << "Please choose 1 or 2.\n";
                }
            }
            else if (vaultUnlocked == true)
            {
                std::cout << "\nVault is unlocked.\n";
                std::cout << "1. Add entry\n";
                std::cout << "2. View entries\n";
                std::cout << "3. Edit entry\n";
                std::cout << "4. Delete entry\n";
                std::cout << "5. Copy a password\n";
                std::cout << "6. Lock vault\n";
                std::cout << "7. Exit\n";
                std::cout << "Choose an option: ";

                if (readBoundedLine(std::cin, menuChoice, 1) == InputResult::endOfInput || interrupted())
                {
                    break;
                }

                if (menuChoice == "1")
                {
                    addEntry(entries, sessionVaultKey, snapshot);
                }
                else if (menuChoice == "2")
                {
                    viewEntries(entries, snapshot);
                }
                else if (menuChoice == "3")
                {
                    editEntry(entries, sessionVaultKey, snapshot);
                }
                else if (menuChoice == "4")
                {
                    deleteEntry(entries, sessionVaultKey, snapshot);
                }
                else if (menuChoice == "5")
                {
                    copyPassword(entries, snapshot, clipboard);
                }
                else if (menuChoice == "6")
                {
                    clipboard.clearNow();
                    entries.clear();

                    sodium_memzero(
                        sessionVaultKey,
                        sizeof sessionVaultKey);

                    snapshot = {};
                    vaultUnlocked = false;
                    std::cout << "Vault locked.\n";
                    logEvent("vault_lock", "success");
                }
                else if (menuChoice == "7")
                {
                    userWantsToExit = true;
                }
                else
                {
                    std::cout << "Please choose 1 to 7.\n";
                }
            }
            else
            {
                std::cout << "\nVault is locked\n";
                std::cout << "1. Unlock vault\n";
                std::cout << "2. Exit\n";
                std::cout << "Choose an option: ";

                if (readBoundedLine(std::cin, menuChoice, 1) == InputResult::endOfInput || interrupted())
                {
                    break;
                }

                if (menuChoice == "1")
                {
                    UnlockLimit limit;
                    const auto now = std::time(nullptr);
                    if (now < 0 || !limit.load())
                    {
                        std::cout << "Could not check the unlock limit. The vault stays locked.\n";
                        logEvent("vault_unlock", "state_error");
                        continue;
                    }
                    if (limit.missing)
                    {
                        logEvent("vault_unlock", "counter_missing");
                        if (!limit.lockBecauseMissing(now))
                        {
                            std::cout << "Could not check the unlock limit. The vault stays locked.\n";
                            logEvent("vault_unlock", "state_error");
                            continue;
                        }
                        std::cout << "The unlock history is missing. Try again in "
                            << limit.blockedUntil - now << " seconds.\n";
                        continue;
                    }
                    if (limit.blocked(now))
                    {
                        std::cout << "Too many attempts. Try again in "
                            << limit.blockedUntil - now << " seconds.\n";
                        logEvent("vault_unlock", "rate_limited");
                        continue;
                    }
                    std::string enteredMasterPassword;
                    StringWiper wipeMaster(enteredMasterPassword);
                    readPassword("Enter your master password: ", enteredMasterPassword);

                    if (!std::cin.good() || interrupted())
                    {
                        break;
                    }

                    const auto submitted = std::time(nullptr);
                    if (submitted < 0 || !limit.reserve(submitted))
                    {
                        std::cout << "Could not record the attempt. The vault stays locked.\n";
                        logEvent("vault_unlock", "state_error");
                        continue;
                    }
                    if (!isValidPassword(enteredMasterPassword))
                    {
                        std::cout << "Enter a non-blank master password of at most 256 printable ASCII characters.\n";
                        logEvent("vault_unlock", "validation_failed");
                        continue;
                    }

                    if (unlockVault(enteredMasterPassword, sessionVaultKey, entries, snapshot))
                    {
                        if (interrupted() || !limit.reset())
                        {
                            entries.clear();
                            sodium_memzero(sessionVaultKey, sizeof sessionVaultKey);
                            snapshot = {};
                            std::cout << "Could not complete the unlock. The vault stays locked.\n";
                            logEvent("vault_unlock", "incomplete");
                            continue;
                        }
                        vaultUnlocked = true;
                        std::cout << "Vault unlocked successfully.\n";
                        logEvent("vault_unlock", "success");
                    }
                    else
                    {
                        logEvent("vault_unlock", "failure");
                    }
                }
                else if (menuChoice == "2")
                {
                    userWantsToExit = true;
                }
                else
                {
                    std::cout << "Please choose 1 or 2.\n";
                }
            }
        }
    }
    logEvent("session_end", interrupted() ? "interrupted" : "success");
    std::cout << "Program ended.\n";
    return 0;
}

int main()
{
    try
    {
        return runManager();
    }
    catch (const std::exception&)
    {
        std::cerr << "Could not continue the session.\n";
        return 1;
    }
}
