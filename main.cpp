#include <iostream>
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

constexpr unsigned long long MAX_VAULT_FILE_SIZE =
16ULL * 1024ULL * 1024ULL;

bool isVaultFileSizeAllowed(const std::filesystem::path& path)
{
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    return !error && size <= MAX_VAULT_FILE_SIZE;
}

void logEvent(const char* event, const char* result)
{
    std::clog << "{\"event\":\"" << event
        << "\",\"result\":\"" << result << "\"}\n";
}

void readPassword(const char* prompt, std::string& password)
{
    clearString(password);
    bool tooLong = false;
    bool invalidCharacter = false;
    password.reserve(MAX_PASSWORD_LENGTH);
    std::cout << prompt << std::flush;

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

    while (true)
    {
#ifdef _WIN32
        int key = _getch();
#else
        int key = std::cin.get();
#endif
        if (key == EOF
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

bool readJsonStringField(
    const std::string& json,
    const std::string& field,
    std::string& value)
{
    std::string marker = "\"" + field + "\": \"";
    std::size_t valueStart = json.find(marker);

    if (valueStart == std::string::npos)
    {
        return false;
    }

    valueStart += marker.size();

    std::size_t valueEnd = json.find('"', valueStart);

    if (valueEnd == std::string::npos)
    {
        return false;
    }

    value = json.substr(valueStart, valueEnd - valueStart);
    return true;
}

bool saveVault(
    const std::deque<Entry>& entries,
    const unsigned char vaultKey[])
{
    if (!isVaultFileSizeAllowed("vault.json"))
    {
        std::cout << "The vault file is missing, too large, or unavailable.\n";
        return false;
    }

    std::ifstream existingFile("vault.json", std::ios::binary);

    if (!existingFile)
    {
        std::cout << "Could not open the existing vault file.\n";
        return false;
    }

    std::string vaultContents;
    std::string line;

    while (std::getline(existingFile, line))
    {
        vaultContents += line;
    }

    existingFile.close();

    std::string saltHex;

    if (vaultContents.find("\"version\": 1") == std::string::npos ||
        readJsonStringField(vaultContents, "salt", saltHex) == false ||
        saltHex.size() != crypto_pwhash_SALTBYTES * 2)
    {
        std::cout << "The vault file is not in the expected format.\n";
        return false;
    }

    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    std::size_t saltLength = 0;

    if (sodium_hex2bin(
        salt.data(),
        salt.size(),
        saltHex.c_str(),
        saltHex.size(),
        nullptr,
        &saltLength,
        nullptr) != 0 ||
        saltLength != salt.size())
    {
        std::cout << "The vault file contains an invalid salt.\n";
        return false;
    }

    std::string plainData = serializeEntries(entries);
    StringWiper wipePlainData(plainData);

    unsigned char nonce[
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    randombytes_buf(nonce, sizeof nonce);

    std::vector<unsigned char> encryptedData(
        plainData.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);

    unsigned long long encryptedLength = 0;

    int encryptResult = crypto_aead_xchacha20poly1305_ietf_encrypt(
        encryptedData.data(),
        &encryptedLength,
        reinterpret_cast<const unsigned char*>(plainData.data()),
        static_cast<unsigned long long>(plainData.size()),
        nullptr,
        0,
        nullptr,
        nonce,
        vaultKey);

    clearString(plainData);

    if (encryptResult != 0)
    {
        std::cout << "Could not encrypt the entries.\n";
        return false;
    }

    encryptedData.resize(static_cast<std::size_t>(encryptedLength));

    char nonceHex[
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES * 2 + 1];

    std::vector<char> encryptedHex(encryptedData.size() * 2 + 1);

    sodium_bin2hex(nonceHex, sizeof nonceHex, nonce, sizeof nonce);
    sodium_bin2hex(
        encryptedHex.data(),
        encryptedHex.size(),
        encryptedData.data(),
        encryptedData.size());

    if (encryptedHex.size() > MAX_VAULT_FILE_SIZE - 256)
    {
        std::cout << "The vault is too large to save.\n";
        return false;
    }

    const std::filesystem::path vaultPath = "vault.json";
    const std::filesystem::path tempPath = "vault.json.tmp";
    const std::filesystem::path backupPath = "vault.json.bak";

    std::ofstream vaultFile(
        tempPath,
        std::ios::binary | std::ios::trunc);

    if (!vaultFile)
    {
        std::cout << "Could not save the vault file.\n";
        return false;
    }

    vaultFile << "{\n"
        << "  \"version\": 1,\n"
        << "  \"salt\": \"" << saltHex << "\",\n"
        << "  \"nonce\": \"" << nonceHex << "\",\n"
        << "  \"encrypted_data\": \"" << encryptedHex.data() << "\"\n"
        << "}\n";

    vaultFile.close();

    if (vaultFile.fail())
    {
        std::error_code cleanupError;
        std::filesystem::remove(tempPath, cleanupError);
        std::cout << "Could not save the vault file.\n";
        return false;
    }

    std::error_code fileError;
    std::filesystem::remove(backupPath, fileError);

    if (fileError)
    {
        std::filesystem::remove(tempPath, fileError);
        std::cout << "Could not prepare the vault file for saving.\n";
        return false;
    }

    std::filesystem::rename(vaultPath, backupPath, fileError);

    if (fileError)
    {
        std::filesystem::remove(tempPath, fileError);
        std::cout << "Could not prepare the vault file for saving.\n";
        return false;
    }

    std::filesystem::rename(tempPath, vaultPath, fileError);

    if (fileError)
    {
        std::error_code restoreError;
        std::filesystem::rename(backupPath, vaultPath, restoreError);
        std::filesystem::remove(tempPath, fileError);
        std::cout << "Could not save the vault file.\n";
        return false;
    }

    std::filesystem::remove(backupPath, fileError);
    return true;
}

bool deriveVaultKey(std::string& masterPassword, const unsigned char salt[], VaultKey& key)
{
    int result = crypto_pwhash(
        key, sizeof key, masterPassword.c_str(),
        static_cast<unsigned long long>(masterPassword.size()), salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13);
    clearString(masterPassword);
    return result == 0;
}

bool unlockVault(
    std::string& masterPassword,
    VaultKey& vaultKey,
    std::deque<Entry>& entries)
{
    VaultKeyWiper wipeOnFailure(vaultKey);

    if (!isVaultFileSizeAllowed("vault.json"))
    {
        std::cout << "The vault file is missing, too large, or unavailable.\n";
        return false;
    }

    std::ifstream vaultFile("vault.json", std::ios::binary);

    if (!vaultFile)
    {
        std::cout << "Could not open the vault file.\n";
        return false;
    }

    std::string vaultContents;
    std::string line;

    while (std::getline(vaultFile, line))
    {
        vaultContents += line;
    }

    std::string saltHex;
    std::string nonceHex;
    std::string encryptedHex;

    if (vaultContents.find("\"version\": 1") == std::string::npos ||
        readJsonStringField(vaultContents, "salt", saltHex) == false ||
        readJsonStringField(vaultContents, "nonce", nonceHex) == false ||
        readJsonStringField(vaultContents, "encrypted_data", encryptedHex) == false)
    {
        std::cout << "The vault file is not in the expected format.\n";
        return false;
    }

    if (saltHex.size() != crypto_pwhash_SALTBYTES * 2 ||
        nonceHex.size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES * 2 ||
        encryptedHex.size() % 2 != 0 ||
        encryptedHex.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES * 2)
    {
        std::cout << "The vault file contains invalid data.\n";
        return false;
    }

    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    std::vector<unsigned char> nonce(
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    std::vector<unsigned char> encryptedData(encryptedHex.size() / 2);

    std::size_t saltLength = 0;
    std::size_t nonceLength = 0;
    std::size_t encryptedLength = 0;

    if (sodium_hex2bin(
        salt.data(), salt.size(), saltHex.c_str(), saltHex.size(),
        nullptr, &saltLength, nullptr) != 0 ||
        sodium_hex2bin(
            nonce.data(), nonce.size(), nonceHex.c_str(), nonceHex.size(),
            nullptr, &nonceLength, nullptr) != 0 ||
        sodium_hex2bin(
            encryptedData.data(), encryptedData.size(),
            encryptedHex.c_str(), encryptedHex.size(),
            nullptr, &encryptedLength, nullptr) != 0 ||
        saltLength != salt.size() ||
        nonceLength != nonce.size() ||
        encryptedLength != encryptedData.size())
    {
        std::cout << "The vault file contains invalid data.\n";
        return false;
    }

    if (!deriveVaultKey(masterPassword, salt.data(), vaultKey))
    {
        std::cout << "Could not create the encryption key.\n";
        return false;
    }

    std::string plainData(encryptedData.size(), '\0');
    StringWiper wipePlainData(plainData);
    unsigned long long decryptedLength = 0;

    int decryptResult = crypto_aead_xchacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char*>(plainData.data()),
        &decryptedLength,
        nullptr,
        encryptedData.data(),
        static_cast<unsigned long long>(encryptedData.size()),
        nullptr,
        0,
        nonce.data(),
        vaultKey);

    if (decryptResult != 0)
    {
        std::cout << "Incorrect password, or the vault file is damaged.\n";
        return false;
    }

    plainData.resize(static_cast<std::size_t>(decryptedLength));
    if (parseEntries(plainData, entries) == false)
    {
        std::cout << "The decrypted vault data is invalid.\n";
        return false;
    }

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

    if (result == InputResult::endOfInput)
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
    if (!readEntryField("Service name: ", entry.service, 100, true) ||
        !readEntryField("Website: ", entry.website, 2048, false) ||
        !readEntryField("Username: ", entry.username, 256, false))
    {
        logEvent("entry_add", "input_rejected");
        return false;
    }

    readPassword("Password: ", entry.password);

    if (!std::cin || !isValidPassword(entry.password))
    {
        std::cout << "The entry password must contain 1-256 printable ASCII characters, not only spaces.\n";
        logEvent("entry_add", "validation_failed");
        return false;
    }

    if (!readEntryField("Notes: ", entry.notes, 2048, false))
    {
        logEvent("entry_add", "input_rejected");
        return false;
    }

    return true;
}

void addEntry(std::deque<Entry>& entries, const unsigned char vaultKey[])
{
    if (!readNewEntry(entries.emplace_back()))
    {
        entries.pop_back();
        return;
    }

    if (!saveVault(entries, vaultKey))
    {
        entries.pop_back();
        std::cout << "Could not save the entry. It was not added.\n";
        logEvent("entry_add", "save_failed");
        return;
    }
    std::cout << "Entry added and saved to the encrypted vault.\n";
    logEvent("entry_add", "success");
}

void viewEntries(const std::deque<Entry>& entries)
{
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

int main()
{
    if (sodium_init() < 0)
    {
        std::cout << "Could not start the crypto library.\n";
        return 1;
    }

    std::cout << "Crypto library is ready.\n";
    bool userWantsToExit = false;
    bool vaultUnlocked = false;

    VaultKey sessionVaultKey{};
    VaultKeyWiper wipeOnExit(sessionVaultKey);

        if (!std::filesystem::exists("vault.json") &&
            std::filesystem::exists("vault.json.bak"))
        {
            std::error_code recoveryError;
            std::filesystem::rename(
                "vault.json.bak",
                "vault.json",
                recoveryError);

            if (recoveryError)
            {
                std::cout << "Could not recover the vault file.\n";
                return 1;
            }
        }

        bool vaultFileExists = std::filesystem::exists("vault.json");
        std::deque<Entry> entries;
        std::string menuChoice;

        while (userWantsToExit == false && std::cin)
        {
            if (vaultFileExists == false)
            {
                std::cout << "\nNo vault file found\n";
                std::cout << "1. Create vault\n";
                std::cout << "2. Exit\n";
                std::cout << "Choose an option: ";

                if (readBoundedLine(std::cin, menuChoice, 1) == InputResult::endOfInput)
                {
                    break;
                }

                if (menuChoice == "1")
                {
                    std::string masterPassword;
                    StringWiper wipeMaster(masterPassword);
                    readPassword("Choose a master password: ", masterPassword);
                    if (!std::cin)
                    {
                        break;
                    }

                    if (!isValidNewMasterPassword(masterPassword))
                    {
                        std::cout << "Use 15-256 printable ASCII characters, not only spaces. A long, unique passphrase is recommended.\n";
                        logEvent("vault_create", "validation_failed");
                        continue;
                    }

                    std::string confirmPassword;
                    StringWiper wipeConfirmation(confirmPassword);
                    readPassword("Type it again: ", confirmPassword);
                    if (!std::cin)
                    {
                        break;
                    }

                    bool passwordsMatch = masterPassword == confirmPassword;
                    clearString(confirmPassword);
                    if (!passwordsMatch)
                    {
                        std::cout << "The passwords do not match. No vault was created.\n";
                    }
                    else
                    {
                        unsigned char salt[crypto_pwhash_SALTBYTES];
                        VaultKey vaultKey{};
                        VaultKeyWiper wipeAfterCreate(vaultKey);

                        randombytes_buf(salt, sizeof salt);

                        if (deriveVaultKey(masterPassword, salt, vaultKey))
                        {
                            const std::string emptyVaultData = "[]";

                            unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
                            randombytes_buf(nonce, sizeof nonce);

                            std::vector<unsigned char> encryptedData(
                                emptyVaultData.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES
                            );

                            unsigned long long encryptedLength = 0;

                            int encryptResult = crypto_aead_xchacha20poly1305_ietf_encrypt(
                                encryptedData.data(),
                                &encryptedLength,
                                reinterpret_cast<const unsigned char*>(emptyVaultData.data()),
                                static_cast<unsigned long long>(emptyVaultData.size()),
                                nullptr,
                                0,
                                nullptr,
                                nonce,
                                vaultKey
                            );

                            if (encryptResult == 0)
                            {
                                encryptedData.resize(static_cast<std::size_t>(encryptedLength));

                                char saltHex[crypto_pwhash_SALTBYTES * 2 + 1];
                                char nonceHex[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES * 2 + 1];

                                std::vector<char> encryptedHex(encryptedData.size() * 2 + 1);

                                sodium_bin2hex(saltHex, sizeof saltHex, salt, sizeof salt);
                                sodium_bin2hex(nonceHex, sizeof nonceHex, nonce, sizeof nonce);
                                sodium_bin2hex(
                                    encryptedHex.data(),
                                    encryptedHex.size(),
                                    encryptedData.data(),
                                    encryptedData.size()
                                );

                                std::ofstream vaultFile("vault.json", std::ios::binary);

                                if (!vaultFile)
                                {
                                    std::cout << "Could not create the vault file.\n";
                                }
                                else
                                {
                                    vaultFile << "{\n"
                                        << "  \"version\": 1,\n"
                                        << "  \"salt\": \"" << saltHex << "\",\n"
                                        << "  \"nonce\": \"" << nonceHex << "\",\n"
                                        << "  \"encrypted_data\": \"" << encryptedHex.data() << "\"\n"
                                        << "}\n";

                                    vaultFile.close();

                                    if (vaultFile.fail())
                                    {
                                        std::cout << "Could not save the vault file.\n";
                                    }
                                    else
                                    {
                                        vaultFileExists = true;
                                        std::cout << "Encrypted vault saved to vault.json.\n";
                                        logEvent("vault_create", "success");
                                    }
                                }
                            }
                            else
                            {
                                std::cout << "Could not encrypt the vault data.\n";
                            }
                        }
                        else
                        {
                            std::cout << "Could not create the encryption key.\n";
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
                std::cout << "3. Lock vault\n";
                std::cout << "4. Exit\n";
                std::cout << "Choose an option: ";

                if (readBoundedLine(std::cin, menuChoice, 1) == InputResult::endOfInput)
                {
                    break;
                }

                if (menuChoice == "1")
                {
                    addEntry(entries, sessionVaultKey);
                }
                else if (menuChoice == "2")
                {
                    viewEntries(entries);
                }
                else if (menuChoice == "3")
                {
                    entries.clear();

                    sodium_memzero(
                        sessionVaultKey,
                        sizeof sessionVaultKey);

                    vaultUnlocked = false;
                    std::cout << "Vault locked.\n";
                    logEvent("vault_lock", "success");
                }
                else if (menuChoice == "4")
                {
                    userWantsToExit = true;
                }
                else
                {
                    std::cout << "Please choose 1, 2, 3, or 4.\n";
                }
            }
            else
            {
                std::cout << "\nVault is locked\n";
                std::cout << "1. Unlock vault\n";
                std::cout << "2. Exit\n";
                std::cout << "Choose an option: ";

                if (readBoundedLine(std::cin, menuChoice, 1) == InputResult::endOfInput)
                {
                    break;
                }

                if (menuChoice == "1")
                {
                    std::string enteredMasterPassword;
                    StringWiper wipeMaster(enteredMasterPassword);
                    readPassword("Enter your master password: ", enteredMasterPassword);

                    if (!std::cin)
                    {
                        break;
                    }

                    if (!isValidPassword(enteredMasterPassword))
                    {
                        std::cout << "Enter a non-blank master password of at most 256 printable ASCII characters.\n";
                        logEvent("vault_unlock", "validation_failed");
                        continue;
                    }

                    if (unlockVault(enteredMasterPassword, sessionVaultKey, entries))
                    {
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

        std::cout << "Program ended.\n";
        entries.clear();
        return 0;
}
