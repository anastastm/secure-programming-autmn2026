#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <sodium.h>
#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstddef>
#include <system_error>

constexpr std::size_t MAX_PASSWORD_LENGTH = 256;

constexpr unsigned long long MAX_VAULT_FILE_SIZE =
16ULL * 1024ULL * 1024ULL;

bool isVaultFileSizeAllowed(const std::filesystem::path& path)
{
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    return !error && size <= MAX_VAULT_FILE_SIZE;
}

bool isValidField(
    const std::string& value,
    std::size_t maxLength,
    bool required)
{
    if ((required && value.empty()) || value.size() > maxLength)
    {
        return false;
    }

    for (unsigned char character : value)
    {
        if (character < 32 || character == 127)
        {
            return false;
        }
    }

    return true;
}

void logEvent(const char* event, const char* result)
{
    std::clog << "{\"event\":\"" << event
        << "\",\"result\":\"" << result << "\"}\n";
}

struct Entry
{
    std::string service;
    std::string website;
    std::string username;
    std::string password;
    std::string notes;
};

void clearString(std::string& value)
{
    if (!value.empty())
    {
        sodium_memzero(value.data(), value.size());
        value.clear();
    }
}

void clearEntry(Entry& entry)
{
    clearString(entry.service);
    clearString(entry.website);
    clearString(entry.username);
    clearString(entry.password);
    clearString(entry.notes);
}

void wipeEntries(std::vector<Entry>& entries)
{
    for (Entry& entry : entries)
    {
        clearEntry(entry);
    }

    entries.clear();
}

std::string readPassword(const std::string& prompt)
{
    std::string password;
    bool tooLong = false;
    std::cout << prompt << std::flush;

#ifndef _WIN32
    termios originalSettings{};
    if (!isatty(STDIN_FILENO) || tcgetattr(STDIN_FILENO, &originalSettings) != 0)
    {
        std::cout << "Password input requires an interactive terminal.\n";
        return password;
    }

    termios hiddenSettings = originalSettings;
    hiddenSettings.c_lflag &= static_cast<tcflag_t>(~(ECHO | ICANON));
    hiddenSettings.c_cc[VMIN] = 1;
    hiddenSettings.c_cc[VTIME] = 0;

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &hiddenSettings) != 0)
    {
        std::cout << "Could not configure hidden password input.\n";
        return password;
    }
#endif

    while (true)
    {
#ifdef _WIN32
        int key = _getch();
#else
        int key = std::cin.get();
#endif
        if (key == EOF)
        {
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
                password.pop_back();
                std::cout << "\b \b" << std::flush;
            }
        }
#ifdef _WIN32
        else if (key == 0 || key == 224)
        {
            _getch(); // Consume the second byte of a Windows special key.
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
    }

#ifndef _WIN32
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &originalSettings);
#endif
    std::cout << '\n';

    if (tooLong)
    {
        clearString(password);
        std::cout << "Password is too long. Maximum length is 256 characters.\n";
        return {};
    }

    return password;
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

std::string serializeEntries(const std::vector<Entry>& entries)
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

bool parseEntries(
    const std::string& data,
    std::vector<Entry>& entries)
{
    std::vector<Entry> loadedEntries;

    if (data == "[]")
    {
        wipeEntries(entries);
        return true;
    }

    std::istringstream input(data);

    while (true)
    {
        Entry entry;

        if (!(input >> std::quoted(entry.service)))
        {
            if (input.eof())
            {
                break;
            }

            wipeEntries(loadedEntries);
            return false;
        }

        if (!(input >> std::quoted(entry.website)
            >> std::quoted(entry.username)
            >> std::quoted(entry.password)
            >> std::quoted(entry.notes)))
        {
            clearEntry(entry);
            wipeEntries(loadedEntries);
            return false;
        }

        if (!isValidField(entry.service, 100, true) ||
            !isValidField(entry.website, 2048, false) ||
            !isValidField(entry.username, 256, false) ||
            !isValidField(entry.notes, 2048, false) ||
            !isValidField(entry.password, MAX_PASSWORD_LENGTH, true))
        {
            clearEntry(entry);
            wipeEntries(loadedEntries);
            return false;
        }

        loadedEntries.push_back(entry);
        clearEntry(entry);
    }

    wipeEntries(entries);
    entries = loadedEntries;
    wipeEntries(loadedEntries);
    return true;
}

bool saveVault(
    const std::vector<Entry>& entries,
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

    if (plainData.empty() == false)
    {
        sodium_memzero(&plainData[0], plainData.size());
    }

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

bool unlockVault(
    const std::string& masterPassword,
    unsigned char vaultKey[],
    std::vector<Entry>& entries)
{
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

    if (crypto_pwhash(
        vaultKey,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
        masterPassword.c_str(),
        static_cast<unsigned long long>(masterPassword.size()),
        salt.data(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13) != 0)
    {
        sodium_memzero(
            vaultKey,
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        std::cout << "Could not create the encryption key.\n";
        return false;
    }

    std::vector<unsigned char> decryptedData(encryptedData.size());
    unsigned long long decryptedLength = 0;

    int decryptResult = crypto_aead_xchacha20poly1305_ietf_decrypt(
        decryptedData.data(),
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
        sodium_memzero(decryptedData.data(), decryptedData.size());
        sodium_memzero(
            vaultKey,
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

        std::cout << "Incorrect password, or the vault file is damaged.\n";
        return false;
    }

    std::string plainData(
        reinterpret_cast<const char*>(decryptedData.data()),
        static_cast<std::size_t>(decryptedLength));

    sodium_memzero(decryptedData.data(), decryptedData.size());

    if (parseEntries(plainData, entries) == false)
    {
        clearString(plainData);
        sodium_memzero(
            vaultKey,
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

        std::cout << "The decrypted vault data is invalid.\n";
        return false;
    }

    clearString(plainData);

    return true;
}

void addEntry(
    std::vector<Entry>& entries,
    const unsigned char vaultKey[])
{
    Entry entry;

    std::cout << "Service name: ";
    std::getline(std::cin, entry.service);

    std::cout << "Website: ";
    std::getline(std::cin, entry.website);

    std::cout << "Username: ";
    std::getline(std::cin, entry.username);

    entry.password = readPassword("Password: ");

    std::cout << "Notes: ";
    std::getline(std::cin, entry.notes);

    if (!isValidField(entry.service, 100, true) ||
        !isValidField(entry.website, 2048, false) ||
        !isValidField(entry.username, 256, false) ||
        !isValidField(entry.notes, 2048, false) ||
        !isValidField(entry.password, MAX_PASSWORD_LENGTH, true))
    {
        clearEntry(entry);
        std::cout << "Invalid entry. Check required fields, length limits, and control characters.\n";
        logEvent("entry_add", "validation_failed");
        return;
    }

    entries.push_back(entry);

    clearEntry(entry);

    if (!saveVault(entries, vaultKey))
    {
        clearEntry(entries.back());
        entries.pop_back();
        std::cout << "Could not save the entry. It was not added.\n";
        logEvent("entry_add", "save_failed");
        return;
    }
    std::cout << "Entry added and saved to the encrypted vault.\n";
    logEvent("entry_add", "success");
}

void viewEntries(const std::vector<Entry>& entries)
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

void clearEntries(std::vector<Entry>& entries)
{
    wipeEntries(entries);
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

    unsigned char sessionVaultKey[
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES] = {};

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
        std::vector<Entry> entries;
        std::string menuChoice;

        while (userWantsToExit == false)
        {
            if (vaultFileExists == false)
            {
                std::cout << "\nNo vault file found\n";
                std::cout << "1. Create vault\n";
                std::cout << "2. Exit\n";
                std::cout << "Choose an option: ";

                std::getline(std::cin, menuChoice);

                if (menuChoice == "1")
                {
                    std::string masterPassword = readPassword("Choose a master password: ");
                    std::string confirmPassword = readPassword("Type it again: ");

                    if (masterPassword.empty())
                    {
                        std::cout << "The password cannot be empty.\n";
                    }
                    else if (masterPassword != confirmPassword)
                    {
                        std::cout << "The passwords do not match. No vault was created.\n";
                    }
                    else
                    {
                        unsigned char salt[crypto_pwhash_SALTBYTES];
                        unsigned char vaultKey[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];

                        randombytes_buf(salt, sizeof salt);

                        int keyResult = crypto_pwhash(
                            vaultKey,
                            sizeof vaultKey,
                            masterPassword.c_str(),
                            static_cast<unsigned long long>(masterPassword.size()),
                            salt,
                            crypto_pwhash_OPSLIMIT_INTERACTIVE,
                            crypto_pwhash_MEMLIMIT_INTERACTIVE,
                            crypto_pwhash_ALG_ARGON2ID13
                        );

                        if (keyResult == 0)
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

                        sodium_memzero(vaultKey, sizeof vaultKey);
                    }
                    if (!masterPassword.empty())
                    {
                        clearString(masterPassword);
                    }

                    if (!confirmPassword.empty())
                    {
                        clearString(confirmPassword);
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

                std::getline(std::cin, menuChoice);

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
                    clearEntries(entries);

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

                std::getline(std::cin, menuChoice);

                if (menuChoice == "1")
                {
                    std::string enteredMasterPassword =
                        readPassword("Enter your master password: ");

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

                    if (enteredMasterPassword.empty() == false)
                    {
                        clearString(enteredMasterPassword);
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
        clearEntries(entries);
        sodium_memzero(sessionVaultKey, sizeof sessionVaultKey);
        return 0;
}
