#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <sodium.h>
#include <conio.h>
#include <fstream>

struct Entry
{
    std::string service;
    std::string website;
    std::string username;
    std::string password;
    std::string notes;
};

std::string readPassword(const std::string& prompt)
{
    std::string password;

    std::cout << prompt;

    while (true)
    {
        int key = _getch();

        if (key == '\r')
        {
            std::cout << '\n';
            break;
        }
        else if (key == '\b')
        {
            if (password.empty() == false)
            {
                password.pop_back();
                std::cout << "\b \b";
            }
        }
        else if (key == 0 || key == 224)
        {
            _getch();
        }
        else if (key >= 32 && key <= 126)
        {
            password.push_back(static_cast<char>(key));
            std::cout << '*';
        }
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

bool unlockVault(
    const std::string& masterPassword,
    unsigned char vaultKey[])
{
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

    sodium_memzero(decryptedData.data(), decryptedData.size());

    if (decryptResult != 0)
    {
        sodium_memzero(
            vaultKey,
            crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        std::cout << "Incorrect password, or the vault file is dacmaged.\n";
        return false;
    }

    return true;
}

void addEntry(std::vector<Entry>& entries)
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

    if (entry.service.empty() || entry.password.empty())
    {
        std::cout << "Service name and password are required.\n";

        if (entry.password.empty() == false)
        {
            sodium_memzero(&entry.password[0], entry.password.size());
        }

        return;
    }

    entries.push_back(entry);
    std::cout << "Entry added for this session. It is not saved yet.\n";
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
    for (Entry& entry : entries)
    {
        if (entry.password.empty() == false)
        {
            sodium_memzero(&entry.password[0], entry.password.size());
        }
    }

    entries.clear();
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
                    addEntry(entries);
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

                    if (unlockVault(enteredMasterPassword, sessionVaultKey))
                    {
                        vaultUnlocked = true;
                        std::cout << "Vault unlocked successfully.\n";
                    }

                    if (enteredMasterPassword.empty() == false)
                    {
                        sodium_memzero(
                            &enteredMasterPassword[0],
                            enteredMasterPassword.size());
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
