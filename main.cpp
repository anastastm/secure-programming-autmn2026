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

int main()
{
    if (sodium_init() < 0)
    {
        std::cout << "Could not start the crypto library.\n";
        return 1;
    }

    std::cout << "Crypto library is ready.\n";
    bool userWantsToExit = false;
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

                std::cout << "Password entered.\n";
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
    return 0;
}
