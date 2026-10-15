#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <sodium.h>

struct Entry
{
    std::string service;
    std::string website;
    std::string username;
    std::string password;
    std::string notes;
};


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
                std::cout << "Creating the vault will be added next.\n";
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
                std::cout << "To be added.\n";
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
