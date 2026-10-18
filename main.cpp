#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <sodium.h>
#include <conio.h>

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
                    std::cout << "The passwords match.\n";
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
