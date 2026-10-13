#include <iostream>
#include <string>

int main()
{
    bool userWantsToExit = false;
    std::string menuChoice;

    while (userWantsToExit == false)
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

    std::cout << "Program ended.\n";
    return 0;
}
