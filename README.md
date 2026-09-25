# Password Manager
## Project scope
The application will be a small local command-line (potentially GUI) password manager for one user. It will store login entries in an encrypted vault.

The final version will support:
1. create a vault and set a master password;
2. unlock and lock the vault;
3. add, view, edit, delete, and search entries;
4. generate a strong random password;
5. save and load the encrypted vault.

## Project status

This repository presents a conceptual design for a password manager.
The planned functionality and program flow are described using
pseudocode. 

I will make my best effort to use C++ for this project. 
However, I graduated with a bachelor’s degree in Information Technology in 2023, rather than Computer Science, 
and I have limited experience with programming and C++. I have not written much code since graduating.

My main goal is to understand how to design and write secure code. 
Because my programming experience is limited, I may use pseudocode to explain the intended logic where 
I am unable to implement the functionality correctly in C++. 
Whenever possible, I will implement the functionality in C++ and use pseudocode 
only to describe parts that I cannot yet implement.

## Planned CLI commands
The planned command-line menu is:
```text
1. Create vault
2. Unlock vault
3. Add entry
4. View or search entries
5. Edit entry
6. Delete entry
7. Generate password
8. Lock vault
9. Save and exit
```
The exact menu may change during implementation, but these commands describe the intended first version.

## Security scope
This project will use well-tested cryptographic library functions. 
**Planned choices:**
1. password-based key derivation: Argon2id, or PBKDF2-HMAC-SHA-256 if the selected library does not provide Argon2id;
2. authenticated encryption: AES-256-GCM or ChaCha20-Poly1305;
3. a unique random salt for the vault and a fresh random nonce for every encryption operation;
4. no plaintext passwords in the storage file, logs, or error messages!

## Planned build and run commands
Create a virtual environment:
```bash
cmake -S . -B build
cmake --build build
./build/password_manager
```

On Windows, the executable may be located at `build\Debug\password_manager.exe` after building with Visual Studio.
The current executable is only a project skeleton and prints a short status message. The features listed above are planned functionality. They will be implemented incrementally, starting with the data model and file handling before adding cryptography through a library.
