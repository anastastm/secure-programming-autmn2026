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

This repository presents a conceptual design and an initial Python project skeleton. The planned functionality and program flow are described in the documentation and will be implemented incrementally.
I will make my best effort to use Python for this project.

However, I graduated with a bachelor’s degree in Information Technology in 2023, rather than Computer Science, and I have limited experience with programming and Python. I have not written much code since graduating.

My main goal is to understand how to design and write secure code. Because my programming experience is limited, I may use pseudocode to explain the intended logic where I am unable to implement the functionality correctly in Python. Whenever possible, I will implement the functionality in Python and use pseudocode only to describe parts that I cannot yet implement.

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
1. Argon2id through `argon2-cffi` for password-based key derivation;
2. AES-GCM through the `cryptography` library for authenticated encryption;
3. a unique random salt for the vault and a fresh random nonce for every encryption operation;
4. Python's `secrets` module for secure random password generation;
5. no plaintext passwords in the storage file, logs, or error messages.


## Planned build and run commands
Create a virtual environment:
```bash
python -m venv .venv
```
Activate it:
```bash
# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate
```
Install the dependencies:
```bash
pip install -r requirements.txt
```
Run the application:
```bash
python src/password_manager.py
```
The current executable is only a Python project skeleton and prints a short status message. The features listed above are planned functionality. They will be implemented incrementally, starting with the data model and file handling before adding cryptography through a library.
