# Password Manager

A small command-line password manager written in C++. It stores account entries in a local encrypted vault.

## Current features

- Create a vault with a master password and confirmation.
- Hide the master password and entry passwords while they are typed.
- Unlock and lock the vault with the master password.
- Add entries containing a service, website, username, password, and notes.
- View saved entries while keeping their passwords hidden.
- Save entries in `vault.json` in encrypted form and load them after unlocking the vault.
- Reject an incorrect master password or damaged encrypted data.

The vault key is derived from the master password using Argon2id. The entry data is encrypted with XChaCha20-Poly1305 using a new random nonce when the vault is saved. The master password is not stored in the vault file.

## Requirements

- Windows and Visual Studio with the **Desktop development with C++** workload.
- vcpkg and the libsodium package for 64-bit Windows.

The program uses `conio.h` to hide typed passwords, so this version is intended for Windows.

## Build and run in Visual Studio

1. Install vcpkg if it is not already installed. Follow the official vcpkg setup instructions and note the folder where you installed it.
2. Open a terminal in that vcpkg folder and run:

   ```powershell
   .\vcpkg.exe install libsodium:x64-windows
   .\vcpkg.exe integrate install
   ```

3. Close and reopen Visual Studio if it was already open.
4. Open `secure-programming.sln`.
5. Select **Debug** and **x64** in the Visual Studio toolbar.
6. Build with **Build → Build Solution**.
7. Run with **Debug → Start Without Debugging** (or press `Ctrl+F5`).

The project is configured for C++17 in the Debug x64 configuration. If Visual Studio still cannot find `sodium.h`, check that the `libsodium:x64-windows` package installed successfully and that vcpkg integration completed.

## First use and basic test

1. Choose **Create vault** and set a master password.
2. Unlock the vault, add a test entry, and lock the vault.
3. Close and reopen the program, unlock the vault, and view the entry.
4. Open `vault.json` in a text editor. The service, username, password, and notes should not appear as readable text.
5. Try an incorrect master password; the vault should remain locked.

`vault.json` is created in the program's current working directory. Keep your own vault file private and do not commit it to Git or include it in a project submission. Add `vault.json` to `.gitignore` so it is not accidentally committed.

## Current limits

This checkpoint version supports adding and viewing entries. It does not yet support editing, deleting, searching, revealing a saved password, generating passwords, or automatically locking after inactivity. It is a course project and is not intended to replace a professionally reviewed password manager.

## Project files

- `main.cpp` — the C++ program.
- `pseudocode` — the planned program flow.
- `Use-cases` — user and misuse cases.
- `threat_model_passmanager.md` — security threats and planned protections.
- `vault_format_cryptographic_scheme` — description of the vault format and encryption design.
- `PassManager.drawio` and `PassManager.drawio.png` — architecture diagram and its image.
