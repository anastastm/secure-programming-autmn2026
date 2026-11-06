# Password Manager

A small cross-platform command-line password manager written in C++. It stores account entries in a local encrypted vault.

## Features

- Create a vault with a master password and confirmation.
- Mask the master password and entry passwords as they are typed.
- Unlock and lock the vault with the master password.
- Add entries with a service, website, username, password, and notes.
- View saved entries while keeping their passwords hidden.
- Save entries in `vault.json` in encrypted form and load them after unlocking.
- Reject an incorrect master password or damaged encrypted data.

The vault key is derived from the master password using Argon2id. Entry data is encrypted with XChaCha20-Poly1305 using a fresh random nonce when the vault is saved. The master password is not stored in the vault file.

## Requirements

- C++17 compiler.
- CMake 3.16 or later.
- libsodium.

### Linux

On Debian or Ubuntu, install the compiler, CMake, pkg-config, and libsodium development package:

```sh
sudo apt update
sudo apt install build-essential cmake pkg-config libsodium-dev
```

Build and run from this directory:

```sh
cmake -S . -B build
cmake --build build
./build/password_manager
```

### Windows

Install Visual Studio with the **Desktop development with C++** workload, CMake, and vcpkg. From a terminal in this project directory, configure using your vcpkg installation path:

```powershell
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake" -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build --config Debug
.\build\Debug\password_manager.exe
```

Replace `C:/path/to/vcpkg` with the directory where you installed vcpkg. The included `vcpkg.json` installs libsodium automatically when CMake configures the project. You can also open this folder in Visual Studio as a CMake project.

## First use and basic check

1. Choose **Create vault** and set a master password.
2. Unlock the vault, add an entry, and lock the vault.
3. Close and reopen the program, unlock the vault, and view the entry.
4. Open `vault.json` in a text editor. The service, username, password, and notes should not appear as readable text.
5. Try an incorrect master password; the vault should remain locked.

`vault.json` is created in the program's current working directory. Keep your vault file private and do not commit it to Git. The included `.gitignore` excludes it.

## Current limits

This checkpoint supports adding and viewing entries. It does not yet support editing, deleting, searching, revealing a saved password, generating passwords, or automatically locking after inactivity. It is a course project and is not intended to replace a professionally reviewed password manager.
