# Password Manager

A small cross-platform command-line password manager written in C++. It stores account entries in a local encrypted vault.

## Features

- Create a vault with a master password and confirmation.
- Mask the master password and entry passwords as they are typed.
- Unlock and lock the vault with the master password.
- Add entries with a service, website, username, password, and notes.
- View a masked list, or use option 5 and confirm with `yes` to show one selected password on the terminal.
- Save entries in `vault.json` in encrypted form and load them after unlocking.
- Reject an incorrect master password or damaged encrypted data.
- Require 15-256 printable ASCII characters for a new master password; spaces are allowed, but a password cannot contain only spaces.
- Reject oversized fields and ASCII control characters, and exit cleanly when input ends.

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

## Input rules

| Field | Limit | Required |
| --- | --- | --- |
| New master password | 15-256 printable ASCII characters | Yes, not only spaces |
| Existing master password at unlock | 1-256 printable ASCII characters | Yes, not only spaces |
| Entry password | 1-256 printable ASCII characters | Yes, not only spaces |
| Service | 100 bytes | Yes, not only spaces |
| Website | 2048 bytes | No |
| Username | 256 bytes | No |
| Notes | 2048 bytes | No |

The stronger minimum applies when creating a vault. Existing vaults with shorter, non-blank master passwords can still be unlocked. Use a long, unique master passphrase; the length check alone cannot establish that a password is strong. The program does not yet check a compromised-password blocklist.

Passwords are preserved exactly, including spaces. Unsupported characters reject the whole password attempt instead of silently changing it. Password input supports printable ASCII only. Other fields retain non-ASCII bytes; complete Unicode validation is not implemented. Field limits count bytes, not Unicode characters. ASCII controls (including tabs, newlines, NUL, and DEL) are rejected in fields. Quotes and backslashes are allowed and escaped by the existing record serialization. Website values are stored as text, never opened or executed, so they are not restricted to a URL scheme.

On unlock, each saved record must contain five quoted fields. Only escaped quotes and backslashes are accepted. Each field is checked against its byte limit, and a malformed record rejects the entire load.

An invalid field cancels adding that entry. Oversized text lines are drained before the next prompt, and their truncated prefixes are discarded. On EOF or an input-stream failure, the current operation is cancelled and the normal exit path clears session entries and the key. During hidden password input, Ctrl+D on Linux and Ctrl+Z on Windows request this exit. Ctrl+C requests a normal session exit and cleanup. Forced process termination may bypass application cleanup.

## Vault ownership

Each vault belongs to one local OS account. Unlock requires the master password and the same account identifier used at creation (Linux UID or Windows SID). Add, view, reveal, and save check the account again inside the operation. Run the program in a private directory for each vault.

Version 1 vaults predate account binding. Open the original file under its filesystem owner and enter its existing master password. Viewing leaves the file at version 1. The next successful save writes version 2. Keep a private backup before upgrading if you need to use the older program. A version 2 vault depends on its original account identifier, so moving it to a different account or operating system requires a separate transfer feature. Local UIDs can repeat on different computers.

If you choose option 5, the selected password is printed on the terminal and can remain in its scrollback. The ordinary list masks all passwords.

## Unlock limit, integrity, and audit history

Five unsuccessful submissions trigger a 60-second cooldown. The fifth submission may still succeed. A successful unlock resets the count. A blank or otherwise invalid submission counts at unlock. Canceling at the prompt before submitting a password costs no attempt. The program reserves each submitted attempt in `vault.attempts` before checking it, so closing and reopening the program preserves the count. A corrupt or unwritable counter leaves the vault locked. The OS lock on `vault.lock` allows one application instance per vault directory and releases when the process exits.

Keep the vault directory private to your OS account. Someone with a copy of the vault can guess offline. Someone who controls its directory or the system clock can bypass the application cooldown. Each launch starts locked. Vault creation requires a new master passphrase and confirmation, and the application reads passwords interactively. It has no password setting in an environment file.

Unlock checks the version, required fields, hex encoding and authentication tag before accepting records. Save compares the current file with the encrypted bytes authenticated at unlock and retains the original salt. A changed file causes the pending add to be discarded. Successful saves use a new temporary file in the vault directory and rename it into place. Another process with write access can still delete or replace files. An older, correctly authenticated vault can pass verification when first opened.

`vault.audit.log` contains JSON lines with UTC time, OS account identifier, action and outcome. For example:

```json
{"timestamp":"2026-11-22T08:30:00Z","actor":"uid-1000","event":"vault_unlock","result":"rate_limited"}
```

Windows uses the account SID. Linux uses the numeric user ID and creates the audit log with owner-only permissions. Windows files inherit directory permissions. The app also writes events to standard error and reports audit-file failures there. Passwords, usernames stored in entries, and other record contents are excluded. This local log can be modified by its owner.

## Tests

The first test suite covers validation boundaries, every ASCII control character, password rules, oversized lines, EOF, and basic string cleanup. It uses libsodium and the C++ standard library; no test framework is required.

After configuring and building with the commands above, run:

```sh
ctest --test-dir build --output-on-failure
```

For a Windows multi-configuration build, run:

```powershell
ctest --test-dir build -C Debug --output-on-failure
```

CTest runs three suites: input validation, secret cleanup, and security controls. The security-controls suite uses a temporary directory and tests persistence, cooldown expiry, invalid state, and the version 1 file format.

The optional Linux terminal suite uses Python 3 and `pexpect`. It launches the real application in a temporary directory and checks restart behavior, interrupts, audit events, and tampering.

```sh
python3 tests/terminal_security_tests.py ./build/password_manager
```

## Current limits

This checkpoint supports adding, listing, and explicitly revealing entries. It does not yet support editing, deleting, searching, generating passwords, or automatically locking after inactivity. It is a course project and is not intended to replace a professionally reviewed password manager.
