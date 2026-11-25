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
- Require 15-256 printable ASCII characters for a new master password and reject guessable ones (repeated characters or blocks, sequences such as `12345` or `qwerty`, and common words such as `password` with a short remainder).
- Reject oversized fields and ASCII control characters, and exit cleanly when input ends.

The vault key is derived from the master password using Argon2id ("moderate" cost, about 256 MiB per guess, for new version 3 vaults). Entry data is encrypted with XChaCha20-Poly1305 using a fresh random nonce when the vault is saved. The master password is not stored in the vault file.

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
| New master password | 15-256 printable ASCII characters, not guessable (see below) | Yes, not only spaces |
| Existing master password at unlock | 1-256 printable ASCII characters | Yes, not only spaces |
| Entry password | 1-256 printable ASCII characters | Yes, not only spaces |
| Service | 100 bytes | Yes, not only spaces |
| Website | 2048 bytes | No |
| Username | 256 bytes | No |
| Notes | 2048 bytes | No |

The stronger rules apply only when creating a vault. A new master password is rejected when it has fewer than 5 different characters, is one block repeated (`passwordpassword`), is a run of an alphabet, digit or keyboard sequence (`123456789012345`, `qwertyuiopasdfgh`), or consists of a common word (also written as `P@ssw0rd`) plus a remainder that is shorter than 10 characters, has fewer than 5 different characters, or is a sequence. Existing vaults with shorter master passwords can still be unlocked. These rules catch obvious choices only; they do not replace a full compromised-password list. Use a long, unique passphrase.

Passwords are preserved exactly, including spaces. Unsupported characters reject the whole password attempt instead of silently changing it. Password input supports printable ASCII only. Other fields retain non-ASCII bytes; complete Unicode validation is not implemented. Field limits count bytes, not Unicode characters. ASCII controls (including tabs, newlines, NUL, and DEL) are rejected in fields. Quotes and backslashes are allowed and escaped by the existing record serialization. Website values are stored as text, never opened or executed, so they are not restricted to a URL scheme.

On unlock, each saved record must contain five quoted fields. Only escaped quotes and backslashes are accepted. Each field is checked against its byte limit, and a malformed record rejects the entire load.

An invalid field cancels adding that entry. Oversized text lines are drained before the next prompt, and their truncated prefixes are discarded. On EOF or an input-stream failure, the current operation is cancelled and the normal exit path clears session entries and the key. During hidden password input, Ctrl+D on Linux and Ctrl+Z on Windows request this exit. On Linux, Ctrl+C, Ctrl+\\, `kill` (SIGTERM) and closing the terminal (SIGHUP) all take the normal exit path: the key and entries are wiped, the terminal echo is restored and `session_end` is logged as `interrupted`. Ctrl+Z (suspend) is ignored, so the program is never paused with the terminal in hidden-input mode. On Windows, Ctrl+C, Ctrl+Break and closing the console window take the same path. `kill -9` or a forced end task cannot be caught by any program and may bypass cleanup.

## Vault ownership

Each vault belongs to one local OS account. Unlock requires the master password and the same account identifier used at creation (Linux UID or Windows SID). Add, view, reveal, and save check the account again inside the operation. Run the program in a private directory for each vault.

Version 1 vaults predate account binding. Open the original file under its filesystem owner and enter its existing master password. Viewing leaves the file at version 1. The next successful save writes version 2. Keep a private backup before upgrading if you need to use the older program. A version 2 vault depends on its original account identifier, so moving it to a different account or operating system requires a separate transfer feature. Local UIDs can repeat on different computers.

If you choose option 5, the selected password is printed on the terminal and can remain in its scrollback. The ordinary list masks all passwords.

## Memory protection

The session key is locked in RAM with `sodium_mlock`, so it is not written to swap, and it is zeroed when the vault locks or the program ends. On Linux the program also disables core dumps and marks itself non-dumpable, so a crash dump or another process of the same user attaching a debugger cannot read the key. Passwords and decrypted entries are wiped from their buffers after use. If the OS refuses to lock memory, the program continues and logs `memory_lock/unavailable`.

## Unlock limit, integrity, and audit history

Five unsuccessful submissions trigger a cooldown. Each further lockout doubles it: 60 seconds, 2 minutes, 4 minutes and so on, up to 1 hour. The fifth submission may still succeed. A successful unlock resets the count and the lockout level. A blank or otherwise invalid submission counts at unlock. Canceling at the prompt before submitting a password costs no attempt. The program reserves each submitted attempt in `vault.attempts` before checking it, so closing and reopening the program (even with `kill -9`) preserves the count. The counter is created with the vault. If it is later missing while the vault exists, the program treats that as tampering and starts a lockout instead of granting new attempts. A corrupt or unwritable counter leaves the vault locked. Counter files from the previous checkpoint (two numbers) are still read. The OS lock on `vault.lock` allows one application instance per vault directory and releases when the process exits.

Keep the vault directory private to your OS account. The cooldown limits guessing through the application only. Someone who can write to the vault directory can still forge the counter, or copy `vault.json` and guess offline; against that, the protection is the Argon2id cost and a strong master password. Someone who controls the system clock can also shorten the cooldown. Each launch starts locked. Vault creation requires a new master passphrase and confirmation, and the application reads passwords interactively. It has no password setting in an environment file.

Unlock checks the version, required fields, hex encoding and authentication tag before accepting records. Save compares the current file with the encrypted bytes authenticated at unlock and retains the original salt. A changed file causes the pending add to be discarded. Successful saves use a new temporary file in the vault directory and rename it into place. Another process with write access can still delete or replace files. Putting back an older, correctly authenticated copy of `vault.json` (a rollback) is not detected: entries added since that copy disappear. Detecting this would need storage that the same OS account cannot roll back.

`vault.audit.log` contains JSON lines with UTC time, OS account identifier, action, outcome and a link to the previous line. For example:

```json
{"timestamp":"2026-11-22T08:30:00Z","actor":"uid-1000","event":"vault_unlock","result":"rate_limited","prev":"3f9c...e1"}
```

`prev` is the BLAKE2b hash of the line before it (the first line uses 64 zeros), so the lines form a hash chain. When a session starts, the program checks the whole chain. If a line was deleted, edited, reordered or cut off, the program shows a warning, keeps the old file as `vault.audit.log.unverified-<UTC time>` for investigation, and starts a new log whose first event is `audit_log/integrity_failed`. A log from the previous checkpoint has no links, so it is kept the same way on the first start.

Windows uses the account SID. Linux uses the numeric user ID and creates the audit log with owner-only permissions. Windows files inherit directory permissions. Events are not shown on the screen; only if the log file cannot be written is the event printed to standard error. Passwords, usernames stored in entries, and other record contents are excluded. The chain has no secret key, so the account owner could rebuild the whole log consistently; it detects careless edits and deleted lines, not a careful rewrite by the same account.

Logged events: `session_start`, `session_end`, `vault_create`, `vault_unlock`, `vault_lock`, `vault_save`, `entry_add`, `entry_view`, `password_reveal`, `audit_log`, `unlock_limit`, `memory_lock` and `process_hardening`, each with a fixed result label such as `success`, `failure`, `rate_limited`, `counter_missing`, `access_denied` or `interrupted`.

## Tests

The tests use libsodium and the C++ standard library; no test framework is required.

After configuring and building with the commands above, run:

```sh
ctest --test-dir build --output-on-failure
```

For a Windows multi-configuration build, run:

```powershell
ctest --test-dir build -C Debug --output-on-failure
```

CTest runs four suites:

- `input_validation`: field and password limits, every ASCII control character, oversized lines, EOF, and weak master passwords.
- `secret_cleanup`: key and password wiping on early return and exceptions, memory locking, and stored-record validation.
- `security_controls`: vault file format, unlock counter persistence, escalating cooldowns, a deleted or forged counter, and audit-log chain verification and tamper handling.
- `vault_crypto`: key derivation, encryption and decryption round trip, wrong password, another account, fresh nonce per save, and changed ciphertext, tag, nonce or length.

The optional Linux terminal suite uses Python 3 and `pexpect` (`pip install pexpect`). It launches the real application in a temporary directory and checks weak passwords, restart behavior, 20 wrong passwords, Ctrl+C, Ctrl+\\, SIGTERM, SIGHUP and Ctrl+Z, that log events stay off the screen, a deleted counter, vault and audit-log tampering, ownership and password reveal.

```sh
python3 tests/terminal_security_tests.py ./build/password_manager
```

## Current limits

This checkpoint supports adding, listing, and explicitly revealing entries. It does not yet support editing, deleting, searching, generating passwords, or automatically locking after inactivity, and it does not detect a rollback to an older vault file. It is a course project and is not intended to replace a professionally reviewed password manager.
