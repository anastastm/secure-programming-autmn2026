"""Linux CLI checks. Run with Python, pexpect, and the path to the built application."""
import json
import os
from pathlib import Path
import stat
import sys
import termios
from tempfile import TemporaryDirectory

import pexpect

APP = str(Path(sys.argv[1]).resolve())
MASTER = "demo-long-master-phrase"
ENTRY_PASSWORD = "demo-entry-password"


def start(folder):
    return pexpect.spawn(APP, cwd=folder, encoding="utf-8", timeout=8)


def answer(app, prompt, response):
    app.expect_exact(prompt)
    app.sendline(response)


def choose(app, option):
    answer(app, "Choose an option: ", str(option))


def finish(app, choice):
    choose(app, choice)
    app.expect_exact("Program ended.")
    app.expect(pexpect.EOF)
    app.close()
    assert app.exitstatus == 0


def unlock(app, password, result):
    choose(app, 1)
    answer(app, "Enter your master password: ", password)
    app.expect_exact(result)


def fill_entry(app):
    choose(app, 1)
    for label, value in [("Service name: ", "demo-service"), ("Website: ", ""),
                         ("Username: ", "demo-user"), ("Password: ", ENTRY_PASSWORD), ("Notes: ", "")]:
        answer(app, label, value)


def check_security(directory):
    folder = Path(directory)
    app = start(directory)
    choose(app, 1)
    answer(app, "Choose a master password: ", "")
    app.expect_exact("Use 15-256")
    assert not (folder / "vault.json").exists()
    choose(app, 1)
    answer(app, "Choose a master password: ", MASTER)
    answer(app, "Type it again: ", MASTER)
    app.expect_exact("Encrypted vault saved")
    other = start(directory)
    other.expect_exact("another open instance")
    other.expect(pexpect.EOF)
    other.close()
    assert other.exitstatus == 1

    unlock(app, "", "Enter a non-blank")
    unlock(app, "wrong", "Incorrect password")
    finish(app, 2)
    app = start(directory)
    for _ in range(3):
        unlock(app, "wrong", "Incorrect password")
    for _ in range(15):
        choose(app, 1)
        app.expect_exact("Too many attempts.")
    finish(app, 2)
    app = start(directory)
    choose(app, 1)
    app.expect_exact("Too many attempts.")
    finish(app, 2)

    # Simulate expiry in this disposable fixture. The application uses the wall clock.
    (folder / "vault.attempts").write_text("5 1\n")
    app = start(directory)
    unlock(app, MASTER, "Vault unlocked successfully.")
    assert (folder / "vault.attempts").read_text().strip() == "0 0"
    choose(app, 1)
    for label, value in [("Service name: ", "empty-password-test"), ("Website: ", ""),
                         ("Username: ", ""), ("Password: ", "")]:
        answer(app, label, value)
    app.expect_exact("The entry password must contain")
    choose(app, 2)
    app.expect_exact("There are no entries")
    fill_entry(app)
    app.expect_exact("Entry added and saved")
    choose(app, 2)
    app.expect_exact("Password: [hidden]")
    vault = folder / "vault.json"
    saved = vault.read_bytes()
    change = json.loads(saved)
    encrypted = change["encrypted_data"]
    change["encrypted_data"] = ("0" if encrypted[0] != "0" else "1") + encrypted[1:]
    modified = json.dumps(change).encode()
    vault.write_bytes(modified)
    fill_entry(app)
    app.expect_exact("The vault changed since unlock")
    assert vault.read_bytes() == modified
    choose(app, 3)
    app.expect_exact("Vault locked.")
    unlock(app, MASTER, "Incorrect password, or the vault file is damaged.")
    vault.write_bytes(saved)
    choose(app, 1)
    app.expect_exact("Enter your master password: ")
    app.send("partial-password")
    app.expect_exact("*")
    app.sendcontrol("c")
    app.expect_exact("Program ended.")
    app.expect(pexpect.EOF)
    flags = termios.tcgetattr(app.child_fd)[3]
    assert flags & termios.ECHO and flags & termios.ICANON
    app.close()
    assert app.exitstatus == 0

    app = start(directory)
    unlock(app, MASTER, "Vault unlocked successfully.")
    app.expect_exact("Choose an option: ")
    app.sendcontrol("c")
    app.expect_exact("Program ended.")
    app.expect(pexpect.EOF)
    app.close()
    assert app.exitstatus == 0
    app = start(directory)
    app.expect_exact("Vault is locked")
    finish(app, 2)
    audit = folder / "vault.audit.log"
    assert stat.S_IMODE(audit.stat().st_mode) == 0o600
    log = audit.read_text()
    for secret in [MASTER, ENTRY_PASSWORD, "partial-password", "demo-service", "demo-user"]:
        assert secret not in log
    events = [json.loads(row) for row in log.splitlines()]
    assert all(e["actor"] == f"uid-{os.getuid()}" and e["timestamp"].endswith("Z") for e in events)
    assert ("vault_unlock", "rate_limited") in [(e["event"], e["result"]) for e in events]
    assert ("entry_view", "success") in [(e["event"], e["result"]) for e in events]
    assert ("session_end", "interrupted") in [(e["event"], e["result"]) for e in events]


if __name__ == "__main__":
    with TemporaryDirectory() as directory:
        check_security(directory)
    print("CLI security checks passed")
