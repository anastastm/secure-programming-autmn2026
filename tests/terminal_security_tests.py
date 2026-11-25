"""Linux CLI checks. Run with Python, pexpect, and the path to the built application."""
import json
import os
import signal
import time
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


def reset_counter(directory):
    Path(directory, "vault.attempts").write_text("0 0 0\n")


def check_security(directory):
    folder = Path(directory)
    app = start(directory)
    choose(app, 1)
    answer(app, "Choose a master password: ", "")
    app.expect_exact("Use 15-256")
    assert not (folder / "vault.json").exists()
    for weak in ["aaaaaaaaaaaaaaa", "123456789012345", "passwordpassword", "Password2024!!!!"]:
        choose(app, 1)
        answer(app, "Choose a master password: ", weak)
        app.expect_exact("Avoid repeated characters")
        assert not (folder / "vault.json").exists()
    choose(app, 1)
    answer(app, "Choose a master password: ", MASTER)
    answer(app, "Type it again: ", MASTER)
    app.expect_exact("Encrypted vault saved")
    assert json.loads((folder / "vault.json").read_text())["version"] == 3
    assert (folder / "vault.attempts").read_text().strip() == "0 0 0"
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

    (folder / "vault.attempts").write_text("5 1 1\n")
    app = start(directory)
    unlock(app, MASTER, "Vault unlocked successfully.")
    assert (folder / "vault.attempts").read_text().strip() == "0 0 0"
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
    choose(app, 2)
    app.expect_exact("Service: demo-service")
    app.expect_exact("Username: demo-user")
    app.expect_exact("Password: [hidden]")
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


def check_owner_and_reveal(directory):
    legacy = {'version': 1, 'salt': '3afcaa338702af02955e956a2da526c9', 'nonce': '0d52237bf33834761811c9160ddd587de6fde9356c869da5', 'encrypted_data': 'c113a8204fa99f3c4b1213741bf2fe4a94433d5993c9eb1220d65928376dd57ff7bf37ee486ad1131ab955240841270557cf0bfd048139'}
    foreign = {'version': 2, 'salt': '7e1623fe04b166d2031f16c6442cc186', 'nonce': '42a4c6909ce0968e1fdacbc4a7f26fe604f0aca32eda393c', 'encrypted_data': 'd2305d7daaf95706f489cf276698908f3a5fcf4932c0b4f27371ac34f6e85fbfaa391ef7f776181702eedc0ed35cb665fcd3790ff2fbd9'}
    vault = Path(directory, "vault.json")
    vault.write_text(json.dumps(foreign))
    reset_counter(directory)
    app = start(directory)
    unlock(app, MASTER, "Incorrect password, or the vault file is damaged.")
    finish(app, 2)
    foreign["version"] = 1
    vault.write_text(json.dumps(foreign))
    reset_counter(directory)
    app = start(directory)
    unlock(app, MASTER, "Incorrect password, or the vault file is damaged.")
    finish(app, 2)

    vault.write_text(json.dumps(legacy))
    reset_counter(directory)
    app = start(directory)
    unlock(app, MASTER, "Vault unlocked successfully.")
    assert json.loads(vault.read_text())["version"] == 1
    fill_entry(app)
    app.expect_exact("Entry added and saved")
    assert json.loads(vault.read_text())["version"] == 2
    finish(app, 4)
    app = start(directory)
    unlock(app, MASTER, "Vault unlocked successfully.")
    choose(app, 5)
    answer(app, "Entry number to reveal (1-2): ", "0")
    app.expect_exact("Invalid entry number.")
    choose(app, 5)
    answer(app, "Entry number to reveal (1-2): ", "1")
    answer(app, "Type yes: ", "no")
    app.expect_exact("Reveal cancelled.")
    choose(app, 5)
    answer(app, "Entry number to reveal (1-2): ", "1")
    answer(app, "Type yes: ", "yes")
    app.expect_exact("Password: old-secret")
    finish(app, 4)
    log = Path(directory, "vault.audit.log").read_text()
    assert '"event":"password_reveal","result":"success"' in log
    assert "old-secret" not in log and ENTRY_PASSWORD not in log


def last_event(directory):
    return json.loads(Path(directory, "vault.audit.log").read_text().splitlines()[-1])


def check_signals_and_tampering(directory):
    folder = Path(directory)
    app = start(directory)
    choose(app, 1)
    answer(app, "Choose a master password: ", MASTER)
    answer(app, "Type it again: ", MASTER)
    app.expect_exact("Encrypted vault saved")
    finish(app, 2)

    for send in [lambda a: a.sendcontrol("\\"), lambda a: a.kill(signal.SIGTERM),
                 lambda a: a.kill(signal.SIGHUP)]:
        app = start(directory)
        choose(app, 1)
        app.expect_exact("Enter your master password: ")
        app.send("half-typed")
        app.expect_exact("*")
        send(app)
        app.expect_exact("Program ended.")
        app.expect(pexpect.EOF)
        flags = termios.tcgetattr(app.child_fd)[3]
        assert flags & termios.ECHO and flags & termios.ICANON
        app.close()
        assert app.exitstatus == 0
        assert (last_event(directory)["event"], last_event(directory)["result"]) == ("session_end", "interrupted")
        reset_counter(directory)

    app = start(directory)
    choose(app, 1)
    app.expect_exact("Enter your master password: ")
    app.sendcontrol("z")
    time.sleep(0.3)
    assert app.isalive()
    app.sendline(MASTER)
    app.expect_exact("Vault unlocked successfully.")
    finish(app, 4)

    app = start(directory)
    unlock(app, "wrong", "Incorrect password")
    app.expect_exact("Choose an option: ")
    assert '"event"' not in app.before
    app.sendline("2")
    app.expect(pexpect.EOF)
    app.close()

    (folder / "vault.attempts").unlink()
    app = start(directory)
    choose(app, 1)
    app.expect_exact("The unlock history is missing.")
    choose(app, 1)
    app.expect_exact("Too many attempts.")
    finish(app, 2)
    reset_counter(directory)

    audit = folder / "vault.audit.log"
    lines = audit.read_text().splitlines()
    hidden = [line for line in lines if '"result":"failure"' not in line]
    assert len(hidden) < len(lines)
    audit.write_text("\n".join(hidden) + "\n")
    app = start(directory)
    app.expect_exact("Warning: the audit log was changed")
    finish(app, 2)
    kept = list(folder.glob("vault.audit.log.unverified-*"))
    assert len(kept) == 1 and kept[0].read_text() == "\n".join(hidden) + "\n"
    events = [json.loads(row) for row in audit.read_text().splitlines()]
    assert (events[0]["event"], events[0]["result"]) == ("audit_log", "integrity_failed")


if __name__ == "__main__":
    with TemporaryDirectory() as directory:
        check_security(directory)
    with TemporaryDirectory() as directory:
        check_owner_and_reveal(directory)
    with TemporaryDirectory() as directory:
        check_signals_and_tampering(directory)
    print("CLI security, ownership, signal and tampering checks passed")
