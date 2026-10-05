"""Synthetic filesystem-equivalent writes; no Codex, credentials or provider calls."""

import hashlib
import json
import os
from pathlib import Path


def attempt(operation):
    try:
        operation()
        return {"denied": False, "errno": None}
    except OSError as error:
        return {"denied": True, "errno": error.errno}


def main():
    protected = {}
    for name in (
        "/control/session.json",
        "/bootstrap.py",
        "/auth.json",
    ):
        path = Path(name)
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        operations = {
            "overwrite": attempt(lambda path=path: path.write_bytes(b"synthetic mutation")),
            "append": attempt(lambda path=path: path.open("ab").close()),
            "unlink": attempt(path.unlink),
            "rename": attempt(lambda path=path: path.rename(path.with_name(path.name + ".moved"))),
            "replace": attempt(lambda path=path: os.replace("/tmp/replacement", path)),
        }
        protected[name] = {
            "operations": operations,
            "unchanged": path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == before,
        }
    hidden = {}
    for name in (
        "/host",
        "/workspace",
        "/repository",
        "/root/.codex",
        "/ledger",
        "/oracle",
        "/opposite-arm",
        "/previous-session",
        "/future-session",
        "/reviewer",
        "/evaluator",
        "/var/run/docker.sock",
        "/packet/input.txt",
        "/packet/task.txt",
        "/packet/instructions.txt",
    ):
        path = Path(name)
        hidden[name] = {
            "stat": attempt(path.stat),
            "create": attempt(lambda path=path: path.mkdir(parents=True)),
        }
    writable = {}
    for name in ("/tmp", "/home/runner", "/capture", "/dev/shm", "/packet"):
        path = Path(name) / "synthetic-effect"
        result = attempt(lambda path=path: path.write_bytes(b"synthetic only"))
        writable[name] = not result["denied"]
    # Docker-generated /etc files can be rw mounts yet unwritable to UID 1000.
    system_files = {
        name: attempt(lambda p=Path(name): p.open("ab").close())
        for name in ("/etc/hosts", "/etc/hostname", "/etc/resolv.conf")
    }
    report = {
        "protected": protected,
        "hidden": hidden,
        "writable": writable,
        "system_files": system_files,
        "mountinfo": Path("/proc/self/mountinfo").read_text(),
        "namespaces": {p.name: os.readlink(p) for p in Path("/proc/self/ns").iterdir()},
        "visible_pids": sorted(p.name for p in Path("/proc").iterdir() if p.name.isdigit()),
        "devices": sorted(p.name for p in Path("/dev").iterdir()),
        "unix_sockets": Path("/proc/net/unix").read_text(),
        "status": Path("/proc/self/status").read_text(),
    }
    print(json.dumps(report))


if __name__ == "__main__":
    Path("/tmp/replacement").write_bytes(b"synthetic replacement")
    main()
