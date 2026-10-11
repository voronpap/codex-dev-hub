#!/usr/bin/env python3
"""Child-side native Linux isolation probe.

This program is entered through an already-created user/mount/PID/network
namespace.  It builds a private root, drops every capability, applies Landlock,
and performs metadata-only negative probes.  It never starts Codex or DevFabric.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import resource
import socket
import stat
import struct
import subprocess
import time
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from devhub.benchmark import canonical, digest
from devhub.linux_isolation import (
    LinuxRlimitsV1,
    landlock_handled_access,
    observed_private_mount_targets,
)

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECUREBITS = 28
PR_CAPBSET_DROP = 24
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_CLEAR_ALL = 4
SECUREBITS_LOCKED = 0xEF
LINUX_CAPABILITY_VERSION_3 = 0x20080522
SYS_CAPSET_X86_64 = 126
SYS_LANDLOCK_CREATE_RULESET_X86_64 = 444
SYS_LANDLOCK_ADD_RULE_X86_64 = 445
SYS_LANDLOCK_RESTRICT_SELF_X86_64 = 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1
ACCESS_EXECUTE = 1 << 0
ACCESS_WRITE_FILE = 1 << 1
ACCESS_READ_FILE = 1 << 2
ACCESS_READ_DIR = 1 << 3
ACCESS_REMOVE_DIR = 1 << 4
ACCESS_REMOVE_FILE = 1 << 5
ACCESS_MAKE_CHAR = 1 << 6
ACCESS_MAKE_DIR = 1 << 7
ACCESS_MAKE_REG = 1 << 8
ACCESS_MAKE_SOCK = 1 << 9
ACCESS_MAKE_FIFO = 1 << 10
ACCESS_MAKE_BLOCK = 1 << 11
ACCESS_MAKE_SYM = 1 << 12
ACCESS_REFER = 1 << 13
ACCESS_TRUNCATE = 1 << 14
READ_ONLY_ACCESS = ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR
READ_WRITE_ACCESS = (
    READ_ONLY_ACCESS
    | ACCESS_WRITE_FILE
    | ACCESS_REMOVE_DIR
    | ACCESS_REMOVE_FILE
    | ACCESS_MAKE_CHAR
    | ACCESS_MAKE_DIR
    | ACCESS_MAKE_REG
    | ACCESS_MAKE_SOCK
    | ACCESS_MAKE_FIFO
    | ACCESS_MAKE_BLOCK
    | ACCESS_MAKE_SYM
    | ACCESS_REFER
    | ACCESS_TRUNCATE
)


class CapabilityHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class CapabilityData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


class LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def namespace_id(kind: str) -> str:
    return os.readlink(f"/proc/self/ns/{kind}")


def start_time_ticks() -> int:
    raw = Path("/proc/self/stat").read_text(encoding="ascii")
    end_command = raw.rfind(")")
    fields = raw[end_command + 2 :].split()
    if end_command < 0 or len(fields) < 20:
        raise ValueError("Process stat is incomplete")
    return int(fields[19])


def outer_pid() -> int:
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if line.startswith("NSpid:"):
            values = [int(item) for item in line.split()[1:]]
            if len(values) < 2 or values[-1] != 1:
                raise ValueError("PID namespace translation is unavailable")
            return values[0]
    raise ValueError("NSpid observation is unavailable")


def outer_uid() -> int:
    inner_uid = os.geteuid()
    for line in Path("/proc/self/uid_map").read_text(encoding="ascii").splitlines():
        inner_start, outer_start, count = (int(item) for item in line.split())
        if inner_start <= inner_uid < inner_start + count:
            return outer_start + inner_uid - inner_start
    raise ValueError("UID namespace translation is unavailable")


def run_mount(mount_binary: str, *arguments: str) -> None:
    completed = subprocess.run(
        [mount_binary, *arguments], capture_output=True, check=False, timeout=10
    )
    if completed.returncode != 0:
        reason = completed.stderr.decode("utf-8", errors="replace")[:256]
        raise ValueError(f"mount operation failed: {reason}")


def bind_mount(
    mount_binary: str, source: Path, target: Path, *, read_only: bool, noexec: bool
) -> None:
    target.mkdir(parents=True, exist_ok=False)
    run_mount(mount_binary, "--bind", str(source), str(target))
    options = "remount,bind,nosuid,nodev"
    if read_only:
        options += ",ro"
    if noexec:
        options += ",noexec"
    run_mount(mount_binary, "-o", options, str(target))


def private_root(
    mount_binary: str,
    root: Path,
    bundle: Path,
    state: Path,
    output: Path,
    broker: Path,
) -> None:
    run_mount(mount_binary, "--make-rprivate", "/")
    run_mount(
        mount_binary, "-t", "tmpfs", "-o", "mode=0755,size=64m,nosuid,nodev", "tmpfs", str(root)
    )
    bind_mount(mount_binary, bundle, root / "bundle", read_only=True, noexec=False)
    bind_mount(mount_binary, state, root / "state", read_only=False, noexec=True)
    bind_mount(mount_binary, output, root / "output", read_only=False, noexec=True)
    bind_mount(
        mount_binary,
        broker,
        root / "run" / "devfabric",
        read_only=True,
        noexec=True,
    )
    for target, options in (
        (root / "home" / "devfabric", "mode=0700,size=16m,nosuid,nodev,noexec,uid=1000,gid=1000"),
        (root / "tmp", "mode=1777,size=16m,nosuid,nodev,noexec"),
        (root / "dev", "mode=0755,size=1m,nosuid,noexec"),
    ):
        target.mkdir(parents=True, exist_ok=False)
        run_mount(mount_binary, "-t", "tmpfs", "-o", options, "tmpfs", str(target))
    proc = root / "proc"
    proc.mkdir(parents=True, exist_ok=False)
    run_mount(
        mount_binary,
        "-t",
        "proc",
        "-o",
        "nosuid,nodev,noexec,hidepid=2",
        "proc",
        str(proc),
    )


def set_limits() -> LinuxRlimitsV1:
    limits = {
        resource.RLIMIT_CPU: (60, 60),
        resource.RLIMIT_AS: (2 * 1024**3, 2 * 1024**3),
        resource.RLIMIT_FSIZE: (64 * 1024**2, 64 * 1024**2),
        resource.RLIMIT_NOFILE: (128, 128),
        resource.RLIMIT_NPROC: (32, 32),
        resource.RLIMIT_CORE: (0, 0),
    }
    for kind, value in limits.items():
        resource.setrlimit(kind, value)
    observed_core = resource.getrlimit(resource.RLIMIT_CORE)[0]
    if observed_core != 0:
        raise ValueError("Core-file rlimit differs from the reviewed zero limit")
    observed = LinuxRlimitsV1(
        cpu_seconds=resource.getrlimit(resource.RLIMIT_CPU)[0],
        address_space_bytes=resource.getrlimit(resource.RLIMIT_AS)[0],
        file_size_bytes=resource.getrlimit(resource.RLIMIT_FSIZE)[0],
        open_files=resource.getrlimit(resource.RLIMIT_NOFILE)[0],
        processes=resource.getrlimit(resource.RLIMIT_NPROC)[0],
        core_bytes=0,
    )
    return observed


def drop_capabilities() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_SECUREBITS, SECUREBITS_LOCKED, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECUREBITS failed")
    cap_last = int(Path("/proc/sys/kernel/cap_last_cap").read_text(encoding="ascii"))
    for capability in range(cap_last + 1):
        if libc.prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_CAPBSET_DROP failed")
    if libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_CAP_AMBIENT_CLEAR_ALL failed")
    header = CapabilityHeader(LINUX_CAPABILITY_VERSION_3, 0)
    values = (CapabilityData * 2)()
    if libc.syscall(SYS_CAPSET_X86_64, ctypes.byref(header), ctypes.byref(values)) != 0:
        raise OSError(ctypes.get_errno(), "capset failed")
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")


def capability_regain_denied() -> bool:
    libc = ctypes.CDLL(None, use_errno=True)
    header = CapabilityHeader(LINUX_CAPABILITY_VERSION_3, 0)
    values = (CapabilityData * 2)()
    values[0].effective = 1
    values[0].permitted = 1
    result = libc.syscall(SYS_CAPSET_X86_64, ctypes.byref(header), ctypes.byref(values))
    return result == -1 and ctypes.get_errno() in {1, 13}


def landlock_abi() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    value = libc.syscall(
        SYS_LANDLOCK_CREATE_RULESET_X86_64,
        ctypes.c_void_p(),
        0,
        LANDLOCK_CREATE_RULESET_VERSION,
    )
    if value < 0:
        raise OSError(ctypes.get_errno(), "Landlock ABI query failed")
    return int(value)


def apply_landlock() -> tuple[int, int, tuple[str, ...], str]:
    abi = landlock_abi()
    handled_access = landlock_handled_access(abi)
    libc = ctypes.CDLL(None, use_errno=True)
    ruleset_attr = LandlockRulesetAttr(handled_access)
    ruleset_fd = libc.syscall(
        SYS_LANDLOCK_CREATE_RULESET_X86_64,
        ctypes.byref(ruleset_attr),
        ctypes.sizeof(ruleset_attr),
        0,
    )
    if ruleset_fd < 0:
        raise OSError(ctypes.get_errno(), "Landlock ruleset creation failed")
    rules: list[tuple[str, int]] = [
        ("/bundle", READ_ONLY_ACCESS),
        ("/home", READ_WRITE_ACCESS),
        ("/output", READ_WRITE_ACCESS),
        ("/proc", ACCESS_READ_FILE | ACCESS_READ_DIR),
        ("/run/devfabric", ACCESS_READ_FILE | ACCESS_READ_DIR),
        ("/state", READ_WRITE_ACCESS),
        ("/tmp", READ_WRITE_ACCESS),
    ]
    opened: list[int] = []
    try:
        for path, access in rules:
            descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC)
            opened.append(descriptor)
            rule = LandlockPathBeneathAttr(access, descriptor)
            if (
                libc.syscall(
                    SYS_LANDLOCK_ADD_RULE_X86_64,
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH,
                    ctypes.byref(rule),
                    0,
                )
                != 0
            ):
                raise OSError(ctypes.get_errno(), "Landlock path rule failed")
        if libc.syscall(SYS_LANDLOCK_RESTRICT_SELF_X86_64, ruleset_fd, 0) != 0:
            raise OSError(ctypes.get_errno(), "Landlock restrict-self failed")
    finally:
        for descriptor in opened:
            os.close(descriptor)
        os.close(ruleset_fd)
    targets = tuple(path for path, _ in rules)
    ruleset_identity = digest(canonical(cast(JsonValue, rules)))
    return abi, handled_access, targets, ruleset_identity


def process_security_status() -> dict[str, int]:
    wanted = {
        "CapEff": "cap_effective",
        "CapPrm": "cap_permitted",
        "CapInh": "cap_inheritable",
        "CapAmb": "cap_ambient",
        "CapBnd": "cap_bounding",
        "NoNewPrivs": "no_new_privs",
    }
    found: dict[str, int] = {}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        key, _, raw = line.partition(":")
        if key in wanted:
            found[wanted[key]] = int(raw.strip(), 16 if key.startswith("Cap") else 10)
    if set(found) != set(wanted.values()):
        raise ValueError("Process security status is incomplete")
    return found


def denied_tcp(address: tuple[str, int]) -> bool:
    candidate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    candidate.settimeout(0.25)
    try:
        candidate.connect(address)
    except OSError:
        return True
    finally:
        candidate.close()
    return False


def denied_dns() -> bool:
    candidate = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    candidate.settimeout(0.25)
    try:
        candidate.sendto(b"\0", ("1.1.1.1", 53))
    except OSError:
        return True
    finally:
        candidate.close()
    return False


def unix_http(socket_path: str, raw: bytes) -> tuple[bytes, tuple[int, int, int], int]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        client.connect(socket_path)
        peer = struct.unpack(
            "3i",
            client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
        )
        socket_info = os.lstat(socket_path)
        parent_info = os.lstat(Path(socket_path).parent)
        if (
            not stat.S_ISSOCK(socket_info.st_mode)
            or stat.S_IMODE(socket_info.st_mode) != 0o600
            or stat.S_IMODE(parent_info.st_mode) != 0o700
            or peer[0] != 0
            or peer[1] != 1000
        ):
            raise ValueError("Child-side Ollama broker identity validation failed")
        client.sendall(raw)
        client.shutdown(socket.SHUT_WR)
        chunks = bytearray()
        while chunk := client.recv(64 * 1024):
            if len(chunks) + len(chunk) > 4 * 1024**2:
                raise ValueError("Broker response exceeded the child limit")
            chunks.extend(chunk)
        return bytes(chunks), peer, socket_info.st_ino
    finally:
        client.close()


def broker_observations() -> dict[str, bool | str | int]:
    socket_path = "/run/devfabric/ollama.sock"
    deadline = time.monotonic() + 10
    while not Path(socket_path).exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not Path(socket_path).exists():
        raise ValueError("Ollama broker socket did not appear")
    version, version_peer, socket_inode = unix_http(
        socket_path,
        b"GET /api/version HTTP/1.1\r\nHost: 127.0.0.1:11434\r\n\r\n",
    )
    tags, tags_peer, tags_inode = unix_http(
        socket_path,
        b"GET /api/tags HTTP/1.1\r\nHost: 127.0.0.1:11434\r\n\r\n",
    )
    show_body = b'{"model":"qwen2.5:14b-instruct"}'
    show, show_peer, show_inode = unix_http(
        socket_path,
        b"POST /api/show HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nContent-Length: "
        + str(len(show_body)).encode("ascii")
        + b"\r\n\r\n"
        + show_body,
    )
    generate, generate_peer, generate_inode = unix_http(
        socket_path,
        b"POST /api/generate HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nContent-Length: 2\r\n\r\n{}",
    )
    oversized, oversized_peer, oversized_inode = unix_http(
        socket_path,
        b"GET /api/version HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nX: " + b"a" * (70 * 1024),
    )
    peers = (version_peer, tags_peer, show_peer, generate_peer, oversized_peer)
    inodes = (socket_inode, tags_inode, show_inode, generate_inode, oversized_inode)
    if len(set(inodes)) != 1:
        raise ValueError("Ollama broker socket identity changed during qualification")
    return {
        "socket_parent_mode": f"0{stat.S_IMODE(os.lstat(Path(socket_path).parent).st_mode):03o}",
        "socket_mode": f"0{stat.S_IMODE(os.lstat(socket_path).st_mode):03o}",
        "pid_namespace_translation_validated": outer_pid() >= 1,
        "child_verified_broker_pid_translation": all(peer[0] == 0 for peer in peers),
        "child_verified_broker_uid": all(peer[1] == 1000 for peer in peers),
        "socket_inode": socket_inode,
        "version_allowed": version.startswith(b"HTTP/1.1 200"),
        "tags_allowed": tags.startswith(b"HTTP/1.1 200"),
        "show_allowed": show.startswith(b"HTTP/1.1 200"),
        "generate_denied": generate.startswith(b"HTTP/1.1 403"),
        "oversized_request_denied": oversized.startswith(b"HTTP/1.1 403"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--broker", type=Path, required=True)
    parser.add_argument("--mount-binary", required=True)
    parser.add_argument("--registration-fd", type=int, required=True)
    parser.add_argument("--result-fd", type=int, required=True)
    parser.add_argument("--host-namespaces", required=True)
    parser.add_argument("--expected-mount-targets", required=True)
    parser.add_argument("--expected-landlock-abi", type=int, required=True)
    parser.add_argument("--expected-landlock-mask", type=int, required=True)
    parser.add_argument("--expected-rlimits-sha256", required=True)
    args = parser.parse_args()

    registration = {
        "outer_pid": outer_pid(),
        "inner_pid": os.getpid(),
        "outer_uid": outer_uid(),
        "inner_uid": os.geteuid(),
        "start_time_ticks": start_time_ticks(),
    }
    os.write(
        args.registration_fd,
        json.dumps(registration, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n",
    )
    os.close(args.registration_fd)

    private_root(
        args.mount_binary,
        args.root,
        args.bundle,
        args.state,
        args.output,
        args.broker,
    )
    result_fd = args.result_fd
    os.chroot(args.root)
    os.chdir("/")
    rlimits = set_limits()
    drop_capabilities()
    abi, handled_access, rule_targets, ruleset_sha = apply_landlock()
    if abi != args.expected_landlock_abi or handled_access != args.expected_landlock_mask:
        raise ValueError("Observed Landlock authority differs from the host profile")
    status = process_security_status()
    if any(status[key] for key in status if key.startswith("cap_")):
        raise ValueError("A Linux capability remained after the drop")
    if status["no_new_privs"] != 1:
        raise ValueError("no_new_privs was not applied")
    regain_denied = capability_regain_denied()
    if not regain_denied:
        raise ValueError("A Linux capability could be regained after the drop")
    Path("/state/allowed.txt").write_text("state", encoding="ascii")
    Path("/output/allowed.txt").write_text("output", encoding="ascii")
    denied_by_landlock = False
    try:
        Path("/dev/forbidden").write_text("no", encoding="ascii")
    except PermissionError:
        denied_by_landlock = True
    if not denied_by_landlock:
        raise ValueError("Landlock did not deny an unapproved writable mount")
    host_hidden = not Path("/etc/passwd").exists()
    home_hidden = not Path("/home/runner").exists()
    bundle_read_only = False
    try:
        Path("/bundle/forbidden.txt").write_text("no", encoding="ascii")
    except OSError:
        bundle_read_only = True
    host_namespaces = json.loads(args.host_namespaces)
    child_namespaces = {kind: namespace_id(kind) for kind in ("user", "mnt", "pid", "net")}
    mount_table = Path("/proc/self/mountinfo").read_bytes()
    expected_mount_targets = tuple(json.loads(args.expected_mount_targets))
    mount_targets = observed_private_mount_targets(mount_table, expected_mount_targets)
    rlimits_sha256 = digest(canonical(rlimits.model_dump(mode="json")))
    if rlimits_sha256 != args.expected_rlimits_sha256:
        raise ValueError("Observed rlimits differ from the host profile")
    observed = {
        "namespaces": {
            "host_user_namespace_id": host_namespaces["user"],
            "child_user_namespace_id": child_namespaces["user"],
            "host_mount_namespace_id": host_namespaces["mnt"],
            "child_mount_namespace_id": child_namespaces["mnt"],
            "host_pid_namespace_id": host_namespaces["pid"],
            "child_pid_namespace_id": child_namespaces["pid"],
            "host_network_namespace_id": host_namespaces["net"],
            "child_network_namespace_id": child_namespaces["net"],
            "uid_map_sha256": sha256(Path("/proc/self/uid_map").read_bytes()),
            "gid_map_sha256": sha256(Path("/proc/self/gid_map").read_bytes()),
            "child_uid": os.geteuid(),
            "child_gid": os.getegid(),
        },
        "private_mount_root": True,
        "mount_table_sha256": sha256(mount_table),
        "observed_mount_targets": mount_targets,
        "bundle_read_only": bundle_read_only,
        "state_read_write": Path("/state/allowed.txt").read_text(encoding="ascii") == "state",
        "output_read_write": Path("/output/allowed.txt").read_text(encoding="ascii") == "output",
        "home_tmpfs": True,
        "tmp_tmpfs": True,
        "fresh_proc": True,
        "minimal_dev": tuple(Path("/dev").iterdir()) == (),
        "host_root_hidden": host_hidden,
        "host_home_hidden": home_hidden,
        "no_new_privs": status["no_new_privs"] == 1,
        "cap_effective": status["cap_effective"],
        "cap_permitted": status["cap_permitted"],
        "cap_inheritable": status["cap_inheritable"],
        "cap_ambient": status["cap_ambient"],
        "cap_bounding": status["cap_bounding"],
        "capability_regain_denied": regain_denied,
        "landlock_abi": abi,
        "landlock_handled_access": handled_access,
        "landlock_rule_targets": rule_targets,
        "landlock_ruleset_sha256": ruleset_sha,
        "landlock_allowed_operations_passed": (
            Path("/state/allowed.txt").read_text(encoding="ascii") == "state"
            and Path("/output/allowed.txt").read_text(encoding="ascii") == "output"
        ),
        "landlock_denied_operations_passed": denied_by_landlock,
        "direct_loopback_denied": denied_tcp(("127.0.0.1", 11434)),
        "direct_lan_denied": denied_tcp(("192.168.0.1", 80)),
        "direct_dns_denied": denied_dns(),
        "direct_public_denied": denied_tcp(("1.1.1.1", 443)),
        "rlimits_applied": True,
        "rlimits_sha256": rlimits_sha256,
        "broker": broker_observations(),
    }
    os.write(
        result_fd,
        json.dumps(observed, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n",
    )
    os.close(result_fd)


if __name__ == "__main__":
    main()
