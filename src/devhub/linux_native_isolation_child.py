#!/usr/bin/env python3
# mypy: disable-error-code="attr-defined,no-any-return"
"""Child-side native Linux isolation probe.

This program is entered through an already-created user/mount/PID/network
namespace.  It builds a private root, drops every capability, applies Landlock,
and performs metadata-only negative probes plus one packaged MCP catalog
lifecycle. It never starts Codex, invokes a tool, or contacts a model/provider.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import resource
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import BinaryIO, cast

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


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def ledger_identity_payload_sha256(identity: Mapping[str, object]) -> str:
    """Hash a ledger identity with the production compact canonical form."""

    return sha256(
        json.dumps(
            identity,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def digest(raw: bytes) -> str:
    return sha256(raw)


def landlock_handled_access(abi: int) -> int:
    if abi not in {3, 4, 5, 6}:
        raise ValueError("Linux qualification supports exactly Landlock ABI 3 through 6")
    base = (1 << 15) - 1
    return base | ((1 << 15) if abi >= 5 else 0)


def enforced_landlock_abi(kernel_abi: int) -> int:
    if kernel_abi < 3:
        raise ValueError("Linux qualification requires Landlock kernel ABI 3 or newer")
    return min(kernel_abi, 6)


def mount_path(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def observed_private_mount_targets(
    raw: bytes, expected_targets: tuple[str, ...]
) -> tuple[str, ...]:
    entries: dict[str, tuple[str, set[str]]] = {}
    for line in raw.decode("utf-8", errors="strict").splitlines():
        fields = line.split(" ")
        separator = fields.index("-")
        target = mount_path(fields[4])
        options = set(fields[5].split(",")) | set(fields[separator + 3].split(","))
        entries[target] = (fields[separator + 1], options)
    if entries.get("/", (None, set()))[0] != "tmpfs":
        raise ValueError("Private root is not a tmpfs mount")
    reviewed = {
        "/bundle": (None, {"ro", "nosuid", "nodev"}, {"noexec"}),
        "/dev": ("tmpfs", {"rw", "nosuid", "noexec"}, {"nodev"}),
        "/home/devfabric": ("tmpfs", {"rw", "nosuid", "nodev", "noexec"}, set()),
        "/output": (None, {"rw", "nosuid", "nodev", "noexec"}, set()),
        "/proc": ("proc", {"rw", "nosuid", "nodev", "noexec"}, set()),
        "/run/devfabric": (None, {"ro", "nosuid", "nodev", "noexec"}, set()),
        "/state": (None, {"rw", "nosuid", "nodev", "noexec"}, set()),
        "/tmp": ("tmpfs", {"rw", "nosuid", "nodev", "noexec"}, set()),
    }
    if tuple(sorted(reviewed)) != expected_targets:
        raise ValueError("Expected mount target contract differs")
    for target, (filesystem, required, forbidden) in reviewed.items():
        if target not in entries:
            raise ValueError("A required private-root mount is absent")
        actual_filesystem, options = entries[target]
        if (filesystem is not None and actual_filesystem != filesystem) or not required <= options:
            raise ValueError("A private-root mount has weaker options than reviewed")
        if forbidden & options:
            raise ValueError("A private-root mount has an unexpected option")
    return tuple(sorted(reviewed))


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


class BootstrapValidationFailure(ValueError):
    def __init__(
        self,
        stage: str,
        reason_code: str,
        *,
        expected_native_identity: dict[str, int] | None = None,
        observed_native_identity: dict[str, int] | None = None,
    ) -> None:
        super().__init__(reason_code)
        self.stage = stage
        self.reason_code = reason_code
        self.expected_native_identity = expected_native_identity
        self.observed_native_identity = observed_native_identity


class BrokerObservationFailure(ValueError):
    def __init__(
        self,
        checkpoint: str,
        operation: str,
        reason_code: str,
        errno_category: str | None = None,
    ) -> None:
        super().__init__(reason_code)
        self.checkpoint = checkpoint
        self.operation = operation
        self.reason_code = reason_code
        self.errno_category = errno_category


class PackagedSubprocessExecutionFailure(ValueError):
    """Bounded subprocess failure that carries hashes/counts, never raw output."""

    def __init__(self, reason: str, capture: dict[str, object]) -> None:
        super().__init__(reason)
        self.capture = capture


class PackagedMcpObservationFailure(ValueError):
    """Fixed-checkpoint packaged MCP failure with optional bounded process evidence."""

    def __init__(self, checkpoint: str, capture: dict[str, object] | None = None) -> None:
        super().__init__(checkpoint)
        self.checkpoint = checkpoint
        self.capture = capture


def bounded_errno_category(error: OSError) -> str:
    if error.errno is None:
        return "other_os_error"
    return {
        errno.ECONNREFUSED: "connection_refused",
        errno.ECONNRESET: "connection_reset",
        errno.EPIPE: "broken_pipe",
        errno.ETIMEDOUT: "timed_out",
        errno.EACCES: "permission_denied",
        errno.EPERM: "permission_denied",
    }.get(error.errno, "other_os_error")


def configured_overflow_id(path: Path) -> int:
    value = int(path.read_text(encoding="ascii").strip())
    if value <= 0 or value > 2**32 - 1:
        raise BootstrapValidationFailure("mount_authority", "namespace_overflow_invalid")
    return value


def host_id_is_mapped_text(raw: str, host_id: int) -> bool:
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) != 3:
            raise BootstrapValidationFailure("mount_authority", "mount_authority_mismatch")
        _inner_start, outer_start, count = (int(item) for item in fields)
        if count <= 0:
            raise BootstrapValidationFailure("mount_authority", "mount_authority_mismatch")
        if outer_start <= host_id < outer_start + count:
            return True
    return False


def validate_owner_projection(
    expected: dict[str, object],
    expected_overflow_uid: int,
    expected_overflow_gid: int,
    overflow_uid: int,
    overflow_gid: int,
    uid_map: str,
    gid_map: str,
    observed_owner_uid: int,
    observed_owner_gid: int,
) -> dict[str, bool | int]:
    if expected.get("owner_uid") != 0 or expected.get("owner_gid") != 0:
        raise BootstrapValidationFailure("mount_authority", "mount_host_authority_not_root")
    if host_id_is_mapped_text(uid_map, 0) or host_id_is_mapped_text(gid_map, 0):
        raise BootstrapValidationFailure("mount_authority", "namespace_host_root_mapped")
    if overflow_uid != expected_overflow_uid or overflow_gid != expected_overflow_gid:
        raise BootstrapValidationFailure("mount_authority", "namespace_overflow_invalid")
    if observed_owner_uid != overflow_uid or observed_owner_gid != overflow_gid:
        raise BootstrapValidationFailure("mount_authority", "namespace_owner_projection_mismatch")
    return {
        "schema_version": 1,
        "host_owner_uid": 0,
        "host_owner_gid": 0,
        "host_root_uid_mapped": False,
        "host_root_gid_mapped": False,
        "overflow_uid": overflow_uid,
        "overflow_gid": overflow_gid,
        "observed_owner_uid": observed_owner_uid,
        "observed_owner_gid": observed_owner_gid,
    }


def validate_mount_authority(
    path: Path,
    expected_raw: str,
    expected_version_environment_raw: str,
    expected_overflow_uid: int,
    expected_overflow_gid: int,
) -> tuple[dict[str, bool | int], dict[str, bool | int]]:
    expected = json.loads(expected_raw)
    if not isinstance(expected, dict):
        raise BootstrapValidationFailure("mount_authority", "mount_pre_exec_content_mismatch")
    version_environment = json.loads(expected_version_environment_raw)
    exact_version_environment = {
        "schema_version": 1,
        "lang": "C.UTF-8",
        "lc_all": "C.UTF-8",
        "path": "/usr/bin:/bin",
    }
    if version_environment != exact_version_environment:
        raise BootstrapValidationFailure("mount_authority", "mount_version_environment_invalid")
    overflow_uid = configured_overflow_id(Path("/proc/sys/kernel/overflowuid"))
    overflow_gid = configured_overflow_id(Path("/proc/sys/kernel/overflowgid"))
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise BootstrapValidationFailure("mount_authority", "mount_pre_exec_path_invalid")
    info = path.stat()
    projection = validate_owner_projection(
        expected,
        expected_overflow_uid,
        expected_overflow_gid,
        overflow_uid,
        overflow_gid,
        Path("/proc/self/uid_map").read_text(encoding="ascii"),
        Path("/proc/self/gid_map").read_text(encoding="ascii"),
        info.st_uid,
        info.st_gid,
    )
    complete_mode = stat.S_IMODE(info.st_mode)
    observed_static = {
        "schema_version": 4,
        "name": "mount",
        "locator": str(path),
        "sha256": file_sha256(path),
        "size": info.st_size,
        "owner_uid": 0,
        "owner_gid": 0,
        "permission_bits": f"0{complete_mode & 0o777:03o}",
        "special_bits": f"0{complete_mode & 0o7000:04o}",
        "full_mode": f"0{complete_mode:04o}",
        "native_identity": {"device": info.st_dev, "inode": info.st_ino},
    }
    if any(
        observed_static.get(key) != expected.get(key)
        for key in ("schema_version", "name", "locator", "sha256", "size", "owner_uid", "owner_gid")
    ):
        raise BootstrapValidationFailure("mount_authority", "mount_pre_exec_content_mismatch")
    if any(
        observed_static[key] != expected.get(key)
        for key in ("permission_bits", "special_bits", "full_mode")
    ):
        raise BootstrapValidationFailure("mount_authority", "mount_pre_exec_mode_mismatch")
    expected_identity = expected.get("native_identity")
    if (
        not isinstance(expected_identity, dict)
        or set(expected_identity) != {"schema_version", "device", "inode"}
        or type(expected_identity.get("schema_version")) is not int
        or expected_identity["schema_version"] != 1
        or type(expected_identity.get("device")) is not int
        or type(expected_identity.get("inode")) is not int
        or expected_identity["device"] < 0
        or expected_identity["inode"] < 1
    ):
        raise BootstrapValidationFailure("mount_authority", "mount_pre_exec_content_mismatch")
    expected_identity_projection = {
        "device": expected_identity["device"],
        "inode": expected_identity["inode"],
    }
    if observed_static["native_identity"] != expected_identity_projection:
        raise BootstrapValidationFailure(
            "mount_authority",
            "mount_pre_exec_identity_mismatch",
            expected_native_identity=expected_identity_projection,
            observed_native_identity={
                "device": info.st_dev,
                "inode": info.st_ino,
            },
        )
    try:
        completed = subprocess.run(
            [str(path), "--version"],
            capture_output=True,
            check=False,
            timeout=10,
            env={
                "LANG": version_environment["lang"],
                "LC_ALL": version_environment["lc_all"],
                "PATH": version_environment["path"],
            },
        )
    except BaseException as error:
        raise BootstrapValidationFailure(
            "mount_authority", "mount_version_execution_failed"
        ) from error
    if completed.returncode != 0:
        raise BootstrapValidationFailure("mount_authority", "mount_version_exit_nonzero")
    version_sha256 = sha256(completed.stdout + b"\n---stderr---\n" + completed.stderr)
    if version_sha256 != expected.get("version_output_sha256"):
        raise BootstrapValidationFailure("mount_authority", "mount_version_output_mismatch")
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise BootstrapValidationFailure("mount_authority", "mount_post_exec_substitution")
    post_info = path.stat()
    post_mode = stat.S_IMODE(post_info.st_mode)
    try:
        post_projection = validate_owner_projection(
            expected,
            expected_overflow_uid,
            expected_overflow_gid,
            configured_overflow_id(Path("/proc/sys/kernel/overflowuid")),
            configured_overflow_id(Path("/proc/sys/kernel/overflowgid")),
            Path("/proc/self/uid_map").read_text(encoding="ascii"),
            Path("/proc/self/gid_map").read_text(encoding="ascii"),
            post_info.st_uid,
            post_info.st_gid,
        )
    except BootstrapValidationFailure as error:
        raise BootstrapValidationFailure(
            "mount_authority", "mount_post_exec_substitution"
        ) from error
    if post_projection != projection:
        raise BootstrapValidationFailure("mount_authority", "mount_post_exec_substitution")
    observed_after = {
        **observed_static,
        "sha256": file_sha256(path),
        "size": post_info.st_size,
        "permission_bits": f"0{post_mode & 0o777:03o}",
        "special_bits": f"0{post_mode & 0o7000:04o}",
        "full_mode": f"0{post_mode:04o}",
        "native_identity": {"device": post_info.st_dev, "inode": post_info.st_ino},
    }
    if observed_after != observed_static:
        raise BootstrapValidationFailure("mount_authority", "mount_post_exec_substitution")
    return projection, {
        "schema_version": 1,
        "pre_exec_authority_matched": True,
        "version_environment_matched": True,
        "version_execution_succeeded": True,
        "version_output_matched": True,
        "post_exec_authority_matched": True,
    }


def child_registration_frame(
    *,
    apparmor_current_profile: str,
    outer_process_id: int,
    inner_process_id: int,
    outer_user_id: int,
    inner_user_id: int,
    process_start_time_ticks: int,
    mount_owner_projection: dict[str, bool | int],
    mount_authority: dict[str, bool | int],
) -> dict[str, object]:
    """Build the exact self-hashed child registration sent to the host."""

    payload: dict[str, object] = {
        "schema_version": 3,
        "frame_kind": "linux_child_registration_v3",
        "apparmor_current_profile": apparmor_current_profile,
        "outer_pid": outer_process_id,
        "inner_pid": inner_process_id,
        "outer_uid": outer_user_id,
        "inner_uid": inner_user_id,
        "start_time_ticks": process_start_time_ticks,
        "mount_owner_projection": mount_owner_projection,
        "mount_authority": mount_authority,
    }
    return {
        "schema_version": 3,
        "child_registration_id": digest(canonical(payload)),
        "payload": payload,
    }


def write_frame(descriptor: int, value: object) -> None:
    os.write(
        descriptor,
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n",
    )


def write_bootstrap_failure(
    descriptor: int,
    stage: str,
    reason_code: str,
    *,
    expected_native_identity: dict[str, int] | None = None,
    observed_native_identity: dict[str, int] | None = None,
) -> None:
    payload = {
        "schema_version": 3,
        "frame_kind": "linux_child_bootstrap_failure_v3",
        "stage": stage,
        "reason_code": reason_code,
        "expected_native_identity": expected_native_identity,
        "observed_native_identity": observed_native_identity,
    }
    frame = {
        "schema_version": 3,
        "child_bootstrap_failure_id": digest(canonical(payload)),
        "payload": payload,
    }
    write_frame(descriptor, frame)
    os.close(descriptor)


def runtime_failure_frame(
    stage: str,
    linux_isolation_profile_id: str,
    environment_instance_id: str,
    broker_failure: BrokerObservationFailure | None = None,
    packaged_mcp_failure: PackagedMcpObservationFailure | None = None,
) -> dict[str, object]:
    if stage == "broker" and broker_failure is None:
        broker_failure = BrokerObservationFailure(
            "socket_wait", "internal", "broker_internal_failure"
        )
    reason_code = {
        "private_root": "private_root_failed",
        "rlimits": "rlimits_failed",
        "capability_drop": "capability_drop_failed",
        "landlock": "landlock_failed",
        "negative_probes": "negative_probes_failed",
        "broker": "broker_internal_failure",
        "result_assembly": "result_assembly_failed",
    }[stage]
    if broker_failure is not None:
        if stage != "broker":
            raise ValueError("Broker diagnostic belongs to a non-broker stage")
        reason_code = broker_failure.reason_code
    if packaged_mcp_failure is not None and stage != "result_assembly":
        raise ValueError("Packaged MCP diagnostic belongs to a non-result stage")
    payload = {
        "schema_version": 3,
        "frame_kind": "linux_child_runtime_failure_v3",
        "linux_isolation_profile_id": linux_isolation_profile_id,
        "environment_instance_id": environment_instance_id,
        "stage": stage,
        "reason_code": reason_code,
        "broker_checkpoint": broker_failure.checkpoint if broker_failure is not None else None,
        "broker_operation": broker_failure.operation if broker_failure is not None else None,
        "errno_category": broker_failure.errno_category if broker_failure is not None else None,
        "packaged_mcp_checkpoint": (
            packaged_mcp_failure.checkpoint if packaged_mcp_failure is not None else None
        ),
        "packaged_subprocess": (
            packaged_mcp_failure.capture if packaged_mcp_failure is not None else None
        ),
    }
    return {
        "schema_version": 3,
        "child_runtime_failure_id": digest(canonical(payload)),
        "payload": payload,
    }


def write_runtime_failure(
    descriptor: int,
    stage: str,
    linux_isolation_profile_id: str,
    environment_instance_id: str,
    broker_failure: BrokerObservationFailure | None = None,
    packaged_mcp_failure: PackagedMcpObservationFailure | None = None,
) -> None:
    write_frame(
        descriptor,
        runtime_failure_frame(
            stage,
            linux_isolation_profile_id,
            environment_instance_id,
            broker_failure,
            packaged_mcp_failure,
        ),
    )
    os.close(descriptor)


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


def set_limits() -> dict[str, int]:
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
    observed = {
        "schema_version": 1,
        "cpu_seconds": resource.getrlimit(resource.RLIMIT_CPU)[0],
        "address_space_bytes": resource.getrlimit(resource.RLIMIT_AS)[0],
        "file_size_bytes": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
        "open_files": resource.getrlimit(resource.RLIMIT_NOFILE)[0],
        "processes": resource.getrlimit(resource.RLIMIT_NPROC)[0],
        "core_bytes": 0,
    }
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


def observed_landlock_authority() -> tuple[int, int, int]:
    """Independently observe the kernel and derive the reviewed enforcement mask."""

    kernel_abi = landlock_abi()
    policy_abi = enforced_landlock_abi(kernel_abi)
    return kernel_abi, policy_abi, landlock_handled_access(policy_abi)


def landlock_rules() -> tuple[tuple[str, int], ...]:
    """Return the exact reviewed paths that remain visible after restriction."""

    return (
        ("/bundle", READ_ONLY_ACCESS),
        ("/home", READ_WRITE_ACCESS),
        ("/output", READ_WRITE_ACCESS),
        ("/proc", ACCESS_READ_FILE | ACCESS_READ_DIR),
        ("/run/devfabric", ACCESS_READ_FILE | ACCESS_READ_DIR),
        ("/state", READ_WRITE_ACCESS),
        ("/tmp", READ_WRITE_ACCESS),
    )


def apply_landlock() -> tuple[int, int, int, tuple[str, ...], str]:
    kernel_abi, policy_abi, handled_access = observed_landlock_authority()
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
    rules = landlock_rules()
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
    ruleset_identity = digest(canonical(rules))
    return kernel_abi, policy_abi, handled_access, targets, ruleset_identity


def validate_private_dev(path: Path = Path("/dev")) -> bool:
    """Seal that the private device tmpfs is empty before Landlock hides it."""

    if tuple(path.iterdir()) != ():
        raise ValueError("Private /dev contains an unexpected entry")
    return True


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


def unix_http(
    checkpoint: str, socket_path: str, raw: bytes
) -> tuple[bytes, tuple[int, int, int], tuple[int, int], int, int]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        try:
            client.connect(socket_path)
        except OSError as error:
            raise BrokerObservationFailure(
                checkpoint,
                "connect",
                "broker_connect_failed",
                bounded_errno_category(error),
            ) from None
        try:
            peer = struct.unpack(
                "3i",
                client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
            )
        except OSError as error:
            raise BrokerObservationFailure(
                checkpoint,
                "peer_credentials",
                "broker_peer_credentials_failed",
                bounded_errno_category(error),
            ) from None
        try:
            socket_info = os.lstat(socket_path)
            parent_info = os.lstat(Path(socket_path).parent)
        except OSError as error:
            raise BrokerObservationFailure(
                checkpoint,
                "path_stat",
                "broker_socket_stat_failed",
                bounded_errno_category(error),
            ) from None
        if not stat.S_ISSOCK(socket_info.st_mode):
            raise BrokerObservationFailure(checkpoint, "socket_type", "broker_socket_type_invalid")
        if stat.S_IMODE(socket_info.st_mode) != 0o600:
            raise BrokerObservationFailure(checkpoint, "socket_mode", "broker_socket_mode_invalid")
        if stat.S_IMODE(parent_info.st_mode) != 0o700:
            raise BrokerObservationFailure(checkpoint, "parent_mode", "broker_parent_mode_invalid")
        if peer[0] != 0:
            raise BrokerObservationFailure(checkpoint, "peer_pid", "broker_peer_pid_invalid")
        if peer[1] != 1000:
            raise BrokerObservationFailure(checkpoint, "peer_uid", "broker_peer_uid_invalid")
        try:
            client.sendall(raw)
        except OSError as error:
            raise BrokerObservationFailure(
                checkpoint,
                "send",
                "broker_send_failed",
                bounded_errno_category(error),
            ) from None
        try:
            client.shutdown(socket.SHUT_WR)
        except OSError as error:
            raise BrokerObservationFailure(
                checkpoint,
                "shutdown_write",
                "broker_shutdown_failed",
                bounded_errno_category(error),
            ) from None
        chunks = bytearray()
        while True:
            try:
                chunk = client.recv(64 * 1024)
            except OSError as error:
                raise BrokerObservationFailure(
                    checkpoint,
                    "receive",
                    "broker_receive_failed",
                    bounded_errno_category(error),
                ) from None
            if not chunk:
                break
            if len(chunks) + len(chunk) > 4 * 1024**2:
                raise BrokerObservationFailure(
                    checkpoint, "response_bound", "broker_response_bound_exceeded"
                )
            chunks.extend(chunk)
        return (
            bytes(chunks),
            peer,
            (socket_info.st_dev, socket_info.st_ino),
            stat.S_IMODE(socket_info.st_mode),
            stat.S_IMODE(parent_info.st_mode),
        )
    finally:
        client.close()


def broker_observations() -> dict[str, bool | str | int]:
    socket_path = "/run/devfabric/ollama.sock"
    deadline = time.monotonic() + 10
    while not Path(socket_path).exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not Path(socket_path).exists():
        raise BrokerObservationFailure("socket_wait", "wait", "broker_socket_missing")
    version, version_peer, version_identity, version_mode, version_parent_mode = unix_http(
        "version",
        socket_path,
        b"GET /api/version HTTP/1.1\r\nHost: 127.0.0.1:11434\r\n\r\n",
    )
    if not version.startswith(b"HTTP/1.1 200"):
        raise BrokerObservationFailure(
            "version", "response_status", "broker_response_status_invalid"
        )
    tags, tags_peer, tags_identity, tags_mode, tags_parent_mode = unix_http(
        "tags",
        socket_path,
        b"GET /api/tags HTTP/1.1\r\nHost: 127.0.0.1:11434\r\n\r\n",
    )
    if not tags.startswith(b"HTTP/1.1 200"):
        raise BrokerObservationFailure("tags", "response_status", "broker_response_status_invalid")
    show_body = b'{"model":"qwen2.5:14b-instruct"}'
    show, show_peer, show_identity, show_mode, show_parent_mode = unix_http(
        "show",
        socket_path,
        b"POST /api/show HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nContent-Length: "
        + str(len(show_body)).encode("ascii")
        + b"\r\n\r\n"
        + show_body,
    )
    if not show.startswith(b"HTTP/1.1 200"):
        raise BrokerObservationFailure("show", "response_status", "broker_response_status_invalid")
    generate, generate_peer, generate_identity, generate_mode, generate_parent_mode = unix_http(
        "generate_denial",
        socket_path,
        b"POST /api/generate HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nContent-Length: 2\r\n\r\n{}",
    )
    if not generate.startswith(b"HTTP/1.1 403"):
        raise BrokerObservationFailure(
            "generate_denial", "response_status", "broker_response_status_invalid"
        )
    oversized, oversized_peer, oversized_identity, oversized_mode, oversized_parent_mode = (
        unix_http(
            "oversized_denial",
            socket_path,
            b"GET /api/version HTTP/1.1\r\nHost: 127.0.0.1:11434\r\nX: " + b"a" * (70 * 1024),
        )
    )
    if not oversized.startswith(b"HTTP/1.1 403"):
        raise BrokerObservationFailure(
            "oversized_denial", "response_status", "broker_response_status_invalid"
        )
    peers = (version_peer, tags_peer, show_peer, generate_peer, oversized_peer)
    checkpoints = ("version", "tags", "show", "generate_denial", "oversized_denial")
    identities = (
        version_identity,
        tags_identity,
        show_identity,
        generate_identity,
        oversized_identity,
    )
    socket_modes = (version_mode, tags_mode, show_mode, generate_mode, oversized_mode)
    parent_modes = (
        version_parent_mode,
        tags_parent_mode,
        show_parent_mode,
        generate_parent_mode,
        oversized_parent_mode,
    )
    for checkpoint, socket_mode, parent_mode in zip(
        checkpoints, socket_modes, parent_modes, strict=True
    ):
        if socket_mode != 0o600:
            raise BrokerObservationFailure(checkpoint, "socket_mode", "broker_socket_mode_invalid")
        if parent_mode != 0o700:
            raise BrokerObservationFailure(checkpoint, "parent_mode", "broker_parent_mode_invalid")
    if len(set(identities)) != 1:
        raise BrokerObservationFailure(
            "inode_stability", "inode_compare", "broker_inode_substitution"
        )
    peer_pid_translation = all(peer[0] == 0 for peer in peers)
    peer_uid_translation = all(peer[1] == 1000 for peer in peers)
    return {
        "socket_parent_mode": f"0{version_parent_mode:03o}",
        "socket_mode": f"0{version_mode:03o}",
        "pid_namespace_translation_validated": peer_pid_translation,
        "child_verified_broker_pid_translation": peer_pid_translation,
        "child_verified_broker_uid": peer_uid_translation,
        "socket_inode": version_identity[1],
        "version_allowed": version.startswith(b"HTTP/1.1 200"),
        "tags_allowed": tags.startswith(b"HTTP/1.1 200"),
        "show_allowed": show.startswith(b"HTTP/1.1 200"),
        "generate_denied": generate.startswith(b"HTTP/1.1 403"),
        "oversized_request_denied": oversized.startswith(b"HTTP/1.1 403"),
    }


def packaged_subprocess_capture(
    process_started: bool,
    returncode: int | None,
    retained: Mapping[str, bytearray | bytes],
    observed: Mapping[str, int],
    *,
    timed_out: bool,
    output_limit_exceeded: bool,
) -> dict[str, object]:
    """Seal only bounded stream counts/hashes for one packaged subprocess."""

    stdout = bytes(retained["stdout"])
    stderr = bytes(retained["stderr"])
    return {
        "schema_version": 1,
        "process_started": process_started,
        "returncode": returncode,
        "stdout_retained_bytes": len(stdout),
        "stdout_observed_bytes": observed["stdout"],
        "stdout_retained_sha256": sha256(stdout),
        "stdout_truncated": len(stdout) < observed["stdout"],
        "stderr_retained_bytes": len(stderr),
        "stderr_observed_bytes": observed["stderr"],
        "stderr_retained_sha256": sha256(stderr),
        "stderr_truncated": len(stderr) < observed["stderr"],
        "timed_out": timed_out,
        "output_limit_exceeded": output_limit_exceeded,
    }


def completed_subprocess_capture(
    returncode: int, stdout: bytes, stderr: bytes
) -> dict[str, object]:
    retained = {"stdout": stdout, "stderr": stderr}
    observed = {"stdout": len(stdout), "stderr": len(stderr)}
    return packaged_subprocess_capture(
        True,
        returncode,
        retained,
        observed,
        timed_out=False,
        output_limit_exceeded=False,
    )


def unstarted_subprocess_capture() -> dict[str, object]:
    """Represent a subprocess boundary that failed before a final status existed."""

    return packaged_subprocess_capture(
        False,
        None,
        {"stdout": b"", "stderr": b""},
        {"stdout": 0, "stderr": 0},
        timed_out=False,
        output_limit_exceeded=False,
    )


def run_bounded_subprocess(
    command: list[str],
    *,
    environment: dict[str, str],
    input_data: bytes | None,
    timeout: float,
) -> tuple[int, bytes, bytes]:
    """Run one package observation without unbounded stdout/stderr retention."""

    limit = 1024 * 1024
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        startup_cleanup_errors: list[BaseException] = []
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except BaseException as error:
            startup_cleanup_errors.append(error)
        try:
            process.wait(timeout=5)
        except BaseException as error:
            startup_cleanup_errors.append(error)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except BaseException as error:
                    startup_cleanup_errors.append(error)
        primary = PackagedSubprocessExecutionFailure(
            "Packaged subprocess diagnostic streams are unavailable",
            packaged_subprocess_capture(
                True,
                process.returncode,
                {"stdout": b"", "stderr": b""},
                {"stdout": 0, "stderr": 0},
                timed_out=False,
                output_limit_exceeded=False,
            ),
        )
        if startup_cleanup_errors:
            raise PackagedSubprocessExecutionFailure(
                "Packaged subprocess startup and cleanup failed", primary.capture
            ) from BaseExceptionGroup(
                "Packaged subprocess startup and cleanup failed", [primary, *startup_cleanup_errors]
            )
        raise primary
    retained = {"stdout": bytearray(), "stderr": bytearray()}
    observed = {"stdout": 0, "stderr": 0}
    overflow = threading.Event()
    drain_errors: list[BaseException] = []
    started_threads: list[threading.Thread] = []
    primary_error: BaseException | None = None
    result: tuple[int, bytes, bytes] | None = None
    timed_out = False

    def kill_group() -> None:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def drain(name: str, stream: BinaryIO) -> None:
        try:
            while chunk := stream.read(64 * 1024):
                observed[name] += len(chunk)
                target = retained[name]
                remaining = limit - len(target)
                if remaining > 0:
                    target.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()
                    kill_group()
                    return
        except BaseException as error:
            drain_errors.append(error)
            kill_group()

    threads = [
        threading.Thread(target=drain, args=("stdout", process.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", process.stderr), daemon=True),
    ]
    try:
        for thread in threads:
            thread.start()
            started_threads.append(thread)
        try:
            if input_data is not None:
                process.stdin.write(input_data)
                process.stdin.flush()
        except BrokenPipeError:
            pass
        finally:
            process.stdin.close()
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_group()
            process.wait(timeout=5)
            returncode = None
        for thread in started_threads:
            thread.join(timeout=5)
        if any(thread.is_alive() for thread in started_threads):
            raise PackagedSubprocessExecutionFailure(
                "Packaged subprocess diagnostics did not drain",
                packaged_subprocess_capture(
                    True,
                    None if timed_out else process.returncode,
                    retained,
                    observed,
                    timed_out=timed_out,
                    output_limit_exceeded=overflow.is_set(),
                ),
            )
        if drain_errors:
            raise PackagedSubprocessExecutionFailure(
                "Packaged subprocess diagnostic drain failed",
                packaged_subprocess_capture(
                    True,
                    None if timed_out else process.returncode,
                    retained,
                    observed,
                    timed_out=timed_out,
                    output_limit_exceeded=overflow.is_set(),
                ),
            ) from drain_errors[0]
        if overflow.is_set():
            raise PackagedSubprocessExecutionFailure(
                "Packaged subprocess output exceeded its retained bound",
                packaged_subprocess_capture(
                    True,
                    None if timed_out else process.returncode,
                    retained,
                    observed,
                    timed_out=timed_out,
                    output_limit_exceeded=True,
                ),
            )
        if timed_out:
            raise PackagedSubprocessExecutionFailure(
                "Packaged subprocess timed out",
                packaged_subprocess_capture(
                    True,
                    None,
                    retained,
                    observed,
                    timed_out=True,
                    output_limit_exceeded=False,
                ),
            )
        assert returncode is not None
        result = returncode, bytes(retained["stdout"]), bytes(retained["stderr"])
    except BaseException as error:
        primary_error = error
    finally:
        cleanup_errors: list[BaseException] = []
        try:
            kill_group()
        except BaseException as error:
            cleanup_errors.append(error)
        try:
            process.wait(timeout=5)
        except BaseException as error:
            cleanup_errors.append(error)
        if not process.stdin.closed:
            try:
                process.stdin.close()
            except BaseException as error:
                cleanup_errors.append(error)
        for thread in started_threads:
            try:
                thread.join(timeout=5)
                if thread.is_alive():
                    raise ValueError("Packaged subprocess diagnostic thread remained")
            except BaseException as error:
                cleanup_errors.append(error)
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except BaseException as error:
                cleanup_errors.append(error)
        if cleanup_errors:
            failures = (
                [*cleanup_errors] if primary_error is None else [primary_error, *cleanup_errors]
            )
            capture = (
                primary_error.capture
                if isinstance(primary_error, PackagedSubprocessExecutionFailure)
                else packaged_subprocess_capture(
                    True,
                    None if timed_out else process.returncode,
                    retained,
                    observed,
                    timed_out=timed_out,
                    output_limit_exceeded=overflow.is_set(),
                )
            )
            raise PackagedSubprocessExecutionFailure(
                "Packaged subprocess cleanup failed", capture
            ) from BaseExceptionGroup("Packaged subprocess cleanup failed", failures)
    if primary_error is not None:
        if isinstance(primary_error, PackagedSubprocessExecutionFailure):
            raise primary_error
        raise PackagedSubprocessExecutionFailure(
            "Packaged subprocess failed after process creation",
            packaged_subprocess_capture(
                True,
                None if timed_out else process.returncode,
                retained,
                observed,
                timed_out=timed_out,
                output_limit_exceeded=overflow.is_set(),
            ),
        ) from primary_error
    if result is None:
        raise ValueError("Packaged subprocess produced no result")
    return result


def strict_mcp_result(
    frame: object,
    request_id: int,
) -> dict[str, object]:
    """Accept one exact successful JSON-RPC 2.0 response frame."""

    if (
        not isinstance(frame, dict)
        or set(frame) != {"jsonrpc", "id", "result"}
        or frame.get("jsonrpc") != "2.0"
        or frame.get("id") != request_id
        or not isinstance(frame.get("result"), dict)
    ):
        raise ValueError("Packaged MCP response frame differs")
    return cast(dict[str, object], frame["result"])


def _observe_packaged_mcp_metadata(
    profile_id: str,
    expected_python_sha256: str,
    *,
    python: Path,
    bundle_root: Path,
    state_root: Path,
    output_root: Path,
    home: Path,
    module_relative_path: str,
    expected_module_origin: str,
) -> dict[str, object]:
    """Observe initialize/tools-list/EOF through one explicit isolated runtime."""

    try:
        if sha256(python.read_bytes()) != expected_python_sha256:
            raise ValueError("Packaged Python differs before MCP metadata observation")
    except BaseException as error:
        raise PackagedMcpObservationFailure("python_authority") from error
    try:
        state = state_root / "package-mcp"
        state.mkdir(mode=0o700)
        config = state_root / "package-mcp-config.json"
        instance_id = hashlib.sha256((profile_id + ":ledger").encode()).hexdigest()[:32]
        authority_id = hashlib.sha256((profile_id + ":authority").encode()).hexdigest()[:32]
        ledger_identity = {
            "family": "devfabric_resource_ledger",
            "format_version": 1,
            "instance_id": instance_id,
            "authority_scope_kind": "qualification",
            "authority_scope_id": authority_id,
            "account_binding_hash": None,
        }
        expected_ledger_identity_sha256 = ledger_identity_payload_sha256(ledger_identity)
        config.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "cloud_enabled": False,
                    "telemetry_footer": "off",
                    "profiles": [
                        {
                            "schema_version": 1,
                            "id": "package-metadata",
                            "task_classes": ["summarize"],
                            "config": {
                                "schema_version": 1,
                                "project": "package-metadata",
                                "root": str(bundle_root),
                                "state_root": str(state),
                                "ledger_identity": ledger_identity,
                                "approved_paths": [module_relative_path],
                                "authoritative_paths": [module_relative_path],
                                "ollama": {
                                    "schema_version": 1,
                                    "endpoint": "http://127.0.0.1:11434",
                                    "model": "qwen2.5:14b-instruct",
                                    "model_digest": (
                                        "7cdf5a0187d5c58cc5d369b255592f7841d1c4696d45a8c8a9489440385b22f6"
                                    ),
                                    "version": "0.34.2",
                                    "context_tokens": 8192,
                                    "max_output_tokens": 256,
                                    "safety_tokens": 128,
                                    "timeout_seconds": 90,
                                },
                            },
                        }
                    ],
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )
    except BaseException as error:
        raise PackagedMcpObservationFailure("state_config_preparation") from error
    environment = {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": f"{python.parent}:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    command = [str(python), "-I", "-B", "-m", "devhub.delegate_server", "--config", str(config)]
    try:
        origin_returncode, origin_stdout, origin_stderr = run_bounded_subprocess(
            [
                str(python),
                "-I",
                "-B",
                "-c",
                (
                    "from pathlib import Path; import devhub.delegate_server as module; "
                    "print(Path(module.__file__).resolve())"
                ),
            ],
            environment=environment,
            input_data=None,
            timeout=20,
        )
    except PackagedSubprocessExecutionFailure as error:
        raise PackagedMcpObservationFailure("module_origin", error.capture) from error
    except BaseException as error:
        raise PackagedMcpObservationFailure(
            "module_origin", unstarted_subprocess_capture()
        ) from error
    origin_capture = completed_subprocess_capture(origin_returncode, origin_stdout, origin_stderr)
    if (
        origin_returncode != 0
        or origin_stderr != b""
        or origin_stdout != (expected_module_origin + "\n").encode()
    ):
        raise PackagedMcpObservationFailure("module_origin", origin_capture)
    try:
        init_returncode, init_stdout, init_stderr = run_bounded_subprocess(
            [*command, "--initialize-ledger"],
            environment=environment,
            input_data=None,
            timeout=20,
        )
    except PackagedSubprocessExecutionFailure as error:
        raise PackagedMcpObservationFailure("ledger_initialization", error.capture) from error
    except BaseException as error:
        raise PackagedMcpObservationFailure(
            "ledger_initialization", unstarted_subprocess_capture()
        ) from error
    init_capture = completed_subprocess_capture(init_returncode, init_stdout, init_stderr)
    try:
        init_lines = init_stdout.splitlines()
        init_result = json.loads(init_lines[0]) if len(init_lines) == 1 else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        init_result = None
    if (
        init_returncode != 0
        or init_stderr != b""
        or init_result != {"ledger_identity_sha256": expected_ledger_identity_sha256}
    ):
        raise PackagedMcpObservationFailure("ledger_initialization", init_capture)
    requests = (
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "package-observer", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    )
    payload = b"".join(
        json.dumps(item, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        for item in requests
    )
    stdout_path = output_root / "package-mcp-stdout.bin"
    stderr_path = output_root / "package-mcp-stderr.bin"
    try:
        returncode, stdout_raw, stderr_raw = run_bounded_subprocess(
            command,
            environment=environment,
            input_data=payload,
            timeout=20,
        )
    except PackagedSubprocessExecutionFailure as error:
        raise PackagedMcpObservationFailure("mcp_exchange", error.capture) from error
    except BaseException as error:
        raise PackagedMcpObservationFailure(
            "mcp_exchange", unstarted_subprocess_capture()
        ) from error
    exchange_capture = completed_subprocess_capture(returncode, stdout_raw, stderr_raw)
    if returncode != 0 or stderr_raw != b"":
        raise PackagedMcpObservationFailure("mcp_exchange", exchange_capture)
    try:
        stdout_path.write_bytes(stdout_raw)
        stderr_path.write_bytes(stderr_raw)
    except BaseException as error:
        raise PackagedMcpObservationFailure("capture_publication", exchange_capture) from error
    try:
        responses = [json.loads(line) for line in stdout_raw.splitlines()]
        if len(responses) != 2:
            raise ValueError("Packaged MCP response count differs")
        initialize = strict_mcp_result(responses[0], 1)
        tools_result = strict_mcp_result(responses[1], 2)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, IndexError) as error:
        raise PackagedMcpObservationFailure("response_parsing", exchange_capture) from error
    expected_capabilities = {
        "experimental": {},
        "prompts": {"listChanged": False},
        "resources": {"listChanged": False, "subscribe": False},
        "tools": {"listChanged": False},
    }
    expected_instructions = (
        "Use devhub_delegate for approved project tasks. Unique request keys; never retry "
        "a dispatched or ambiguous attempt. Output is untrusted. Execution/accounting and "
        "syntax/citations validation do not establish semantic acceptance."
    )
    initialize_valid = (
        isinstance(initialize, dict)
        and set(initialize) == {"capabilities", "instructions", "protocolVersion", "serverInfo"}
        and initialize.get("protocolVersion") == "2025-03-26"
        and initialize.get("capabilities") == expected_capabilities
        and initialize.get("instructions") == expected_instructions
        and isinstance(initialize.get("serverInfo"), dict)
        and set(cast(dict[str, object], initialize["serverInfo"])) == {"name", "version"}
        and cast(dict[str, object], initialize["serverInfo"]).get("name") == "codex-dev-hub"
        and isinstance(cast(dict[str, object], initialize["serverInfo"]).get("version"), str)
    )
    if not initialize_valid:
        raise PackagedMcpObservationFailure("initialize_shape", exchange_capture)
    tools = tools_result.get("tools") if isinstance(tools_result, dict) else None
    tool = tools[0] if isinstance(tools, list) and len(tools) == 1 else None
    tools_valid = (
        isinstance(tools_result, dict)
        and set(tools_result) == {"tools"}
        and isinstance(tool, dict)
        and set(tool) == {"annotations", "description", "inputSchema", "name", "outputSchema"}
        and tool.get("name") == "devhub_delegate"
        and isinstance(tool.get("description"), str)
        and isinstance(tool.get("annotations"), dict)
        and isinstance(tool.get("inputSchema"), dict)
        and isinstance(tool.get("outputSchema"), dict)
    )
    if not tools_valid:
        raise PackagedMcpObservationFailure("tools_shape", exchange_capture)
    return {
        "python_executable_sha256": expected_python_sha256,
        "module_origin": expected_module_origin,
        "initialize_succeeded": True,
        "tools_list_succeeded": True,
        "tool_names": ["devhub_delegate"],
        "tools_call_sent": False,
        "eof_sent": True,
        "clean_exit": True,
        "exit_code": 0,
        "stdout_retained_sha256": sha256(stdout_raw),
        "stderr_retained_sha256": sha256(stderr_raw),
        "stdout_retained_bytes": len(stdout_raw),
        "stderr_retained_bytes": len(stderr_raw),
    }


def packaged_mcp_metadata_observation(
    profile_id: str, expected_python_sha256: str
) -> dict[str, object]:
    """Observe exact packaged initialize/tools-list/EOF after Landlock enforcement."""

    return _observe_packaged_mcp_metadata(
        profile_id,
        expected_python_sha256,
        python=Path("/bundle/python/bin/python3.12"),
        bundle_root=Path("/bundle"),
        state_root=Path("/state"),
        output_root=Path("/output"),
        home=Path("/home/devfabric"),
        module_relative_path=("python/lib/python3.12/site-packages/devhub/delegate_server.py"),
        expected_module_origin=(
            "/bundle/python/lib/python3.12/site-packages/devhub/delegate_server.py"
        ),
    )


def run_post_registration(
    args: argparse.Namespace,
    apparmor_current: str,
    owner_projection: Mapping[str, int],
    mount_authority: Mapping[str, object],
) -> None:
    """Run the closed child stages and emit only typed failure evidence."""

    stage = "private_root"
    try:
        private_root(
            args.mount_binary,
            args.root,
            args.bundle,
            args.state,
            args.output,
            args.broker,
        )
        os.chroot(args.root)
        os.chdir("/")
        minimal_dev = validate_private_dev()

        stage = "rlimits"
        rlimits = set_limits()
        rlimits_sha256 = digest(canonical(rlimits))
        if rlimits_sha256 != args.expected_rlimits_sha256:
            raise ValueError("Observed rlimits differ from the host profile")

        stage = "capability_drop"
        drop_capabilities()
        status = process_security_status()
        if any(status[key] for key in status if key.startswith("cap_")):
            raise ValueError("A Linux capability remained after the drop")
        if status["no_new_privs"] != 1:
            raise ValueError("no_new_privs was not applied")
        regain_denied = capability_regain_denied()
        if not regain_denied:
            raise ValueError("A Linux capability could be regained after the drop")

        stage = "landlock"
        kernel_abi, policy_abi, handled_access, rule_targets, ruleset_sha = apply_landlock()
        if (
            kernel_abi != args.expected_kernel_landlock_abi
            or policy_abi != args.expected_enforced_landlock_abi
            or handled_access != args.expected_landlock_mask
        ):
            raise ValueError("Observed Landlock authority differs from the host profile")

        stage = "negative_probes"
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
        direct_loopback_denied = denied_tcp(("127.0.0.1", 11434))
        direct_lan_denied = denied_tcp(("192.168.0.1", 80))
        direct_dns_denied = denied_dns()
        direct_public_denied = denied_tcp(("1.1.1.1", 443))

        stage = "broker"
        observed_broker = broker_observations()

        stage = "result_assembly"
        packaged_mcp = packaged_mcp_metadata_observation(
            args.linux_isolation_profile_id, args.expected_python_sha256
        )
        try:
            observed = {
                "apparmor_current_profile": apparmor_current,
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
                "mount_authority_revalidated": True,
                "mount_authority": mount_authority,
                "mount_table_sha256": sha256(mount_table),
                "observed_mount_targets": mount_targets,
                "bundle_read_only": bundle_read_only,
                "state_read_write": Path("/state/allowed.txt").read_text(encoding="ascii")
                == "state",
                "output_read_write": (
                    Path("/output/allowed.txt").read_text(encoding="ascii") == "output"
                ),
                "home_tmpfs": True,
                "tmp_tmpfs": True,
                "fresh_proc": True,
                "minimal_dev": minimal_dev,
                "host_root_hidden": host_hidden,
                "host_home_hidden": home_hidden,
                "no_new_privs": status["no_new_privs"] == 1,
                "cap_effective": status["cap_effective"],
                "cap_permitted": status["cap_permitted"],
                "cap_inheritable": status["cap_inheritable"],
                "cap_ambient": status["cap_ambient"],
                "cap_bounding": status["cap_bounding"],
                "capability_regain_denied": regain_denied,
                "kernel_landlock_abi": kernel_abi,
                "enforced_landlock_abi": policy_abi,
                "landlock_handled_access": handled_access,
                "landlock_rule_targets": rule_targets,
                "landlock_ruleset_sha256": ruleset_sha,
                "landlock_allowed_operations_passed": (
                    Path("/state/allowed.txt").read_text(encoding="ascii") == "state"
                    and Path("/output/allowed.txt").read_text(encoding="ascii") == "output"
                ),
                "landlock_denied_operations_passed": denied_by_landlock,
                "direct_loopback_denied": direct_loopback_denied,
                "direct_lan_denied": direct_lan_denied,
                "direct_dns_denied": direct_dns_denied,
                "direct_public_denied": direct_public_denied,
                "rlimits_applied": True,
                "rlimits_sha256": rlimits_sha256,
                "child_bootstrap": {
                    "isolated_python": True,
                    "bytecode_disabled": True,
                    "stdlib_only": True,
                },
                "mount_owner_projection": owner_projection,
                "broker": observed_broker,
                "child_module_origin": (
                    "/bundle/python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"
                ),
                "child_module_sha256": args.expected_child_module_sha256,
                "packaged_mcp": packaged_mcp,
            }
        except BaseException as error:
            raise PackagedMcpObservationFailure("observation_assembly") from error
        try:
            write_frame(args.result_fd, observed)
            os.close(args.result_fd)
        except BaseException as error:
            raise PackagedMcpObservationFailure("result_frame_publication") from error
    except BaseException as error:
        broker_failure = error if isinstance(error, BrokerObservationFailure) else None
        packaged_mcp_failure = error if isinstance(error, PackagedMcpObservationFailure) else None
        if stage == "result_assembly" and packaged_mcp_failure is None:
            packaged_mcp_failure = PackagedMcpObservationFailure("observation_assembly")
        write_runtime_failure(
            args.result_fd,
            stage,
            args.linux_isolation_profile_id,
            args.environment_instance_id,
            broker_failure,
            packaged_mcp_failure,
        )
        raise SystemExit(71) from None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--broker", type=Path, required=True)
    parser.add_argument("--mount-binary", required=True)
    parser.add_argument("--expected-mount-authority", required=True)
    parser.add_argument("--expected-mount-version-environment", required=True)
    parser.add_argument("--expected-overflow-uid", type=int, required=True)
    parser.add_argument("--expected-overflow-gid", type=int, required=True)
    parser.add_argument("--registration-fd", type=int, required=True)
    parser.add_argument("--result-fd", type=int, required=True)
    parser.add_argument("--host-namespaces", required=True)
    parser.add_argument("--expected-mount-targets", required=True)
    parser.add_argument("--expected-kernel-landlock-abi", type=int, required=True)
    parser.add_argument("--expected-enforced-landlock-abi", type=int, required=True)
    parser.add_argument("--expected-landlock-mask", type=int, required=True)
    parser.add_argument("--expected-rlimits-sha256", required=True)
    parser.add_argument("--expected-apparmor-current", required=True)
    parser.add_argument("--linux-isolation-profile-id", required=True)
    parser.add_argument("--environment-instance-id", required=True)
    parser.add_argument("--expected-python-sha256", required=True)
    parser.add_argument("--expected-child-module-sha256", required=True)
    args = parser.parse_args()

    if sys.flags.isolated != 1 or sys.flags.dont_write_bytecode != 1:
        write_bootstrap_failure(
            args.registration_fd, "interpreter_flags", "interpreter_flags_invalid"
        )
        raise SystemExit(70)

    try:
        if sha256(Path(__file__).read_bytes()) != args.expected_child_module_sha256:
            raise ValueError
    except BaseException:
        write_bootstrap_failure(
            args.registration_fd, "interpreter_flags", "interpreter_flags_invalid"
        )
        raise SystemExit(70) from None

    try:
        apparmor_current = Path("/proc/self/attr/current").read_text(encoding="utf-8").strip()
        if apparmor_current != args.expected_apparmor_current:
            raise ValueError
    except BaseException:
        write_bootstrap_failure(
            args.registration_fd, "apparmor_identity", "apparmor_identity_invalid"
        )
        raise SystemExit(70) from None

    try:
        owner_projection, mount_authority = validate_mount_authority(
            Path(args.mount_binary),
            args.expected_mount_authority,
            args.expected_mount_version_environment,
            args.expected_overflow_uid,
            args.expected_overflow_gid,
        )
    except BootstrapValidationFailure as error:
        write_bootstrap_failure(
            args.registration_fd,
            error.stage,
            error.reason_code,
            expected_native_identity=error.expected_native_identity,
            observed_native_identity=error.observed_native_identity,
        )
        raise SystemExit(70) from None
    except BaseException:
        write_bootstrap_failure(
            args.registration_fd, "mount_authority", "mount_authority_internal_failure"
        )
        raise SystemExit(70) from None

    try:
        registration = child_registration_frame(
            apparmor_current_profile=apparmor_current,
            outer_process_id=outer_pid(),
            inner_process_id=os.getpid(),
            outer_user_id=outer_uid(),
            inner_user_id=os.geteuid(),
            process_start_time_ticks=start_time_ticks(),
            mount_owner_projection=owner_projection,
            mount_authority=mount_authority,
        )
    except BaseException:
        write_bootstrap_failure(
            args.registration_fd, "process_identity", "process_identity_invalid"
        )
        raise SystemExit(70) from None
    write_frame(args.registration_fd, registration)
    os.close(args.registration_fd)

    run_post_registration(args, apparmor_current, owner_projection, mount_authority)


if __name__ == "__main__":
    main()
