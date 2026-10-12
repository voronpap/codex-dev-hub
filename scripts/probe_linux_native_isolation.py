#!/usr/bin/env python3
"""Run the metadata-only native Linux namespace qualification baseline."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import re
import select
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from functools import partial
from pathlib import Path
from typing import Any, Literal, cast

from pydantic import JsonValue

from devhub import linux_ollama_broker as linux_broker_module
from devhub.benchmark import canonical, digest
from devhub.linux_isolation import (
    LINUX_APPARMOR_CURRENT,
    LINUX_PRIVATE_UNSHARE,
    LINUX_SYSTEM_UNSHARE,
    LinuxAppArmorAuthorityV2,
    LinuxAppArmorParserAuthorityV2,
    LinuxBrokerExpectationV1,
    LinuxChildBootstrapFailureV3,
    LinuxChildRegistrationPayloadV3,
    LinuxChildRegistrationV3,
    LinuxChildRuntimeFailureV2,
    LinuxDirectoryAuthorityV1,
    LinuxFileAuthorityV1,
    LinuxHostAuthorityV3,
    LinuxHostBrokerFailurePayloadV1,
    LinuxHostBrokerFailureV1,
    LinuxHostCleanupObservationV1,
    LinuxIsolationEvidencePayloadV11,
    LinuxIsolationEvidenceV11,
    LinuxIsolationFailurePayloadV7,
    LinuxIsolationFailureV7,
    LinuxIsolationObservationV11,
    LinuxIsolationProfilePayloadV11,
    LinuxIsolationProfileV11,
    LinuxIsolationReceiptPayloadV11,
    LinuxIsolationReceiptV11,
    LinuxMountAuthorityV1,
    LinuxNamespaceOwnerProjectionExpectationV1,
    LinuxNativePathIdentityV1,
    LinuxSyntheticUpstreamAuthorityV1,
    LinuxSyntheticUpstreamObservationV1,
    LinuxToolAuthorityV1,
    LinuxToolAuthorityV4,
    LinuxToolVersionEnvironmentV1,
    enforced_landlock_abi,
    landlock_handled_access,
)
from devhub.linux_ollama_broker import (
    LinuxBrokerPeerAuthorityV1,
    LinuxMetadataBrokerFailure,
    LinuxMetadataBrokerV1,
)
from devhub.native_bundle import git_blob_sha256

RETAINED_LIMIT = 1024 * 1024
HARD_LIMIT = 8 * 1024 * 1024
LANDLOCK_CREATE_RULESET_VERSION = 1
SYS_LANDLOCK_CREATE_RULESET_X86_64 = 444
_COMMIT = re.compile(r"^[a-f0-9]{40}$")
LINUX_SIGKILL = 9
MOUNT_VERSION_ENVIRONMENT = LinuxToolVersionEnvironmentV1()
ToolName = Literal["unshare", "mount"]
DirectoryRole = Literal["fixture", "state", "output", "broker", "scratch_root"]
FailurePhase = Literal[
    "host_inspection",
    "source_revalidation",
    "namespace_creation",
    "child_registration",
    "private_root",
    "capability_drop",
    "landlock",
    "broker",
    "negative_probes",
    "child_result",
    "cleanup",
]
FailureReason = Literal[
    "host_authority_invalid",
    "source_authority_changed",
    "namespace_launch_failed",
    "child_registration_invalid",
    "private_root_failed",
    "capability_drop_failed",
    "landlock_failed",
    "broker_failed",
    "negative_probe_failed",
    "child_output_invalid",
    "cleanup_failed",
    "unexpected_internal_failure",
]


def current_uid() -> int:
    getter = getattr(os, "getuid", None)
    if not callable(getter):
        raise ValueError("Native Linux qualification requires getuid")
    return int(getter())


def current_gid() -> int:
    getter = getattr(os, "getgid", None)
    if not callable(getter):
        raise ValueError("Native Linux qualification requires getgid")
    return int(getter())


def configured_overflow_id(path: Path) -> int:
    value = int(path.read_text(encoding="ascii").strip())
    if value <= 0 or value > 2**32 - 1:
        raise ValueError("Linux namespace overflow identity is invalid")
    return value


def kill_process_group(pid: int) -> None:
    killer = getattr(os, "killpg", None)
    if not callable(killer):
        raise ValueError("Native Linux qualification requires process-group signals")
    killer(pid, LINUX_SIGKILL)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def tree_identity(root: Path) -> str:
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("Isolation fixture cannot contain symbolic links")
        if path.is_dir():
            entries.append({"path": relative, "kind": "directory", "mode": info.st_mode & 0o7777})
        elif path.is_file():
            entries.append(
                {
                    "path": relative,
                    "kind": "file",
                    "mode": info.st_mode & 0o7777,
                    "size": info.st_size,
                    "sha256": file_sha256(path),
                }
            )
        else:
            raise ValueError("Isolation fixture contains a non-plain entry")
    return digest(canonical(cast(JsonValue, entries)))


def native_identity(info: os.stat_result) -> LinuxNativePathIdentityV1:
    return LinuxNativePathIdentityV1(device=info.st_dev, inode=info.st_ino)


def plain_file_authority(path: Path) -> LinuxFileAuthorityV1:
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError("File authority must be one non-symlink regular file")
    info = path.stat()
    return LinuxFileAuthorityV1(
        locator=str(path),
        sha256=file_sha256(path),
        size=info.st_size,
        owner_uid=info.st_uid,
        owner_gid=info.st_gid,
        mode=f"0{stat.S_IMODE(info.st_mode):03o}",
        native_identity=native_identity(info),
    )


def file_authority(path: Path, name: ToolName) -> LinuxToolAuthorityV1:
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError(f"{name} authority must be one non-symlink regular file")
    info = path.stat()
    completed = subprocess.run(
        [str(path), "--version"], capture_output=True, check=False, timeout=10
    )
    if completed.returncode != 0:
        raise ValueError(f"{name} version observation failed")
    return LinuxToolAuthorityV1(
        name=name,
        locator=str(path),
        sha256=file_sha256(path),
        size=info.st_size,
        owner_uid=info.st_uid,
        owner_gid=info.st_gid,
        mode=f"0{stat.S_IMODE(info.st_mode):03o}",
        native_identity=native_identity(info),
        version_output_sha256=sha256(completed.stdout + b"\n---stderr---\n" + completed.stderr),
    )


def full_mode_authority(path: Path, name: ToolName) -> LinuxToolAuthorityV4:
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError(f"{name} authority must be one non-symlink regular file")
    before_info = path.stat()
    before_mode = stat.S_IMODE(before_info.st_mode)
    before_sha256 = file_sha256(path)
    completed = subprocess.run(
        [str(path), "--version"],
        capture_output=True,
        check=False,
        timeout=10,
        env={
            "LANG": MOUNT_VERSION_ENVIRONMENT.lang,
            "LC_ALL": MOUNT_VERSION_ENVIRONMENT.lc_all,
            "PATH": MOUNT_VERSION_ENVIRONMENT.path,
        },
    )
    if completed.returncode != 0:
        raise ValueError(f"{name} version observation failed")
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError(f"{name} authority changed during version observation")
    after_info = path.stat()
    after_mode = stat.S_IMODE(after_info.st_mode)
    after_sha256 = file_sha256(path)
    if (
        native_identity(before_info) != native_identity(after_info)
        or before_info.st_size != after_info.st_size
        or before_info.st_uid != after_info.st_uid
        or before_info.st_gid != after_info.st_gid
        or before_mode != after_mode
        or before_sha256 != after_sha256
    ):
        raise ValueError(f"{name} authority changed during version observation")
    return LinuxToolAuthorityV4(
        name=name,
        locator=str(path),
        sha256=after_sha256,
        size=after_info.st_size,
        owner_uid=after_info.st_uid,
        owner_gid=after_info.st_gid,
        permission_bits=f"0{after_mode & 0o777:03o}",
        special_bits=f"0{after_mode & 0o7000:04o}",
        full_mode=f"0{after_mode:04o}",
        native_identity=native_identity(after_info),
        version_output_sha256=sha256(completed.stdout + b"\n---stderr---\n" + completed.stderr),
    )


def apparmor_parser_authority(path: Path) -> LinuxAppArmorParserAuthorityV2:
    authority = plain_file_authority(path)
    completed = subprocess.run(
        [str(path), "--version"], capture_output=True, check=False, timeout=10
    )
    if completed.returncode != 0:
        raise ValueError("AppArmor parser version observation failed")
    return LinuxAppArmorParserAuthorityV2(
        **authority.model_dump(mode="python"),
        version_output_sha256=sha256(completed.stdout + b"\n---stderr---\n" + completed.stderr),
    )


def apparmor_authority(
    repo: Path,
    implementation_commit: str,
    *,
    installed: Path = Path("/etc/apparmor.d/devfabric-linux-isolation-unshare"),
    parser: Path = Path("/usr/sbin/apparmor_parser"),
    loaded: Path = Path("/run/devfabric/devfabric-linux-isolation-profiles"),
) -> LinuxAppArmorAuthorityV2:
    relative = Path("packaging/linux/apparmor/devfabric-linux-isolation-unshare")
    source = repo / relative
    if loaded.read_text(encoding="utf-8").splitlines() != [LINUX_APPARMOR_CURRENT]:
        raise ValueError("Exact AppArmor profile is not loaded in the reviewed mode")
    return LinuxAppArmorAuthorityV2(
        source_git_blob_sha256=git_blob_sha256(repo, implementation_commit, relative.as_posix()),
        source_sha256=file_sha256(source),
        installed_profile=plain_file_authority(installed),
        parser=apparmor_parser_authority(parser),
        loaded_profiles_snapshot=plain_file_authority(loaded),
    )


def directory_authority(path: Path, role: DirectoryRole) -> LinuxDirectoryAuthorityV1:
    if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path:
        raise ValueError("Isolation directory authority must be a non-symlink directory")
    info = path.stat()
    if (
        info.st_uid != current_uid()
        or info.st_gid != current_gid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("Isolation directory must be owned by the current private user")
    return LinuxDirectoryAuthorityV1(
        locator=str(path),
        role=role,
        owner_uid=info.st_uid,
        owner_gid=info.st_gid,
        native_identity=native_identity(info),
    )


def authority_sha(value: LinuxDirectoryAuthorityV1) -> str:
    return digest(canonical(value.model_dump(mode="json")))


def revalidate_file(expected: LinuxFileAuthorityV1) -> None:
    observed = plain_file_authority(Path(expected.locator))
    if observed != expected:
        raise ValueError("A required isolation file authority changed")


def revalidate_tool(expected: LinuxToolAuthorityV1) -> None:
    observed = file_authority(Path(expected.locator), expected.name)
    if observed != expected:
        raise ValueError("A required isolation tool authority changed")


def revalidate_full_mode_tool(expected: LinuxToolAuthorityV4) -> None:
    observed = full_mode_authority(Path(expected.locator), expected.name)
    if observed != expected:
        raise ValueError("A required full-mode isolation tool authority changed")


def revalidate_directory(expected: LinuxDirectoryAuthorityV1) -> None:
    observed = directory_authority(Path(expected.locator), expected.role)
    if observed != expected:
        raise ValueError("A required isolation directory authority changed")


def revalidate_profile_sources(
    profile: LinuxIsolationProfileV11, child_script: Path, bundle: Path
) -> None:
    revalidate_tool(profile.payload.system_unshare)
    revalidate_tool(profile.payload.unshare)
    revalidate_full_mode_tool(profile.payload.mount)
    revalidate_file(profile.payload.bootstrap_python)
    for source in profile.payload.source_directories:
        revalidate_directory(source)
    parent_script = Path(__file__).resolve(strict=True)
    if (
        file_sha256(parent_script) != profile.payload.probe_sha256
        or file_sha256(child_script) != profile.payload.child_probe_sha256
        or tree_identity(bundle) != profile.payload.native_bundle_id
    ):
        raise ValueError("A required isolation source changed")
    broker_path = Path(linux_broker_module.__file__ or "").resolve(strict=True)
    broker = profile.payload.broker
    if (
        file_sha256(broker_path) != broker.broker_module_sha256
        or os.getpid() != broker.broker_host_pid
        or process_start_time(os.getpid()) != broker.broker_host_start_time_ticks
        or current_uid() != broker.broker_host_uid
    ):
        raise ValueError("Linux broker host authority changed")
    repo = Path(__file__).resolve(strict=True).parents[1]
    if (
        apparmor_authority(repo, profile.payload.implementation_commit)
        != profile.payload.host.apparmor
    ):
        raise ValueError("AppArmor host authority changed")


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


def namespace_id(kind: str) -> str:
    return os.readlink(f"/proc/self/ns/{kind}")


def parse_os_release(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        values[key] = raw.strip().strip('"')
    return values


def host_authority(
    unshare: Path, apparmor_authority_value: LinuxAppArmorAuthorityV2
) -> LinuxHostAuthorityV3:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Native isolation probe requires Linux x86_64")
    os_release = Path("/etc/os-release")
    release = parse_os_release(os_release)
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
        raise ValueError("Native isolation probe is qualified only for Ubuntu 24.04")
    apparmor_path = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if not apparmor_path.is_file() or apparmor_path.read_text(encoding="ascii").strip() != "1":
        raise ValueError("AppArmor unprivileged userns restriction must remain enabled")
    userns = subprocess.run(
        [str(unshare), "--user", "--map-user=1000", "--map-group=1000", "/usr/bin/true"],
        capture_output=True,
        check=False,
        timeout=10,
    )
    if userns.returncode != 0:
        raise ValueError("Rootless user namespace creation is unavailable")
    cgroup = Path("/sys/fs/cgroup/cgroup.controllers")
    if not cgroup.is_file():
        raise ValueError("cgroup v2 is unavailable")
    current_cgroup = Path("/sys/fs/cgroup")
    for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines():
        if line.startswith("0::"):
            current_cgroup /= line[3:].lstrip("/")
            break
    delegated = os.access(current_cgroup / "cgroup.subtree_control", os.W_OK)
    kernel_abi = landlock_abi()
    return LinuxHostAuthorityV3(
        os_release_sha256=file_sha256(os_release),
        kernel_release=platform.release(),
        kernel_version_sha256=sha256(platform.version().encode("utf-8")),
        apparmor=apparmor_authority_value,
        kernel_landlock_abi=kernel_abi,
        enforced_landlock_abi=enforced_landlock_abi(kernel_abi),
        delegated_cgroup_available=delegated,
    )


def mount_authorities(
    sources: tuple[LinuxDirectoryAuthorityV1, ...],
) -> tuple[LinuxMountAuthorityV1, ...]:
    identities = {item.role: authority_sha(item) for item in sources}
    values = [
        LinuxMountAuthorityV1(
            target="/bundle",
            kind="bundle_read_only",
            source_identity_sha256=identities["fixture"],
            read_only=True,
            nodev=True,
            noexec=False,
        ),
        LinuxMountAuthorityV1(
            target="/dev", kind="dev_tmpfs", read_only=False, nodev=False, noexec=True
        ),
        LinuxMountAuthorityV1(
            target="/home/devfabric",
            kind="tmpfs_home",
            read_only=False,
            nodev=True,
            noexec=True,
        ),
        LinuxMountAuthorityV1(
            target="/output",
            kind="output_read_write",
            source_identity_sha256=identities["output"],
            read_only=False,
            nodev=True,
            noexec=True,
        ),
        LinuxMountAuthorityV1(
            target="/proc", kind="proc", read_only=False, nodev=True, noexec=True
        ),
        LinuxMountAuthorityV1(
            target="/run/devfabric",
            kind="broker_read_only",
            source_identity_sha256=identities["broker"],
            read_only=True,
            nodev=True,
            noexec=True,
        ),
        LinuxMountAuthorityV1(
            target="/state",
            kind="state_read_write",
            source_identity_sha256=identities["state"],
            read_only=False,
            nodev=True,
            noexec=True,
        ),
        LinuxMountAuthorityV1(
            target="/tmp", kind="tmpfs_tmp", read_only=False, nodev=True, noexec=True
        ),
    ]
    return tuple(sorted(values, key=lambda item: item.target))


def process_start_time(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    end_command = raw.rfind(")")
    fields = raw[end_command + 2 :].split()
    if end_command < 0 or len(fields) < 20:
        raise ValueError("Registered child process stat is incomplete")
    return int(fields[19])


def is_descendant(pid: int, ancestor: int) -> bool:
    current = pid
    for _ in range(64):
        if current == ancestor:
            return True
        status = Path(f"/proc/{current}/status")
        if not status.exists():
            return False
        parent = 0
        for line in status.read_text(encoding="ascii").splitlines():
            if line.startswith("PPid:"):
                parent = int(line.split()[1])
                break
        if parent <= 0 or parent == current:
            return False
        current = parent
    return False


def process_group_absent(process_group: int) -> bool:
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            raw = (entry / "stat").read_text(encoding="ascii")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        end_command = raw.rfind(")")
        fields = raw[end_command + 2 :].split()
        if end_command >= 0 and len(fields) >= 3 and int(fields[2]) == process_group:
            return False
    return True


def read_line(fd: int, timeout: float) -> bytes:
    ready, _, _ = select.select([fd], [], [], timeout)
    if not ready:
        raise TimeoutError("Isolation child registration timed out")
    raw = os.read(fd, 4096)
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise ValueError("Isolation child registration frame is invalid")
    return raw[:-1]


class BoundedCollector:
    def __init__(self) -> None:
        self.data = bytearray()
        self.observed = 0
        self.hard_limit = False

    def read(self, stream: Any, stop: threading.Event) -> None:
        while chunk := stream.read(64 * 1024):
            self.observed += len(chunk)
            remaining = RETAINED_LIMIT - len(self.data)
            if remaining > 0:
                self.data.extend(chunk[:remaining])
            if self.observed > HARD_LIMIT:
                self.hard_limit = True
                stop.set()

    @property
    def truncated(self) -> bool:
        return len(self.data) < self.observed


class ProbeProcessCapture:
    def __init__(self) -> None:
        self.stdout = BoundedCollector()
        self.stderr = BoundedCollector()
        self.process_started = False
        self.returncode: int | None = None
        self.cleanup_failed = False
        self.child_bootstrap_failure: LinuxChildBootstrapFailureV3 | None = None
        self.child_runtime_failure: LinuxChildRuntimeFailureV2 | None = None
        self.host_broker_failure: LinuxHostBrokerFailureV1 | None = None


class ProbePhaseFailure(ValueError):
    def __init__(self, phase: FailurePhase, message: str) -> None:
        super().__init__(message)
        self.phase = phase


class ChildRegistrationFailure(ProbePhaseFailure):
    """The launched child exited or failed before a valid registration frame."""

    def __init__(self, message: str) -> None:
        super().__init__("child_registration", message)


class ChildBootstrapFailure(ChildRegistrationFailure):
    def __init__(self, frame: LinuxChildBootstrapFailureV3) -> None:
        super().__init__("Isolation child reported a bounded bootstrap failure")
        self.frame = frame


class ChildRuntimeFailure(ProbePhaseFailure):
    def __init__(self, frame: LinuxChildRuntimeFailureV2) -> None:
        phase = {
            "private_root": "private_root",
            "rlimits": "child_result",
            "capability_drop": "capability_drop",
            "landlock": "landlock",
            "negative_probes": "negative_probes",
            "broker": "broker",
            "result_assembly": "child_result",
        }[frame.payload.stage]
        super().__init__(
            cast(FailurePhase, phase), "Isolation child reported a bounded runtime failure"
        )
        self.frame = frame


def host_broker_failure_frame(
    profile: LinuxIsolationProfileV11, error: LinuxMetadataBrokerFailure
) -> LinuxHostBrokerFailureV1:
    """Bind one bounded host diagnostic to the exact active authority."""

    return LinuxHostBrokerFailureV1.create(
        LinuxHostBrokerFailurePayloadV1(
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            environment_instance_id=profile.payload.environment_instance_id,
            checkpoint=cast(
                Literal[
                    "construction",
                    "thread_creation",
                    "thread_start",
                    "worker",
                    "parent_validation",
                    "bind",
                    "chmod",
                    "listen",
                    "accept",
                    "peer_credentials",
                    "peer_start_time",
                    "request_parse",
                    "denial_response",
                    "upstream_connect",
                    "upstream_send",
                    "upstream_read",
                    "client_forwarding",
                    "cleanup",
                ],
                error.checkpoint,
            ),
            reason_code=cast(
                Literal[
                    "construction_failed",
                    "thread_creation_failed",
                    "thread_start_failed",
                    "worker_failed",
                    "parent_validation_failed",
                    "bind_failed",
                    "chmod_failed",
                    "listen_failed",
                    "accept_failed",
                    "peer_credentials_failed",
                    "peer_start_time_failed",
                    "request_parse_failed",
                    "denial_response_failed",
                    "upstream_connect_failed",
                    "upstream_send_failed",
                    "upstream_read_failed",
                    "client_forwarding_failed",
                    "cleanup_failed",
                ],
                str(error),
            ),
            failure_kind=cast(
                Literal[
                    "os_error",
                    "authority_validation",
                    "response_bound_exceeded",
                    "cleanup_error",
                    "internal_error",
                ],
                error.failure_kind,
            ),
            errno_category=cast(
                Literal[
                    "address_in_use",
                    "connection_refused",
                    "connection_reset",
                    "broken_pipe",
                    "timed_out",
                    "permission_denied",
                    "other_os_error",
                ]
                | None,
                error.errno_category,
            ),
            completed_outcomes=cast(
                tuple[Literal["/api/version", "/api/tags", "/api/show", "denied"], ...],
                error.completed_outcomes,
            ),
        )
    )


def record_host_broker_failure(
    profile: LinuxIsolationProfileV11,
    capture: ProbeProcessCapture,
    checkpoint: str,
    cause: BaseException,
    completed_outcomes: tuple[str, ...] = (),
) -> LinuxMetadataBrokerFailure:
    """Retain one bounded host diagnostic for every broker-phase failure."""

    failure = (
        cause
        if isinstance(cause, LinuxMetadataBrokerFailure)
        else LinuxMetadataBrokerFailure(checkpoint, completed_outcomes, cause)
    )
    capture.host_broker_failure = host_broker_failure_frame(profile, failure)
    return failure


def projected_failure_diagnostics(
    capture: ProbeProcessCapture,
) -> tuple[LinuxChildRuntimeFailureV2 | None, LinuxHostBrokerFailureV1 | None]:
    """Project only diagnostics compatible with the primary sealed failure."""

    child = capture.child_runtime_failure
    host = capture.host_broker_failure
    if host is not None and child is not None and child.payload.stage != "broker":
        child = None
    return child, host


def validate_child_bootstrap_failure(
    profile: LinuxIsolationProfileV11,
    frame: LinuxChildBootstrapFailureV3,
    child_script: Path,
    bundle: Path,
) -> None:
    """Join a self-hashed child diagnostic to the exact host profile authority."""

    if (
        frame.payload.reason_code == "mount_pre_exec_identity_mismatch"
        and frame.payload.expected_native_identity != profile.payload.mount.native_identity
    ):
        raise ChildRegistrationFailure(
            "Isolation child native identity expectation differs from profile authority"
        )
    revalidate_profile_sources(profile, child_script, bundle)


def validate_child_runtime_failure(
    profile: LinuxIsolationProfileV11,
    frame: LinuxChildRuntimeFailureV2,
    child_script: Path,
    bundle: Path,
) -> None:
    if profile.payload.child_runtime_failure_protocol != frame.payload.frame_kind:
        raise ValueError("Isolation child runtime failure protocol differs from profile")
    revalidate_profile_sources(profile, child_script, bundle)


def expected_broker_cancellation(errors: list[BaseException], *, child_exited: bool) -> bool:
    return (
        bool(errors)
        and child_exited
        and all(
            isinstance(error, TimeoutError) and str(error) == "Linux metadata broker was cancelled"
            for error in errors
        )
    )


class ProbeCleanupFailure(ValueError):
    """One or more child cleanup operations failed after launch."""


def exhaustive_cleanup(actions: tuple[Callable[[], object], ...]) -> list[BaseException]:
    """Attempt every independent cleanup action and return bounded typed failures."""

    failures: list[BaseException] = []
    for action in actions:
        try:
            action()
        except BaseException as error:
            failures.append(error)
    return failures


def cleanup_failure(errors: list[BaseException]) -> ProbeCleanupFailure:
    kinds = ",".join(sorted({type(error).__name__ for error in errors}))
    return ProbeCleanupFailure(f"Isolation child cleanup failed: {kinds}")


def bind_stub_ollama(host: str = "127.0.0.1", port: int = 11434) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((host, port))
        server.listen(3)
        server.settimeout(0.2)
    except BaseException:
        server.close()
        raise
    return server


def synthetic_upstream_authority(server: socket.socket) -> LinuxSyntheticUpstreamAuthorityV1:
    if (
        server.family != socket.AF_INET
        or server.type & socket.SOCK_STREAM != socket.SOCK_STREAM
        or server.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
    ):
        raise ValueError("Synthetic upstream must be one retained listening TCP socket")
    host, port = server.getsockname()
    info = os.fstat(server.fileno())
    return LinuxSyntheticUpstreamAuthorityV1(
        host=host,
        port=port,
        socket_inode=info.st_ino,
        owner_pid=os.getpid(),
        owner_start_time_ticks=process_start_time(os.getpid()),
        owner_uid=current_uid(),
    )


def revalidate_synthetic_upstream(
    server: socket.socket, expected: LinuxSyntheticUpstreamAuthorityV1
) -> None:
    if synthetic_upstream_authority(server) != expected:
        raise ValueError("Synthetic upstream listener authority changed before launch")


def stub_ollama(
    server: socket.socket,
    stop: threading.Event,
    outcomes: list[str],
    errors: list[BaseException],
) -> None:
    try:
        while len(outcomes) < 3 and not stop.is_set():
            try:
                connection, _ = server.accept()
            except TimeoutError:
                continue
            with connection:
                raw = bytearray()
                while b"\r\n\r\n" not in raw and len(raw) <= 64 * 1024:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    raw.extend(chunk)
                line = bytes(raw).split(b"\r\n", 1)[0].decode("ascii")
                path = line.split(" ")[1]
                if path not in {"/api/version", "/api/tags", "/api/show"}:
                    raise ValueError("Broker forwarded a non-metadata endpoint")
                outcomes.append(path)
                body = b"{}"
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
    except BaseException as error:
        errors.append(error)
        stop.set()
    finally:
        server.close()


def namespace_command(
    profile: LinuxIsolationProfileV11,
    child_script: Path,
    root: Path,
    bundle: Path,
    state: Path,
    output: Path,
    broker_dir: Path,
    registration_write: int,
    result_write: int,
    host_namespaces: dict[str, str],
) -> list[str]:
    return [
        profile.payload.unshare.locator,
        "--user",
        "--map-user=1000",
        "--map-group=1000",
        "--keep-caps",
        "--mount",
        "--pid",
        "--fork",
        "--kill-child=KILL",
        "--net",
        profile.payload.bootstrap_python.locator,
        *profile.payload.child_python_flags,
        str(child_script),
        "--root",
        str(root),
        "--bundle",
        str(bundle),
        "--state",
        str(state),
        "--output",
        str(output),
        "--broker",
        str(broker_dir),
        "--mount-binary",
        profile.payload.mount.locator,
        "--expected-mount-authority",
        json.dumps(
            profile.payload.mount.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ),
        "--expected-mount-version-environment",
        json.dumps(
            profile.payload.mount_version_environment.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ),
        "--expected-overflow-uid",
        str(profile.payload.mount_owner_projection.overflow_uid),
        "--expected-overflow-gid",
        str(profile.payload.mount_owner_projection.overflow_gid),
        "--registration-fd",
        str(registration_write),
        "--result-fd",
        str(result_write),
        "--host-namespaces",
        json.dumps(host_namespaces, sort_keys=True, separators=(",", ":")),
        "--expected-mount-targets",
        json.dumps([item.target for item in profile.payload.mounts], separators=(",", ":")),
        "--expected-kernel-landlock-abi",
        str(profile.payload.host.kernel_landlock_abi),
        "--expected-enforced-landlock-abi",
        str(profile.payload.host.enforced_landlock_abi),
        "--expected-landlock-mask",
        str(profile.payload.landlock_handled_access),
        "--expected-rlimits-sha256",
        digest(canonical(profile.payload.rlimits.model_dump(mode="json"))),
        "--expected-apparmor-current",
        LINUX_APPARMOR_CURRENT,
        "--linux-isolation-profile-id",
        profile.linux_isolation_profile_id,
        "--environment-instance-id",
        profile.payload.environment_instance_id,
    ]


def validate_registered_observation(
    raw_observation: dict[str, object],
    registered: LinuxChildRegistrationPayloadV3,
) -> LinuxIsolationObservationV11:
    observation = LinuxIsolationObservationV11.model_validate_json(
        canonical(cast(JsonValue, raw_observation))
    )
    if observation.mount_authority != registered.mount_authority:
        raise ValueError("Isolation child result/registration mount authority mismatch")
    return observation


def run_probe(
    profile: LinuxIsolationProfileV11,
    child_script: Path,
    root: Path,
    bundle: Path,
    state: Path,
    output: Path,
    broker_dir: Path,
    stub_server: socket.socket,
    capture: ProbeProcessCapture,
) -> LinuxIsolationObservationV11:
    owned_fds: set[int] = set()
    process: subprocess.Popen[bytes] | None = None
    collectors: list[threading.Thread] = []
    stop_capture = threading.Event()
    broker_error: list[BaseException] = []
    broker_outcomes: list[str] = []
    stub_stop = threading.Event()
    broker_stop = threading.Event()
    stub_outcomes: list[str] = []
    stub_errors: list[BaseException] = []
    stub_thread: threading.Thread | None = None
    broker_thread: threading.Thread | None = None
    primary_error: BaseException | None = None
    active_phase: FailurePhase = "namespace_creation"
    result: bytes | None = None
    runtime_failure: LinuxChildRuntimeFailureV2 | None = None

    def close_owned(descriptor: int) -> None:
        os.close(descriptor)
        owned_fds.remove(descriptor)

    try:
        revalidate_profile_sources(profile, child_script, bundle)
        registration_read, registration_write = os.pipe()
        owned_fds.update((registration_read, registration_write))
        result_read, result_write = os.pipe()
        owned_fds.update((result_read, result_write))
        host_namespaces = {kind: namespace_id(kind) for kind in ("user", "mnt", "pid", "net")}
        command = namespace_command(
            profile,
            child_script,
            root,
            bundle,
            state,
            output,
            broker_dir,
            registration_write,
            result_write,
            host_namespaces,
        )
        revalidate_synthetic_upstream(stub_server, profile.payload.synthetic_upstream)
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(registration_write, result_write),
            start_new_session=True,
            env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1"},
        )
        capture.process_started = True
        close_owned(registration_write)
        close_owned(result_write)
        if process.stdout is None or process.stderr is None:
            raise ValueError("Isolation child diagnostic streams are unavailable")
        collectors = [
            threading.Thread(
                target=capture.stdout.read, args=(process.stdout, stop_capture), daemon=True
            ),
            threading.Thread(
                target=capture.stderr.read, args=(process.stderr, stop_capture), daemon=True
            ),
        ]
        for thread in collectors:
            thread.start()
        stub_thread = threading.Thread(
            target=stub_ollama,
            args=(stub_server, stub_stop, stub_outcomes, stub_errors),
            daemon=True,
        )
        active_phase = "child_registration"
        try:
            raw_registration = json.loads(read_line(registration_read, 15))
        except (TimeoutError, ValueError) as error:
            raise ChildRegistrationFailure("Isolation child registration failed") from error
        if (
            isinstance(raw_registration, dict)
            and isinstance(raw_registration.get("payload"), dict)
            and raw_registration["payload"].get("frame_kind") == "linux_child_bootstrap_failure_v3"
        ):
            try:
                bootstrap_failure = LinuxChildBootstrapFailureV3.model_validate(raw_registration)
            except ValueError as error:
                raise ChildRegistrationFailure(
                    "Isolation child bootstrap failure frame is invalid"
                ) from error
            validate_child_bootstrap_failure(profile, bootstrap_failure, child_script, bundle)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired as error:
                raise ChildRegistrationFailure(
                    "Isolation child bootstrap failure process did not exit"
                ) from error
            if process.returncode != 70:
                raise ChildRegistrationFailure(
                    "Isolation child bootstrap failure exit code is invalid"
                )
            capture.child_bootstrap_failure = bootstrap_failure
            raise ChildBootstrapFailure(bootstrap_failure)
        try:
            registration = LinuxChildRegistrationV3.model_validate(raw_registration)
        except ValueError as error:
            raise ChildRegistrationFailure(
                "Isolation child registration frame is invalid"
            ) from error
        registered = registration.payload
        outer_pid = registered.outer_pid
        outer_uid = registered.outer_uid
        expected_projection = profile.payload.mount_owner_projection
        observed_projection = registered.mount_owner_projection
        if (
            registered.apparmor_current_profile != LINUX_APPARMOR_CURRENT
            or outer_uid != current_uid()
            or not is_descendant(outer_pid, process.pid)
            or process_start_time(outer_pid) != registered.start_time_ticks
            or Path(f"/proc/{outer_pid}").stat().st_uid != outer_uid
            or observed_projection.host_owner_uid != expected_projection.host_owner_uid
            or observed_projection.host_owner_gid != expected_projection.host_owner_gid
            or observed_projection.overflow_uid != expected_projection.overflow_uid
            or observed_projection.overflow_gid != expected_projection.overflow_gid
        ):
            raise ValueError("Isolation child outer/inner process identity mismatch")
        peer = LinuxBrokerPeerAuthorityV1(
            outer_pid=outer_pid,
            outer_uid=outer_uid,
            start_time_ticks=registered.start_time_ticks,
        )
        active_phase = "broker"
        revalidate_synthetic_upstream(stub_server, profile.payload.synthetic_upstream)
        stub_thread.start()
        try:
            broker = LinuxMetadataBrokerV1(
                broker_dir / "ollama.sock",
                peer,
                synthetic_upstream=profile.payload.synthetic_upstream,
            )
        except BaseException as error:
            record_host_broker_failure(profile, capture, "construction", error)
            raise ProbePhaseFailure("broker", "Isolation broker construction failed") from error

        def serve() -> None:
            try:
                broker_outcomes.extend(
                    broker.serve_requests(5, stop_event=broker_stop, deadline=time.monotonic() + 60)
                )
            except LinuxMetadataBrokerFailure as error:
                broker_error.append(
                    record_host_broker_failure(profile, capture, error.checkpoint, error)
                )
            except BaseException as error:
                broker_error.append(error)

        try:
            broker_thread = threading.Thread(target=serve, daemon=True)
        except BaseException as error:
            record_host_broker_failure(profile, capture, "thread_creation", error)
            raise ProbePhaseFailure("broker", "Isolation broker thread creation failed") from error
        try:
            broker_thread.start()
        except BaseException as error:
            record_host_broker_failure(profile, capture, "thread_start", error)
            raise ProbePhaseFailure("broker", "Isolation broker thread start failed") from error
        deadline = time.monotonic() + 60
        while process.poll() is None and time.monotonic() < deadline and not stop_capture.is_set():
            time.sleep(0.02)
        if process.poll() is None:
            kill_process_group(process.pid)
        process.wait(timeout=10)
        active_phase = "child_result"
        try:
            result = read_line(result_read, 5)
            raw_result = json.loads(result)
        except (TimeoutError, ValueError, json.JSONDecodeError):
            raw_result = None
        if (
            isinstance(raw_result, dict)
            and isinstance(raw_result.get("payload"), dict)
            and raw_result["payload"].get("frame_kind") == "linux_child_runtime_failure_v2"
        ):
            try:
                runtime_failure = LinuxChildRuntimeFailureV2.model_validate(raw_result)
            except ValueError as error:
                raise ProbePhaseFailure(
                    "child_result", "Isolation child runtime failure frame is invalid"
                ) from error
            validate_child_runtime_failure(profile, runtime_failure, child_script, bundle)
            if process.returncode != 71:
                raise ProbePhaseFailure(
                    "child_result", "Isolation child runtime failure exit code is invalid"
                )
            capture.child_runtime_failure = runtime_failure
        broker_stop.set()
        broker_thread.join(timeout=5)
        stub_stop.set()
        stub_thread.join(timeout=5)
        if broker_thread.is_alive() or stub_thread.is_alive():
            raise ValueError("Isolation broker or stub did not terminate")
        if broker_error and not expected_broker_cancellation(
            broker_error, child_exited=process.returncode is not None
        ):
            if capture.host_broker_failure is None:
                record_host_broker_failure(
                    profile, capture, "worker", broker_error[0], tuple(broker_outcomes)
                )
            raise ProbePhaseFailure(
                "broker", f"Isolation broker failed: {type(broker_error[0]).__name__}"
            )
        if runtime_failure is not None:
            raise ChildRuntimeFailure(runtime_failure)
        active_phase = "child_result"
        if process.returncode != 0 or capture.stdout.hard_limit or capture.stderr.hard_limit:
            raise ValueError("Isolation child failed or exceeded its output bound")
        if result is None:
            raise ValueError("Isolation child result is absent")
        if stub_errors:
            raise ValueError(f"Fixed Ollama stub failed: {type(stub_errors[0]).__name__}")
        active_phase = "negative_probes"
        if broker_outcomes != ["/api/version", "/api/tags", "/api/show", "denied", "denied"]:
            raise ValueError("Isolation broker endpoint outcomes differ")
        if stub_outcomes != ["/api/version", "/api/tags", "/api/show"]:
            raise ValueError("Fixed Ollama stub observed a non-canonical request set")
        active_phase = "child_result"
        raw_observation = json.loads(result)
        raw_observation["broker"].update(
            {
                "peer_pid_matched": True,
                "peer_start_time_matched": True,
                "peer_uid_matched": True,
            }
        )
        raw_observation["synthetic_upstream"] = LinuxSyntheticUpstreamObservationV1(
            authority=profile.payload.synthetic_upstream
        ).model_dump(mode="json")
        raw_observation["descendant_cleanup_passed"] = True
        raw_observation["cleanup_failures"] = []
        observation = validate_registered_observation(raw_observation, registered)
        if Path(f"/proc/{process.pid}").exists() or not process_group_absent(process.pid):
            raise ValueError("Isolation launcher process group remained after process exit")
        revalidate_profile_sources(profile, child_script, bundle)
        if (broker_dir / "ollama.sock").exists():
            raise ValueError("Isolation broker socket remained after shutdown")
        return observation
    except ChildRegistrationFailure as error:
        primary_error = error
        raise
    except ProbePhaseFailure as error:
        primary_error = error
        raise
    except BaseException as error:
        if active_phase == "broker" and capture.host_broker_failure is None:
            record_host_broker_failure(profile, capture, "worker", error, tuple(broker_outcomes))
        phased_error = ProbePhaseFailure(active_phase, f"Isolation {active_phase} phase failed")
        primary_error = phased_error
        raise phased_error from error
    finally:
        stub_stop.set()
        broker_stop.set()
        cleanup_errors: list[BaseException] = []
        process_actions: list[Callable[[], object]] = []
        if process is not None:
            should_kill = True

            def observe_process_state() -> None:
                nonlocal should_kill
                should_kill = process.poll() is None

            cleanup_errors.extend(exhaustive_cleanup((observe_process_state,)))
            if should_kill:
                process_actions.append(lambda: kill_process_group(process.pid))
            process_actions.append(lambda: process.wait(timeout=10))
        cleanup_errors.extend(exhaustive_cleanup(tuple(process_actions)))
        if process is not None:

            def record_returncode() -> None:
                capture.returncode = process.poll()

            cleanup_errors.extend(exhaustive_cleanup((record_returncode,)))

        def join_thread(thread: threading.Thread, label: str, timeout: float = 5) -> None:
            thread.join(timeout=timeout)
            if thread.is_alive():
                raise ValueError(f"{label} did not stop")

        cleanup_errors.extend(
            exhaustive_cleanup(
                tuple(
                    partial(join_thread, thread, "Isolation child diagnostic stream")
                    for thread in collectors
                    if thread.ident is not None
                )
            )
        )
        if broker_thread is not None and broker_thread.ident is not None:
            cleanup_errors.extend(
                exhaustive_cleanup(
                    (partial(join_thread, broker_thread, "Isolation broker thread"),)
                )
            )
        if stub_thread is not None and stub_thread.ident is not None:
            cleanup_errors.extend(
                exhaustive_cleanup((partial(join_thread, stub_thread, "Isolation stub thread"),))
            )
        else:
            cleanup_errors.extend(exhaustive_cleanup((stub_server.close,)))
        if process is not None:
            stream_actions = tuple(
                stream.close for stream in (process.stdout, process.stderr) if stream is not None
            )
            cleanup_errors.extend(exhaustive_cleanup(stream_actions))
        cleanup_errors.extend(
            exhaustive_cleanup(
                tuple(partial(os.close, descriptor) for descriptor in tuple(owned_fds))
            )
        )
        cleanup_errors.extend(
            exhaustive_cleanup(
                tuple(
                    partial(join_thread, thread, "Isolation child diagnostic stream", timeout=1)
                    for thread in collectors
                    if thread.ident is not None
                )
            )
        )
        capture.cleanup_failed = bool(cleanup_errors)
        if cleanup_errors:
            raise cleanup_failure(cleanup_errors) from primary_error


def verified_git_head(repo: Path, expected: str) -> None:
    head = (
        subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, check=True, timeout=10
        )
        .stdout.decode("ascii")
        .strip()
    )
    dirty = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo,
        capture_output=True,
        check=True,
        timeout=10,
    ).stdout
    if head != expected or dirty:
        raise ValueError("Isolation qualification requires the exact clean implementation commit")


def failure_reason(phase: FailurePhase, error: BaseException) -> tuple[FailureReason, int | None]:
    mapping: dict[FailurePhase, FailureReason] = {
        "host_inspection": "host_authority_invalid",
        "source_revalidation": "source_authority_changed",
        "namespace_creation": "namespace_launch_failed",
        "child_registration": "child_registration_invalid",
        "private_root": "private_root_failed",
        "capability_drop": "capability_drop_failed",
        "landlock": "landlock_failed",
        "broker": "broker_failed",
        "negative_probes": "negative_probe_failed",
        "child_result": "child_output_invalid",
        "cleanup": "cleanup_failed",
    }
    observed_errno = error.errno if isinstance(error, OSError) and error.errno else None
    return mapping.get(phase, "unexpected_internal_failure"), observed_errno


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--implementation-commit", required=True)
    parser.add_argument("--environment-instance-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--failure-output", type=Path, required=True)
    args = parser.parse_args()
    if not _COMMIT.fullmatch(args.implementation_commit):
        raise SystemExit("Implementation commit must be one lowercase full Git SHA")
    root_script = Path(__file__).resolve(strict=True)
    child_script = root_script.with_name("linux_native_isolation_child.py").resolve(strict=True)
    if args.output.exists() or args.failure_output.exists():
        raise SystemExit("Isolation evidence output already exists")
    environment = args.environment_instance_id
    profile: LinuxIsolationProfileV11 | None = None
    capture = ProbeProcessCapture()
    phase: FailurePhase = "host_inspection"
    cleanup_succeeded = False
    scratch: Path | None = None
    stub_server: socket.socket | None = None
    try:
        repo = root_script.parents[1]
        verified_git_head(repo, args.implementation_commit)
        with tempfile.TemporaryDirectory(prefix="devfabric-linux-isolation-") as temporary:
            temp = Path(temporary).resolve(strict=True)
            scratch = temp
            bundle = temp / "bundle"
            state = temp / "state"
            output = temp / "output"
            broker = temp / "broker"
            root = temp / "root"
            for directory in (bundle, state, output, broker, root):
                directory.mkdir(mode=0o700)
            (bundle / "mechanics-only.txt").write_text(
                "native Linux isolation mechanics; not a runnable bundle\n", encoding="ascii"
            )
            system_unshare_path = Path(LINUX_SYSTEM_UNSHARE)
            unshare_path = Path(LINUX_PRIVATE_UNSHARE)
            mount_path = Path("/usr/bin/mount")
            apparmor = apparmor_authority(repo, args.implementation_commit)
            host = host_authority(unshare_path, apparmor)
            system_unshare = file_authority(system_unshare_path, "unshare")
            unshare = file_authority(unshare_path, "unshare")
            mount = full_mode_authority(mount_path, "mount")
            if mount.owner_uid != 0 or mount.owner_gid != 0:
                raise ValueError("Linux mount authority is not root-owned")
            mount_owner_projection = LinuxNamespaceOwnerProjectionExpectationV1(
                overflow_uid=configured_overflow_id(Path("/proc/sys/kernel/overflowuid")),
                overflow_gid=configured_overflow_id(Path("/proc/sys/kernel/overflowgid")),
            )
            bootstrap_python = plain_file_authority(Path(sys.executable).resolve(strict=True))
            bundle_id = tree_identity(bundle)
            sources = tuple(
                sorted(
                    (
                        directory_authority(broker, "broker"),
                        directory_authority(bundle, "fixture"),
                        directory_authority(output, "output"),
                        directory_authority(root, "scratch_root"),
                        directory_authority(state, "state"),
                    ),
                    key=lambda item: item.role,
                )
            )
            mounts = mount_authorities(sources)
            if linux_broker_module.__file__ is None:
                raise ValueError("Linux broker module has no file identity")
            broker_module = Path(linux_broker_module.__file__).resolve(strict=True)
            broker_expectation = LinuxBrokerExpectationV1(
                broker_host_pid=os.getpid(),
                broker_host_start_time_ticks=process_start_time(os.getpid()),
                broker_host_uid=current_uid(),
                broker_module_sha256=file_sha256(broker_module),
            )
            stub_server = bind_stub_ollama(port=0)
            synthetic_upstream = synthetic_upstream_authority(stub_server)
            profile = LinuxIsolationProfileV11.create(
                LinuxIsolationProfilePayloadV11(
                    environment_instance_id=environment,
                    implementation_commit=args.implementation_commit,
                    native_bundle_id=bundle_id,
                    bundle_manifest_sha256=bundle_id,
                    bootstrap_python=bootstrap_python,
                    probe_sha256=file_sha256(root_script),
                    child_probe_sha256=file_sha256(child_script),
                    host=host,
                    system_unshare=system_unshare,
                    unshare=unshare,
                    mount=mount,
                    source_directories=sources,
                    mounts=mounts,
                    broker=broker_expectation,
                    synthetic_upstream=synthetic_upstream,
                    mount_owner_projection=mount_owner_projection,
                    mount_version_environment=MOUNT_VERSION_ENVIRONMENT,
                    landlock_handled_access=landlock_handled_access(host.enforced_landlock_abi),
                )
            )
            phase = "source_revalidation"
            if file_sha256(root_script) != profile.payload.probe_sha256:
                raise ValueError("Isolation parent probe changed before launch")
            phase = "namespace_creation"
            observation = run_probe(
                profile,
                child_script,
                root,
                bundle,
                state,
                output,
                broker,
                stub_server,
                capture,
            )
            close_errors = exhaustive_cleanup((stub_server.close,))
            if close_errors:
                capture.cleanup_failed = True
                raise cleanup_failure(close_errors)
            stub_server = None
        cleanup_succeeded = not temp.exists()
        if not cleanup_succeeded:
            raise ValueError("Isolation scratch cleanup verification failed")
        receipt = LinuxIsolationReceiptV11.create(
            LinuxIsolationReceiptPayloadV11(
                linux_isolation_profile_id=profile.linux_isolation_profile_id,
                environment_instance_id=environment,
                observation=observation,
            )
        )
        evidence = LinuxIsolationEvidenceV11.create(
            LinuxIsolationEvidencePayloadV11(
                profile=profile,
                receipt=receipt,
                child_stdout_retained_sha256=sha256(bytes(capture.stdout.data)),
                child_stderr_retained_sha256=sha256(bytes(capture.stderr.data)),
                child_stdout_retained_bytes=len(capture.stdout.data),
                child_stderr_retained_bytes=len(capture.stderr.data),
                child_stdout_truncated=capture.stdout.truncated,
                child_stderr_truncated=capture.stderr.truncated,
                cleanup=LinuxHostCleanupObservationV1(),
            )
        )
        write_new(args.output, canonical(evidence.model_dump(mode="json")))
    except BaseException as error:
        final_error = error
        if stub_server is not None:
            close_errors = exhaustive_cleanup((stub_server.close,))
            if close_errors:
                capture.cleanup_failed = True
                final_error = cleanup_failure(close_errors)
        if isinstance(final_error, ProbeCleanupFailure):
            phase = "cleanup"
        elif isinstance(final_error, ProbePhaseFailure):
            phase = final_error.phase
        cleanup_succeeded = (
            scratch is not None and not scratch.exists() and not capture.cleanup_failed
        )
        reason_code, observed_errno = failure_reason(phase, final_error)
        child_runtime_failure, host_broker_failure = projected_failure_diagnostics(capture)
        failure = LinuxIsolationFailureV7.create(
            LinuxIsolationFailurePayloadV7(
                linux_isolation_profile_id=(
                    profile.linux_isolation_profile_id if profile is not None else None
                ),
                environment_instance_id=environment,
                phase=phase,
                reason_code=reason_code,
                errno=observed_errno,
                child_stdout_retained_sha256=sha256(bytes(capture.stdout.data)),
                child_stderr_retained_sha256=sha256(bytes(capture.stderr.data)),
                child_stdout_truncated=capture.stdout.truncated,
                child_stderr_truncated=capture.stderr.truncated,
                child_process_started=capture.process_started,
                child_returncode=capture.returncode,
                child_stdout_retained_bytes=len(capture.stdout.data),
                child_stderr_retained_bytes=len(capture.stderr.data),
                child_stdout_observed_bytes=capture.stdout.observed,
                child_stderr_observed_bytes=capture.stderr.observed,
                child_bootstrap_failure=capture.child_bootstrap_failure,
                child_runtime_failure=child_runtime_failure,
                host_broker_failure=host_broker_failure,
                cleanup_attempted=scratch is not None,
                cleanup_succeeded=cleanup_succeeded,
            )
        )
        write_new(args.failure_output, canonical(failure.model_dump(mode="json")))
        if final_error is error:
            raise
        raise final_error from error


if __name__ == "__main__":
    main()
