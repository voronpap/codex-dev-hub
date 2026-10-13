#!/usr/bin/env python3
"""Create, run, and clean one exact native-Linux transient service cgroup."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import os
import platform
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Literal

from devhub.benchmark import canonical
from devhub.linux_isolation import (
    LINUX_CGROUP_ROOT,
    LINUX_REVIEWED_SYSTEMD_VERSION_SHA256,
    LINUX_SYSCALL_ALLOWLIST_COUNT,
    LINUX_SYSCALL_ALLOWLIST_SHA256,
    LINUX_SYSTEMCTL,
    LINUX_SYSTEMD_ANALYZE,
    LINUX_SYSTEMD_MANAGER,
    LINUX_SYSTEMD_RUN,
    LinuxCgroupBoundaryAuthorityV1,
    LinuxCgroupCleanupPayloadV2,
    LinuxCgroupCleanupPayloadV3,
    LinuxCgroupCleanupReceiptV2,
    LinuxCgroupCleanupReceiptV3,
    LinuxCgroupCleanupStatePayloadV2,
    LinuxCgroupCleanupStateV2,
    LinuxCgroupLifecycleFailurePayloadV1,
    LinuxCgroupLifecycleFailureV1,
    LinuxCgroupRollbackPayloadV1,
    LinuxCgroupRollbackPayloadV2,
    LinuxCgroupRollbackReceiptV1,
    LinuxCgroupRollbackReceiptV2,
    LinuxCgroupSetupStatePayloadV1,
    LinuxCgroupSetupStatePayloadV2,
    LinuxCgroupSetupStateV1,
    LinuxCgroupSetupStateV2,
    LinuxFileAuthorityV1,
    LinuxIsolationEvidenceV17,
    LinuxIsolationEvidenceV18,
    LinuxMatchedControlAuthorityV1,
    LinuxMatchedControlExecutionPayloadV1,
    LinuxMatchedControlExecutionV1,
    LinuxMatchedControlObservationV1,
    LinuxMatchedControlReceiptPayloadV1,
    LinuxMatchedControlReceiptV1,
    LinuxNativePathIdentityV1,
    LinuxRawPersonalityObservationV1,
    LinuxSyscallAllowlistAuthorityV1,
    LinuxSyscallFilterBoundaryAuthorityV1,
    LinuxSystemdAnalyzeAuthorityV1,
    LinuxSystemdControlPolicyObservationV1,
    LinuxSystemdManagerAuthorityV1,
    LinuxSystemdResourcePolicyObservationV1,
    LinuxSystemdToolAuthorityV1,
    LinuxSystemdUnitPolicyObservationV1,
    LinuxToolVersionEnvironmentV1,
)
from devhub.native_bundle import git_blob_sha256

_COMMIT = re.compile(r"^[a-f0-9]{40}$")
_ENVIRONMENT = re.compile(r"^[a-f0-9]{32}$")
_VERSION_ENVIRONMENT = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"}
_SYSCALL_SELECTORS = ("@system-service", "@mount", "@sandbox")
_PERSONALITY_QUERY = 0xFFFFFFFF
_SYS_PERSONALITY_X86_64 = 135


def file_sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def write_new(path: Path, raw: bytes, mode: int = 0o644) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def tool_authority(
    path: Path, name: Literal["systemd-run", "systemctl"]
) -> LinuxSystemdToolAuthorityV1:
    resolved = path.resolve(strict=True)
    if str(resolved) != str(path):
        raise ValueError("Systemd tool locator resolves through substitution")
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Systemd tool is not a regular file")
    version = subprocess.run(
        [str(path), "--version"],
        capture_output=True,
        check=True,
        timeout=10,
        env=_VERSION_ENVIRONMENT,
    )
    after = os.lstat(path)
    if (
        after.st_dev != info.st_dev
        or after.st_ino != info.st_ino
        or after.st_size != info.st_size
        or stat.S_IMODE(after.st_mode) != stat.S_IMODE(info.st_mode)
    ):
        raise ValueError("Systemd tool authority changed during version observation")
    return LinuxSystemdToolAuthorityV1(
        name=name,
        locator=str(path),
        sha256=file_sha256(path),
        size=info.st_size,
        owner_uid=info.st_uid,
        owner_gid=info.st_gid,
        mode=f"0{stat.S_IMODE(info.st_mode):03o}",
        native_identity=LinuxNativePathIdentityV1(device=info.st_dev, inode=info.st_ino),
        version_output_sha256=hashlib.sha256(version.stdout + version.stderr).hexdigest(),
    )


def plain_file_authority(path: Path) -> tuple[LinuxNativePathIdentityV1, os.stat_result, str]:
    resolved = path.resolve(strict=True)
    if str(resolved) != str(path):
        raise ValueError("Systemd authority locator resolves through substitution")
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Systemd authority is not a regular file")
    return (
        LinuxNativePathIdentityV1(device=info.st_dev, inode=info.st_ino),
        info,
        file_sha256(path),
    )


def file_authority(path: Path) -> LinuxFileAuthorityV1:
    resolved = path.resolve(strict=True)
    native, info, sha = plain_file_authority(resolved)
    return LinuxFileAuthorityV1(
        locator=str(resolved),
        sha256=sha,
        size=info.st_size,
        owner_uid=info.st_uid,
        owner_gid=info.st_gid,
        mode=f"0{stat.S_IMODE(info.st_mode):03o}",
        native_identity=native,
    )


def systemd_analyze_authority() -> LinuxSystemdAnalyzeAuthorityV1:
    path = Path(LINUX_SYSTEMD_ANALYZE)
    native, info, sha = plain_file_authority(path)
    version = subprocess.run(
        [str(path), "--version"],
        capture_output=True,
        check=True,
        timeout=10,
        env=_VERSION_ENVIRONMENT,
    )
    after_native, after_info, after_sha = plain_file_authority(path)
    if (
        after_native != native
        or after_info.st_size != info.st_size
        or stat.S_IMODE(after_info.st_mode) != stat.S_IMODE(info.st_mode)
        or after_sha != sha
    ):
        raise ValueError("systemd-analyze authority changed during version observation")
    return LinuxSystemdAnalyzeAuthorityV1(
        locator=str(path),
        sha256=sha,
        size=info.st_size,
        owner_uid=info.st_uid,
        owner_gid=info.st_gid,
        mode=f"0{stat.S_IMODE(info.st_mode):03o}",
        native_identity=native,
        version_output_sha256=hashlib.sha256(version.stdout + version.stderr).hexdigest(),
    )


def systemd_manager_authority() -> LinuxSystemdManagerAuthorityV1:
    manager_link = os.readlink("/proc/1/exe")
    if manager_link != LINUX_SYSTEMD_MANAGER:
        raise ValueError("PID 1 is not the reviewed systemd manager executable")
    path = Path(LINUX_SYSTEMD_MANAGER)
    native, info, sha = plain_file_authority(path)
    version = subprocess.run(
        [str(path), "--version"],
        capture_output=True,
        check=True,
        timeout=10,
        env=_VERSION_ENVIRONMENT,
    )
    stat_raw = Path("/proc/1/stat").read_text(encoding="ascii").strip()
    try:
        stat_tail = stat_raw.rsplit(") ", 1)[1].split()
    except IndexError as error:
        raise ValueError("PID 1 start-time identity is unavailable") from error
    if len(stat_tail) < 20:
        raise ValueError("PID 1 start-time identity is unavailable")
    start_time_ticks = int(stat_tail[19])
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    after_native, after_info, after_sha = plain_file_authority(path)
    after_stat_raw = Path("/proc/1/stat").read_text(encoding="ascii").strip()
    after_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    if (
        os.readlink("/proc/1/exe") != manager_link
        or after_native != native
        or after_info.st_size != info.st_size
        or stat.S_IMODE(after_info.st_mode) != stat.S_IMODE(info.st_mode)
        or after_sha != sha
        or after_stat_raw != stat_raw
        or after_boot_id != boot_id
    ):
        raise ValueError("PID 1 systemd authority changed during version observation")
    return LinuxSystemdManagerAuthorityV1(
        executable=LinuxFileAuthorityV1(
            locator=str(path),
            sha256=sha,
            size=info.st_size,
            owner_uid=info.st_uid,
            owner_gid=info.st_gid,
            mode=f"0{stat.S_IMODE(info.st_mode):03o}",
            native_identity=native,
        ),
        start_time_ticks=start_time_ticks,
        boot_id=boot_id,
        version_output_sha256=hashlib.sha256(version.stdout + version.stderr).hexdigest(),
    )


def _parse_selector_output(selector: str, raw: bytes) -> tuple[str, ...]:
    lines = raw.decode("utf-8", errors="strict").splitlines()
    if len(lines) < 2 or lines[0] != selector or not lines[1].startswith("    # "):
        raise ValueError("systemd-analyze selector output has an unsupported representation")
    values: list[str] = []
    for line in lines[2:]:
        if not re.fullmatch(r"    @[a-z0-9-]+|    [a-z0-9_]+", line):
            raise ValueError("systemd-analyze selector output contains an unsupported line")
        values.append(line.strip())
    if not values or len(values) != len(set(values)):
        raise ValueError("systemd-analyze selector output is empty or duplicated")
    return tuple(values)


def resolve_syscall_allowlist() -> LinuxSyscallAllowlistAuthorityV1:
    analyze = systemd_analyze_authority()
    manager = systemd_manager_authority()
    if analyze.version_output_sha256 != manager.version_output_sha256:
        raise ValueError("systemd analyzer and manager lineages differ")
    outputs: dict[str, bytes] = {}
    parsed: dict[str, tuple[str, ...]] = {}

    def resolve(selector: str, stack: tuple[str, ...] = ()) -> set[str]:
        if selector in stack:
            raise ValueError("systemd syscall selector expansion is cyclic")
        if selector not in parsed:
            result = subprocess.run(
                [LINUX_SYSTEMD_ANALYZE, "--no-pager", "syscall-filter", selector],
                capture_output=True,
                check=True,
                timeout=10,
                env=_VERSION_ENVIRONMENT,
            )
            outputs[selector] = result.stdout
            parsed[selector] = _parse_selector_output(selector, result.stdout)
        resolved: set[str] = set()
        for value in parsed[selector]:
            if value.startswith("@"):
                resolved.update(resolve(value, stack + (selector,)))
            else:
                resolved.add(value)
        return resolved

    names: set[str] = set()
    for selector in _SYSCALL_SELECTORS:
        names.update(resolve(selector))
    if "personality" not in names:
        raise ValueError("Reviewed personality exclusion is absent from the selector expansion")
    names.remove("personality")
    configured = tuple(sorted(names))
    configured_sha = hashlib.sha256(canonical(list(configured))).hexdigest()
    output_projection = {
        selector: hashlib.sha256(outputs[selector]).hexdigest() for selector in sorted(outputs)
    }
    if (
        len(configured) != LINUX_SYSCALL_ALLOWLIST_COUNT
        or configured_sha != LINUX_SYSCALL_ALLOWLIST_SHA256
        or analyze.version_output_sha256 != LINUX_REVIEWED_SYSTEMD_VERSION_SHA256
    ):
        raise ValueError("Resolved syscall selector expansion is not the pre-authorized V19 set")
    return LinuxSyscallAllowlistAuthorityV1(
        configured_explicit_allowlist=configured,
        configured_allowlist_sha256=configured_sha,
        selector_outputs_sha256=hashlib.sha256(canonical(output_projection)).hexdigest(),
        systemd_analyze=analyze,
        systemd_manager=manager,
    )


def setup_state(
    implementation_commit: str,
    environment_instance_id: str,
    service_uid: int,
    service_gid: int,
) -> LinuxCgroupSetupStateV1:
    if not _COMMIT.fullmatch(implementation_commit) or not _ENVIRONMENT.fullmatch(
        environment_instance_id
    ):
        raise ValueError("Cgroup setup identity is invalid")
    if service_uid <= 0 or service_gid <= 0:
        raise ValueError("Cgroup service identity must be unprivileged")
    unit = f"devfabric-linux-isolation-{environment_instance_id}.service"
    control_group = f"/system.slice/{unit}"
    cgroup = Path(LINUX_CGROUP_ROOT + control_group)
    load_state = systemctl_property(unit, "LoadState", check=False)
    if load_state != "not-found" or cgroup.exists():
        raise ValueError("Cgroup unit or path already exists")
    return LinuxCgroupSetupStateV1.create(
        LinuxCgroupSetupStatePayloadV1(
            implementation_commit=implementation_commit,
            environment_instance_id=environment_instance_id,
            boundary=LinuxCgroupBoundaryAuthorityV1(
                unit_name=unit,
                control_group=control_group,
                service_uid=service_uid,
                service_gid=service_gid,
                systemd_run=tool_authority(Path(LINUX_SYSTEMD_RUN), "systemd-run"),
                systemctl=tool_authority(Path(LINUX_SYSTEMCTL), "systemctl"),
                version_environment=LinuxToolVersionEnvironmentV1(),
            ),
        )
    )


def setup_state_v2(
    implementation_commit: str,
    environment_instance_id: str,
    service_uid: int,
    service_gid: int,
) -> LinuxCgroupSetupStateV2:
    baseline = setup_state(
        implementation_commit,
        environment_instance_id,
        service_uid,
        service_gid,
    )
    control_unit = f"devfabric-linux-isolation-control-{environment_instance_id}.service"
    control_group = f"/system.slice/{control_unit}"
    if (
        systemctl_property(control_unit, "LoadState", check=False) != "not-found"
        or Path(LINUX_CGROUP_ROOT + control_group).exists()
    ):
        raise ValueError("Matched control unit or path already exists")
    return LinuxCgroupSetupStateV2.create(
        LinuxCgroupSetupStatePayloadV2(
            implementation_commit=implementation_commit,
            environment_instance_id=environment_instance_id,
            boundary=baseline.payload.boundary,
            syscall_filter=LinuxSyscallFilterBoundaryAuthorityV1(
                policy=resolve_syscall_allowlist(),
                matched_control=LinuxMatchedControlAuthorityV1(
                    unit_name=control_unit,
                    control_group=control_group,
                    service_uid=service_uid,
                    service_gid=service_gid,
                ),
            ),
        )
    )


def systemctl_property(unit: str, name: str, *, check: bool = True) -> str:
    result = subprocess.run(
        [LINUX_SYSTEMCTL, "show", unit, f"--property={name}", "--value"],
        capture_output=True,
        check=False,
        timeout=10,
        env=_VERSION_ENVIRONMENT,
        text=True,
    )
    value = result.stdout.strip()
    if check and result.returncode != 0:
        raise ValueError("systemctl property query failed")
    return value


def revalidate_state(state: LinuxCgroupSetupStateV1) -> None:
    boundary = state.payload.boundary
    if tool_authority(Path(LINUX_SYSTEMD_RUN), "systemd-run") != boundary.systemd_run:
        raise ValueError("systemd-run authority changed")
    if tool_authority(Path(LINUX_SYSTEMCTL), "systemctl") != boundary.systemctl:
        raise ValueError("systemctl authority changed")


def revalidate_state_v2(state: LinuxCgroupSetupStateV2) -> None:
    boundary = state.payload.boundary
    if tool_authority(Path(LINUX_SYSTEMD_RUN), "systemd-run") != boundary.systemd_run:
        raise ValueError("systemd-run authority changed")
    if tool_authority(Path(LINUX_SYSTEMCTL), "systemctl") != boundary.systemctl:
        raise ValueError("systemctl authority changed")
    if resolve_syscall_allowlist() != state.payload.syscall_filter.policy:
        raise ValueError("systemd syscall-filter authority changed")


def raw_personality() -> LinuxRawPersonalityObservationV1:
    if platform.machine() != "x86_64":
        raise ValueError("Reviewed raw personality syscall is x86_64-only")
    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    result = int(libc.syscall(_SYS_PERSONALITY_X86_64, _PERSONALITY_QUERY))
    observed_errno = ctypes.get_errno()
    return LinuxRawPersonalityObservationV1(
        result=result,
        observed_errno=observed_errno,
    )


def process_security_status(pid: int) -> tuple[int, int, int]:
    values: dict[str, int] = {}
    for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
        if ":" not in line:
            continue
        key, raw = line.split(":", 1)
        if key in {"NoNewPrivs", "Seccomp", "Seccomp_filters"}:
            values[key] = int(raw.strip())
    if set(values) != {"NoNewPrivs", "Seccomp", "Seccomp_filters"}:
        raise ValueError("Process security status is incomplete")
    return values["NoNewPrivs"], values["Seccomp"], values["Seccomp_filters"]


def _parse_filter_property(raw: str) -> tuple[bool, tuple[str, ...]]:
    if not raw:
        return False, ()
    tokens = raw.split()
    if tokens[0] in {"yes", "true", "allow"}:
        tokens = tokens[1:]
    elif tokens[0] in {"no", "false", "deny"}:
        raise ValueError("systemd reported a syscall denylist instead of the required allowlist")
    if (
        not tokens
        or len(tokens) != len(set(tokens))
        or any(not re.fullmatch(r"[a-z0-9_]+", token) for token in tokens)
    ):
        raise ValueError("systemd reported an unsupported syscall-filter representation")
    return True, tuple(sorted(set(tokens)))


def _parse_systemd_usec(raw: str) -> int:
    match = re.fullmatch(r"([0-9]+)(us|ms|s)", raw)
    if match is None:
        raise ValueError("systemd resource duration has an unsupported representation")
    factors = {"us": 1, "ms": 1_000, "s": 1_000_000}
    return int(match.group(1)) * factors[match.group(2)]


def _resource_policy(unit: str) -> tuple[LinuxSystemdResourcePolicyObservationV1, dict[str, str]]:
    raw = {
        name: systemctl_property(unit, name)
        for name in (
            "User",
            "Group",
            "MemoryMax",
            "TasksMax",
            "CPUQuotaPerSecUSec",
            "CPUQuotaPeriodUSec",
        )
    }
    return (
        LinuxSystemdResourcePolicyObservationV1(
            service_uid=int(raw["User"]),
            service_gid=int(raw["Group"]),
            memory_max=raw["MemoryMax"],
            tasks_max=raw["TasksMax"],
            cpu_quota_per_sec_usec=_parse_systemd_usec(raw["CPUQuotaPerSecUSec"]),
            cpu_quota_period_usec=_parse_systemd_usec(raw["CPUQuotaPeriodUSec"]),
        ),
        raw,
    )


def observe_unit_policy(
    unit: str, *, expected_filter: tuple[str, ...] | None
) -> LinuxSystemdUnitPolicyObservationV1 | LinuxSystemdControlPolicyObservationV1:
    raw_values = {
        name: systemctl_property(unit, name)
        for name in (
            "NoNewPrivileges",
            "SystemCallArchitectures",
            "SystemCallErrorNumber",
            "SystemCallFilter",
        )
    }
    resources, resource_raw = _resource_policy(unit)
    raw_values.update(resource_raw)
    architectures = tuple(sorted(raw_values["SystemCallArchitectures"].split()))
    allowlist, reported = _parse_filter_property(raw_values["SystemCallFilter"])
    raw_hash = hashlib.sha256(canonical(raw_values)).hexdigest()
    if raw_values["NoNewPrivileges"] != "yes" or architectures != ("native",):
        raise ValueError("systemd unit NNP or architecture policy differs")
    if expected_filter is None:
        if allowlist or reported:
            raise ValueError("Matched control unexpectedly has a syscall filter")
        return LinuxSystemdControlPolicyObservationV1(
            unit_name=unit,
            system_call_error_number=raw_values["SystemCallErrorNumber"],
            raw_properties_sha256=raw_hash,
            resources=resources,
        )
    if not allowlist or reported != expected_filter:
        raise ValueError("systemd reported syscall allowlist differs from configured authority")
    if int(raw_values["SystemCallErrorNumber"]) != errno.EPERM:
        raise ValueError("systemd syscall error action differs from EPERM")
    return LinuxSystemdUnitPolicyObservationV1(
        unit_name=unit,
        systemd_reported_filter=reported,
        systemd_reported_filter_sha256=hashlib.sha256(canonical(list(reported))).hexdigest(),
        raw_properties_sha256=raw_hash,
        resources=resources,
    )


def launch(state: LinuxCgroupSetupStateV1, repo: Path, command: list[str]) -> None:
    revalidate_state(state)
    boundary = state.payload.boundary
    if not command or not Path(command[0]).is_absolute():
        raise ValueError("Cgroup service command must use an absolute executable")
    if systemctl_property(boundary.unit_name, "LoadState", check=False) != "not-found":
        raise ValueError("Cgroup service unit is already loaded")
    result = subprocess.run(
        [
            LINUX_SYSTEMD_RUN,
            "--quiet",
            "--no-block",
            f"--unit={boundary.unit_name}",
            "--service-type=exec",
            f"--uid={boundary.service_uid}",
            f"--gid={boundary.service_gid}",
            f"--working-directory={repo.resolve(strict=True)}",
            "--property=MemoryMax=2147483648",
            "--property=TasksMax=128",
            "--property=CPUQuota=200%",
            "--property=CPUQuotaPeriodSec=100ms",
            "--property=KillMode=control-group",
            "--property=Delegate=no",
            "--property=RemainAfterExit=yes",
            "--property=TimeoutStopSec=30s",
            "--",
            *command,
        ],
        capture_output=True,
        check=False,
        timeout=20,
        env=_VERSION_ENVIRONMENT,
    )
    if result.returncode != 0:
        raise ValueError("Transient cgroup service creation failed")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        load = systemctl_property(boundary.unit_name, "LoadState", check=False)
        group = systemctl_property(boundary.unit_name, "ControlGroup", check=False)
        if load == "loaded" and group == boundary.control_group:
            if (
                systemctl_property(boundary.unit_name, "Transient") != "yes"
                or systemctl_property(boundary.unit_name, "RemainAfterExit") != "yes"
            ):
                raise ValueError("Transient cgroup service retention authority differs")
            break
        time.sleep(0.05)
    else:
        raise ValueError("Transient cgroup service authority was not observed")
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        active = systemctl_property(boundary.unit_name, "ActiveState", check=False)
        substate = systemctl_property(boundary.unit_name, "SubState", check=False)
        if active == "active" and substate == "exited":
            status = systemctl_property(boundary.unit_name, "ExecMainStatus", check=False)
            result_name = systemctl_property(boundary.unit_name, "Result", check=False)
            if status != "0" or result_name != "success":
                raise ValueError("Transient cgroup service execution failed")
            return
        if active in {"inactive", "failed", "not-found"}:
            raise ValueError("Transient cgroup service unloaded or failed before verification")
        time.sleep(0.1)
    raise ValueError("Transient cgroup service execution timed out")


def _run_transient_service(
    *,
    unit: str,
    uid: int,
    gid: int,
    repo: Path,
    command: list[str],
    explicit_allowlist: tuple[str, ...] | None,
) -> None:
    if not command or not Path(command[0]).is_absolute():
        raise ValueError("Transient service command must use an absolute executable")
    if systemctl_property(unit, "LoadState", check=False) != "not-found":
        raise ValueError("Transient service unit is already loaded")
    arguments = [
        LINUX_SYSTEMD_RUN,
        "--quiet",
        "--no-block",
        f"--unit={unit}",
        "--service-type=exec",
        f"--uid={uid}",
        f"--gid={gid}",
        f"--working-directory={repo.resolve(strict=True)}",
        "--property=MemoryMax=2147483648",
        "--property=TasksMax=128",
        "--property=CPUQuota=200%",
        "--property=CPUQuotaPeriodSec=100ms",
        "--property=KillMode=control-group",
        "--property=Delegate=no",
        "--property=RemainAfterExit=yes",
        "--property=TimeoutStopSec=30s",
        "--property=NoNewPrivileges=yes",
        "--property=SystemCallArchitectures=native",
    ]
    if explicit_allowlist is not None:
        arguments.extend(
            (
                f"--property=SystemCallFilter={' '.join(explicit_allowlist)}",
                "--property=SystemCallErrorNumber=EPERM",
            )
        )
    result = subprocess.run(
        [*arguments, "--", *command],
        capture_output=True,
        check=False,
        timeout=20,
        env=_VERSION_ENVIRONMENT,
    )
    if result.returncode != 0:
        raise ValueError("Transient service creation failed")
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        load = systemctl_property(unit, "LoadState", check=False)
        if load == "loaded":
            if (
                systemctl_property(unit, "Transient") != "yes"
                or systemctl_property(unit, "RemainAfterExit") != "yes"
            ):
                raise ValueError("Transient service retention authority differs")
            observed_policy = observe_unit_policy(unit, expected_filter=explicit_allowlist)
            if (
                observed_policy.resources.service_uid != uid
                or observed_policy.resources.service_gid != gid
            ):
                raise ValueError("Transient service resource identity differs")
            break
        time.sleep(0.05)
    else:
        raise ValueError("Transient service authority was not observed")
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        active = systemctl_property(unit, "ActiveState", check=False)
        substate = systemctl_property(unit, "SubState", check=False)
        if active == "active" and substate == "exited":
            if (
                systemctl_property(unit, "ExecMainStatus", check=False) != "0"
                or systemctl_property(unit, "Result", check=False) != "success"
            ):
                raise ValueError("Transient service execution failed")
            return
        if active in {"inactive", "failed", "not-found"}:
            raise ValueError("Transient service unloaded or failed before verification")
        time.sleep(0.1)
    raise ValueError("Transient service execution timed out")


def _stop_exact_unit(
    unit: str,
    control_group: str,
    *,
    uid: int,
    gid: int,
    expected_filter: tuple[str, ...] | None,
) -> None:
    cgroup = Path(LINUX_CGROUP_ROOT + control_group)
    if systemctl_property(unit, "LoadState", check=False) == "not-found":
        if not _path_is_absent(cgroup):
            raise ValueError("Transient cgroup path remains without its unit")
        return
    if systemctl_property(unit, "LoadState", check=False) != "loaded":
        raise ValueError("Transient unit load state differs before exact cleanup")
    observed_group = systemctl_property(unit, "ControlGroup", check=False)
    if observed_group != control_group and not (observed_group == "" and _path_is_absent(cgroup)):
        raise ValueError("Transient unit control group differs before exact cleanup")
    if (
        systemctl_property(unit, "Transient") != "yes"
        or systemctl_property(unit, "RemainAfterExit") != "yes"
    ):
        raise ValueError("Transient unit lifecycle policy differs before exact cleanup")
    policy = observe_unit_policy(unit, expected_filter=expected_filter)
    if policy.resources.service_uid != uid or policy.resources.service_gid != gid:
        raise ValueError("Transient unit service identity differs before exact cleanup")
    subprocess.run(
        [LINUX_SYSTEMCTL, "stop", unit],
        check=True,
        timeout=30,
        env=_VERSION_ENVIRONMENT,
    )
    subprocess.run(
        [LINUX_SYSTEMCTL, "reset-failed", unit],
        check=False,
        timeout=10,
        env=_VERSION_ENVIRONMENT,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if systemctl_property(unit, "LoadState", check=False) == "not-found" and _path_is_absent(
            cgroup
        ):
            return
        time.sleep(0.05)
    raise ValueError("Transient unit or cgroup remained after exact cleanup")


def read_control_execution(path: Path) -> LinuxMatchedControlExecutionV1:
    if path.is_symlink():
        raise ValueError("Matched control execution authority cannot be a symlink")
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_gid != 0
        or stat.S_IMODE(before.st_mode) != 0o444
    ):
        raise ValueError("Matched control execution authority permissions differ")
    raw = path.read_bytes()
    after = os.lstat(path)
    if (
        after.st_dev != before.st_dev
        or after.st_ino != before.st_ino
        or after.st_size != before.st_size
        or stat.S_IMODE(after.st_mode) != stat.S_IMODE(before.st_mode)
        or after.st_uid != before.st_uid
        or after.st_gid != before.st_gid
    ):
        raise ValueError("Matched control execution authority changed during read")
    return LinuxMatchedControlExecutionV1.model_validate_json(raw)


def revalidate_control_execution(
    execution: LinuxMatchedControlExecutionV1,
    state: LinuxCgroupSetupStateV2,
    state_path: Path,
) -> None:
    payload = execution.payload
    if (
        payload.implementation_commit != state.payload.implementation_commit
        or payload.environment_instance_id != state.payload.environment_instance_id
        or payload.linux_cgroup_setup_state_id != state.linux_cgroup_setup_state_id
        or payload.state_locator != str(state_path.resolve(strict=True))
        or payload.state_sha256 != file_sha256(state_path)
        or file_authority(Path(payload.python.locator)) != payload.python
        or file_authority(Path(payload.manager_script.locator)) != payload.manager_script
        or payload.manager_script.sha256 != payload.manager_script_git_blob_sha256
    ):
        raise ValueError("Matched control execution authority differs")


def control_probe(
    state: LinuxCgroupSetupStateV2,
    state_path: Path,
    execution_path: Path,
    output: Path,
) -> None:
    execution = read_control_execution(execution_path)
    revalidate_control_execution(execution, state, state_path)
    if (
        execution.payload.execution_authority_locator != str(execution_path.resolve(strict=True))
        or execution.payload.observation_locator != str(output.resolve(strict=False))
        or tuple((sys.executable, *sys.argv)) != execution.payload.argv
    ):
        raise ValueError("Matched control process command differs")
    control = state.payload.syscall_filter.matched_control
    cgroup_path = Path(LINUX_CGROUP_ROOT + control.control_group)
    if (
        os.getuid() != control.service_uid
        or os.getgid() != control.service_gid
        or process_cgroup_for_manager(os.getpid()) != control.control_group
        or cgroup_path.is_symlink()
    ):
        raise ValueError("Matched control process identity differs")
    cgroup_info = os.lstat(cgroup_path)
    if not stat.S_ISDIR(cgroup_info.st_mode):
        raise ValueError("Matched control cgroup is not a directory")
    memory_max = (cgroup_path / "memory.max").read_text(encoding="ascii").strip()
    pids_max = (cgroup_path / "pids.max").read_text(encoding="ascii").strip()
    cpu_max = (cgroup_path / "cpu.max").read_text(encoding="ascii").strip()
    members = {
        int(value)
        for value in (cgroup_path / "cgroup.procs").read_text(encoding="ascii").splitlines()
    }
    if (
        memory_max != control.limits.memory_max
        or pids_max != control.limits.pids_max
        or cpu_max != control.limits.cpu_max
        or members != {os.getpid()}
    ):
        raise ValueError("Matched control cgroup limits or membership differ")
    no_new_privs, seccomp_mode, seccomp_filters = process_security_status(os.getpid())
    observation = LinuxMatchedControlObservationV1(
        implementation_commit=state.payload.implementation_commit,
        environment_instance_id=state.payload.environment_instance_id,
        linux_cgroup_setup_state_id=state.linux_cgroup_setup_state_id,
        unit_name=control.unit_name,
        control_group=control.control_group,
        cgroup_native_identity=LinuxNativePathIdentityV1(
            device=cgroup_info.st_dev, inode=cgroup_info.st_ino
        ),
        memory_max=memory_max,
        pids_max=pids_max,
        cpu_max=cpu_max,
        sole_cgroup_member=True,
        personality=raw_personality(),
        no_new_privs=no_new_privs,
        seccomp_mode=seccomp_mode,
        seccomp_filters=seccomp_filters,
    )
    revalidate_control_execution(execution, state, state_path)
    write_new(output, canonical(observation.model_dump(mode="json")), mode=0o600)


def process_cgroup_for_manager(pid: int) -> str:
    values = [
        line[3:]
        for line in Path(f"/proc/{pid}/cgroup").read_text(encoding="ascii").splitlines()
        if line.startswith("0::")
    ]
    if len(values) != 1:
        raise ValueError("Process cgroup identity is invalid")
    return values[0]


def launch_control_v2(
    state: LinuxCgroupSetupStateV2,
    state_path: Path,
    repo: Path,
    python: Path,
    script: Path,
    execution_authority_path: Path,
    observation_path: Path,
) -> LinuxMatchedControlReceiptV1:
    revalidate_state_v2(state)
    control = state.payload.syscall_filter.matched_control
    python_authority = file_authority(python.resolve(strict=True))
    script_authority = file_authority(script.resolve(strict=True))
    relative_script = script.resolve(strict=True).relative_to(repo.resolve(strict=True)).as_posix()
    script_blob = git_blob_sha256(repo, state.payload.implementation_commit, relative_script)
    if script_authority.sha256 != script_blob:
        raise ValueError("Matched control manager differs from reviewed Git blob")
    resolved_state = state_path.resolve(strict=True)
    resolved_execution = execution_authority_path.resolve(strict=False)
    resolved_observation = observation_path.resolve(strict=False)
    command = [
        python_authority.locator,
        script_authority.locator,
        "control-probe-v19",
        "--state",
        str(resolved_state),
        "--execution-authority",
        str(resolved_execution),
        "--output",
        str(resolved_observation),
    ]
    execution = LinuxMatchedControlExecutionV1.create(
        LinuxMatchedControlExecutionPayloadV1(
            implementation_commit=state.payload.implementation_commit,
            environment_instance_id=state.payload.environment_instance_id,
            linux_cgroup_setup_state_id=state.linux_cgroup_setup_state_id,
            python=python_authority,
            manager_script=script_authority,
            manager_script_git_blob_sha256=script_blob,
            state_locator=str(resolved_state),
            state_sha256=file_sha256(resolved_state),
            execution_authority_locator=str(resolved_execution),
            observation_locator=str(resolved_observation),
            argv=tuple(command),
        )
    )
    write_new(resolved_execution, canonical(execution.model_dump(mode="json")), mode=0o444)
    try:
        _run_transient_service(
            unit=control.unit_name,
            uid=control.service_uid,
            gid=control.service_gid,
            repo=repo,
            command=command,
            explicit_allowlist=None,
        )
        policy = observe_unit_policy(control.unit_name, expected_filter=None)
        if not isinstance(policy, LinuxSystemdControlPolicyObservationV1):
            raise ValueError("Matched control policy observation type differs")
        if observation_path.is_symlink():
            raise ValueError("Matched control observation cannot be a symlink")
        observation = LinuxMatchedControlObservationV1.model_validate_json(
            observation_path.read_bytes()
        )
        revalidate_control_execution(execution, state, state_path)
        if (
            git_blob_sha256(repo, state.payload.implementation_commit, relative_script)
            != script_blob
        ):
            raise ValueError("Matched control Git authority changed")
    finally:
        _stop_exact_unit(
            control.unit_name,
            control.control_group,
            uid=control.service_uid,
            gid=control.service_gid,
            expected_filter=None,
        )
    return LinuxMatchedControlReceiptV1.create(
        LinuxMatchedControlReceiptPayloadV1(
            implementation_commit=state.payload.implementation_commit,
            environment_instance_id=state.payload.environment_instance_id,
            linux_cgroup_setup_state_id=state.linux_cgroup_setup_state_id,
            authority=control,
            execution=execution,
            observation=observation,
            unit_policy=policy,
        )
    )


def launch_v2(
    state: LinuxCgroupSetupStateV2,
    repo: Path,
    command: list[str],
) -> LinuxSystemdUnitPolicyObservationV1:
    revalidate_state_v2(state)
    boundary = state.payload.boundary
    allowlist = state.payload.syscall_filter.policy.configured_explicit_allowlist
    _run_transient_service(
        unit=boundary.unit_name,
        uid=boundary.service_uid,
        gid=boundary.service_gid,
        repo=repo,
        command=command,
        explicit_allowlist=allowlist,
    )
    observed = observe_unit_policy(boundary.unit_name, expected_filter=allowlist)
    if not isinstance(observed, LinuxSystemdUnitPolicyObservationV1):
        raise ValueError("Target unit policy observation type differs")
    return observed


def _verify_mechanics_join(
    state: LinuxCgroupSetupStateV1,
    mechanics: LinuxIsolationEvidenceV17,
) -> None:
    boundary = state.payload.boundary
    observed = mechanics.payload.receipt.payload.observation.cgroup
    if (
        mechanics.payload.profile.payload.cgroup_setup_state_id != state.linux_cgroup_setup_state_id
        or mechanics.payload.profile.payload.cgroup != boundary
        or observed.setup_state_id != state.linux_cgroup_setup_state_id
        or observed.control_group != boundary.control_group
    ):
        raise ValueError("Cgroup mechanics and setup state differ")
    if (
        observed.memory_max != boundary.limits.memory_max
        or observed.pids_max != boundary.limits.pids_max
        or observed.cpu_max != boundary.limits.cpu_max
        or observed.cgroup_type != "domain"
        or not observed.initial_members_only_probe
        or not observed.terminal_members_only_probe
        or not observed.process_tree_inheritance_verified
        or not observed.active_members_all_descendants
        or not observed.cgroup_controls_not_writable
        or not observed.ancestor_controls_not_writable
    ):
        raise ValueError("Qualified cgroup mechanics are incomplete or differ")


def _verify_loaded_unit(state: LinuxCgroupSetupStateV1) -> None:
    boundary = state.payload.boundary
    if systemctl_property(boundary.unit_name, "LoadState", check=False) != "loaded":
        raise ValueError("Cgroup unit is not loaded")
    if systemctl_property(boundary.unit_name, "ControlGroup") != boundary.control_group:
        raise ValueError("Cgroup unit path differs before cleanup")
    if systemctl_property(boundary.unit_name, "Transient") != "yes":
        raise ValueError("Cgroup unit is not transient")
    if systemctl_property(boundary.unit_name, "RemainAfterExit") != "yes":
        raise ValueError("Cgroup unit is not retained for exact cleanup")


def _verify_removed_empty_cgroup_state(state: LinuxCgroupSetupStateV1) -> None:
    """Accept only systemd's exact loaded/exited unit with its empty cgroup removed."""

    boundary = state.payload.boundary
    if systemctl_property(boundary.unit_name, "LoadState", check=False) != "loaded":
        raise ValueError("Cgroup unit is not loaded")
    if systemctl_property(boundary.unit_name, "Transient") != "yes":
        raise ValueError("Cgroup unit is not transient")
    if systemctl_property(boundary.unit_name, "RemainAfterExit") != "yes":
        raise ValueError("Cgroup unit is not retained for exact cleanup")
    if (
        systemctl_property(boundary.unit_name, "ActiveState") != "active"
        or systemctl_property(boundary.unit_name, "SubState") != "exited"
        or systemctl_property(boundary.unit_name, "ExecMainStatus") != "0"
        or systemctl_property(boundary.unit_name, "Result") != "success"
    ):
        raise ValueError("Cgroup unit completion state differs before cleanup")
    if systemctl_property(boundary.unit_name, "ControlGroup") != "":
        raise ValueError("Cgroup unit retained or substituted a control group after exit")
    cgroup = Path(boundary.cgroup_root + boundary.control_group)
    if not _path_is_absent(cgroup):
        raise ValueError("Expected post-exit cgroup path is present or substituted")


def _path_is_absent(path: Path) -> bool:
    """Prove lexical absence without accepting a dangling symlink."""

    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def _stop_and_verify_absent(state: LinuxCgroupSetupStateV1) -> None:
    boundary = state.payload.boundary
    subprocess.run(
        [LINUX_SYSTEMCTL, "stop", boundary.unit_name],
        check=True,
        timeout=30,
        env=_VERSION_ENVIRONMENT,
    )
    subprocess.run(
        [LINUX_SYSTEMCTL, "reset-failed", boundary.unit_name],
        check=False,
        timeout=10,
        env=_VERSION_ENVIRONMENT,
    )
    cgroup = Path(boundary.cgroup_root + boundary.control_group)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if systemctl_property(
            boundary.unit_name, "LoadState", check=False
        ) == "not-found" and _path_is_absent(cgroup):
            break
        time.sleep(0.05)
    else:
        raise ValueError("Cgroup unit or path remained after cleanup")


def remove_unit(state: LinuxCgroupSetupStateV1) -> None:
    """Best-effort rollback for a run that produced no qualified mechanics."""

    revalidate_state(state)
    boundary = state.payload.boundary
    load = systemctl_property(boundary.unit_name, "LoadState", check=False)
    if load == "not-found":
        if not _path_is_absent(Path(boundary.cgroup_root + boundary.control_group)):
            raise ValueError("Cgroup path remains without its exact unit authority")
        return
    _verify_loaded_unit(state)
    _stop_and_verify_absent(state)


def _cleanup_state(
    state: LinuxCgroupSetupStateV1,
    mechanics: LinuxIsolationEvidenceV17,
) -> LinuxCgroupCleanupStateV2:
    profile = mechanics.payload.profile
    observed = mechanics.payload.receipt.payload.observation.cgroup
    boundary = state.payload.boundary
    return LinuxCgroupCleanupStateV2.create(
        LinuxCgroupCleanupStatePayloadV2(
            implementation_commit=state.payload.implementation_commit,
            environment_instance_id=state.payload.environment_instance_id,
            linux_cgroup_setup_state_id=state.linux_cgroup_setup_state_id,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=mechanics.linux_isolation_evidence_id,
            unit_name=boundary.unit_name,
            control_group=boundary.control_group,
            cgroup_native_identity=observed.cgroup_native_identity,
            post_exit_state="systemd_removed_empty_cgroup",
        )
    )


def cleanup(
    state: LinuxCgroupSetupStateV1,
    mechanics: LinuxIsolationEvidenceV17,
    cleanup_state_path: Path,
) -> LinuxCgroupCleanupReceiptV2:
    boundary = state.payload.boundary
    revalidate_state(state)
    _verify_mechanics_join(state, mechanics)
    _verify_removed_empty_cgroup_state(state)
    write_new(
        cleanup_state_path,
        canonical(_cleanup_state(state, mechanics).model_dump(mode="json")),
    )
    _stop_and_verify_absent(state)
    profile = mechanics.payload.profile
    return LinuxCgroupCleanupReceiptV2.create(
        LinuxCgroupCleanupPayloadV2(
            implementation_commit=state.payload.implementation_commit,
            environment_instance_id=state.payload.environment_instance_id,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=mechanics.linux_isolation_evidence_id,
            linux_cgroup_setup_state_id=state.linux_cgroup_setup_state_id,
            unit_name=boundary.unit_name,
            control_group=boundary.control_group,
            post_exit_state="systemd_removed_empty_cgroup",
        )
    )


def _verify_mechanics_join_v19(
    state: LinuxCgroupSetupStateV2,
    mechanics: LinuxIsolationEvidenceV18,
    unit_policy: LinuxSystemdUnitPolicyObservationV1,
) -> None:
    profile = mechanics.payload.profile.payload
    observed = mechanics.payload.receipt.payload.observation
    policy = state.payload.syscall_filter.policy
    if (
        profile.cgroup_setup_state_id != state.linux_cgroup_setup_state_id
        or profile.cgroup != state.payload.boundary
        or profile.syscall_filter != state.payload.syscall_filter
        or observed.cgroup.setup_state_id != state.linux_cgroup_setup_state_id
        or observed.cgroup.control_group != state.payload.boundary.control_group
        or observed.syscall_filter.configured_allowlist_sha256 != policy.configured_allowlist_sha256
        or unit_policy.unit_name != state.payload.boundary.unit_name
        or unit_policy.systemd_reported_filter != policy.configured_explicit_allowlist
    ):
        raise ValueError("V19 mechanics, setup and systemd policy authority differ")


def cleanup_v19(
    state: LinuxCgroupSetupStateV2,
    mechanics: LinuxIsolationEvidenceV18,
    unit_policy: LinuxSystemdUnitPolicyObservationV1,
    cleanup_state_path: Path,
) -> LinuxCgroupCleanupReceiptV3:
    revalidate_state_v2(state)
    _verify_mechanics_join_v19(state, mechanics, unit_policy)
    _verify_removed_empty_cgroup_state(state)  # type: ignore[arg-type]
    profile = mechanics.payload.profile
    observed = mechanics.payload.receipt.payload.observation.cgroup
    cleanup_state = LinuxCgroupCleanupStateV2.create(
        LinuxCgroupCleanupStatePayloadV2(
            implementation_commit=state.payload.implementation_commit,
            environment_instance_id=state.payload.environment_instance_id,
            linux_cgroup_setup_state_id=state.linux_cgroup_setup_state_id,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=mechanics.linux_isolation_evidence_id,
            unit_name=state.payload.boundary.unit_name,
            control_group=state.payload.boundary.control_group,
            cgroup_native_identity=observed.cgroup_native_identity,
            post_exit_state="systemd_removed_empty_cgroup",
        )
    )
    write_new(cleanup_state_path, canonical(cleanup_state.model_dump(mode="json")))
    boundary = state.payload.boundary
    _stop_exact_unit(
        boundary.unit_name,
        boundary.control_group,
        uid=boundary.service_uid,
        gid=boundary.service_gid,
        expected_filter=state.payload.syscall_filter.policy.configured_explicit_allowlist,
    )
    control = state.payload.syscall_filter.matched_control
    if systemctl_property(
        control.unit_name, "LoadState", check=False
    ) != "not-found" or not _path_is_absent(Path(LINUX_CGROUP_ROOT + control.control_group)):
        raise ValueError("Matched control authority remained during target cleanup")
    return LinuxCgroupCleanupReceiptV3.create(
        LinuxCgroupCleanupPayloadV3(
            implementation_commit=state.payload.implementation_commit,
            environment_instance_id=state.payload.environment_instance_id,
            linux_isolation_profile_id=profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=mechanics.linux_isolation_evidence_id,
            linux_cgroup_setup_state_id=state.linux_cgroup_setup_state_id,
            unit_name=state.payload.boundary.unit_name,
            control_group=state.payload.boundary.control_group,
            post_exit_state="systemd_removed_empty_cgroup",
            unit_policy=unit_policy,
            target_unit_absent=True,
            target_cgroup_absent=True,
            control_unit_name=control.unit_name,
            control_control_group=control.control_group,
            control_unit_absent=True,
            control_cgroup_absent=True,
        )
    )


def resume_cleanup_v19(
    state: LinuxCgroupSetupStateV2,
    mechanics: LinuxIsolationEvidenceV18,
    unit_policy: LinuxSystemdUnitPolicyObservationV1,
    cleanup_state: LinuxCgroupCleanupStateV2,
) -> LinuxCgroupRollbackReceiptV2:
    profile = mechanics.payload.profile
    observed = mechanics.payload.receipt.payload.observation.cgroup
    journal = cleanup_state.payload
    boundary = state.payload.boundary
    if (
        journal.implementation_commit != state.payload.implementation_commit
        or journal.environment_instance_id != state.payload.environment_instance_id
        or journal.linux_cgroup_setup_state_id != state.linux_cgroup_setup_state_id
        or journal.linux_isolation_profile_id != profile.linux_isolation_profile_id
        or journal.linux_isolation_evidence_id != mechanics.linux_isolation_evidence_id
        or journal.unit_name != boundary.unit_name
        or journal.control_group != boundary.control_group
        or journal.cgroup_native_identity != observed.cgroup_native_identity
        or journal.post_exit_state != "systemd_removed_empty_cgroup"
    ):
        raise ValueError("V19 cleanup journal differs from qualified mechanics")
    target_unit_absent = False
    target_cgroup_absent = False
    control_unit_absent = False
    control_cgroup_absent = False
    try:
        revalidate_state_v2(state)
        _verify_mechanics_join_v19(state, mechanics, unit_policy)
        load = systemctl_property(boundary.unit_name, "LoadState", check=False)
        if load == "loaded":
            _verify_removed_empty_cgroup_state(state)  # type: ignore[arg-type]
            _stop_exact_unit(
                boundary.unit_name,
                boundary.control_group,
                uid=boundary.service_uid,
                gid=boundary.service_gid,
                expected_filter=state.payload.syscall_filter.policy.configured_explicit_allowlist,
            )
        elif load != "not-found" or not _path_is_absent(
            Path(boundary.cgroup_root + boundary.control_group)
        ):
            raise ValueError("V19 cleanup resume authority is ambiguous")
        control = state.payload.syscall_filter.matched_control
        _stop_exact_unit(
            control.unit_name,
            control.control_group,
            uid=control.service_uid,
            gid=control.service_gid,
            expected_filter=None,
        )
    except BaseException:
        pass
    target_unit_absent = (
        systemctl_property(boundary.unit_name, "LoadState", check=False) == "not-found"
    )
    target_cgroup_absent = _path_is_absent(Path(LINUX_CGROUP_ROOT + boundary.control_group))
    control = state.payload.syscall_filter.matched_control
    control_unit_absent = (
        systemctl_property(control.unit_name, "LoadState", check=False) == "not-found"
    )
    control_cgroup_absent = _path_is_absent(Path(LINUX_CGROUP_ROOT + control.control_group))
    succeeded = all(
        (target_unit_absent, target_cgroup_absent, control_unit_absent, control_cgroup_absent)
    )
    return LinuxCgroupRollbackReceiptV2.create(
        LinuxCgroupRollbackPayloadV2(
            implementation_commit=state.payload.implementation_commit,
            environment_instance_id=state.payload.environment_instance_id,
            linux_cgroup_setup_state_id=state.linux_cgroup_setup_state_id,
            unit_name=boundary.unit_name,
            control_group=boundary.control_group,
            cleanup_succeeded=succeeded,
            unit_absent=target_unit_absent,
            cgroup_absent=target_cgroup_absent,
            control_unit_name=control.unit_name,
            control_control_group=control.control_group,
            control_unit_absent=control_unit_absent,
            control_cgroup_absent=control_cgroup_absent,
        )
    )


def rollback_v19(state: LinuxCgroupSetupStateV2) -> LinuxCgroupRollbackReceiptV2:
    boundary = state.payload.boundary
    control = state.payload.syscall_filter.matched_control
    try:
        revalidate_state_v2(state)
        _stop_exact_unit(
            boundary.unit_name,
            boundary.control_group,
            uid=boundary.service_uid,
            gid=boundary.service_gid,
            expected_filter=state.payload.syscall_filter.policy.configured_explicit_allowlist,
        )
        _stop_exact_unit(
            control.unit_name,
            control.control_group,
            uid=control.service_uid,
            gid=control.service_gid,
            expected_filter=None,
        )
    except BaseException:
        pass
    target_unit_absent = (
        systemctl_property(boundary.unit_name, "LoadState", check=False) == "not-found"
    )
    target_cgroup_absent = _path_is_absent(Path(LINUX_CGROUP_ROOT + boundary.control_group))
    control_unit_absent = (
        systemctl_property(control.unit_name, "LoadState", check=False) == "not-found"
    )
    control_cgroup_absent = _path_is_absent(Path(LINUX_CGROUP_ROOT + control.control_group))
    succeeded = all(
        (target_unit_absent, target_cgroup_absent, control_unit_absent, control_cgroup_absent)
    )
    return LinuxCgroupRollbackReceiptV2.create(
        LinuxCgroupRollbackPayloadV2(
            implementation_commit=state.payload.implementation_commit,
            environment_instance_id=state.payload.environment_instance_id,
            linux_cgroup_setup_state_id=state.linux_cgroup_setup_state_id,
            unit_name=boundary.unit_name,
            control_group=boundary.control_group,
            cleanup_succeeded=succeeded,
            unit_absent=target_unit_absent,
            cgroup_absent=target_cgroup_absent,
            control_unit_name=control.unit_name,
            control_control_group=control.control_group,
            control_unit_absent=control_unit_absent,
            control_cgroup_absent=control_cgroup_absent,
        )
    )


def read_cleanup_state(path: Path) -> LinuxCgroupCleanupStateV2:
    if path.is_symlink():
        raise ValueError("Cgroup cleanup state cannot be a symlink")
    return LinuxCgroupCleanupStateV2.model_validate_json(path.read_bytes())


def resume_cleanup(
    state: LinuxCgroupSetupStateV1,
    mechanics: LinuxIsolationEvidenceV17,
    cleanup_state: LinuxCgroupCleanupStateV2,
) -> LinuxCgroupRollbackReceiptV1:
    boundary = state.payload.boundary
    profile = mechanics.payload.profile
    observed = mechanics.payload.receipt.payload.observation.cgroup
    journal = cleanup_state.payload
    if (
        journal.implementation_commit != state.payload.implementation_commit
        or journal.environment_instance_id != state.payload.environment_instance_id
        or journal.linux_cgroup_setup_state_id != state.linux_cgroup_setup_state_id
        or journal.linux_isolation_profile_id != profile.linux_isolation_profile_id
        or journal.linux_isolation_evidence_id != mechanics.linux_isolation_evidence_id
        or journal.unit_name != boundary.unit_name
        or journal.control_group != boundary.control_group
        or journal.cgroup_native_identity != observed.cgroup_native_identity
        or journal.post_exit_state != "systemd_removed_empty_cgroup"
    ):
        raise ValueError("Cgroup cleanup journal differs from qualified mechanics")
    succeeded = False
    try:
        revalidate_state(state)
        load = systemctl_property(boundary.unit_name, "LoadState", check=False)
        cgroup = Path(boundary.cgroup_root + boundary.control_group)
        if load == "loaded":
            _verify_mechanics_join(state, mechanics)
            _verify_removed_empty_cgroup_state(state)
            _stop_and_verify_absent(state)
        elif load == "not-found" and _path_is_absent(cgroup):
            pass
        else:
            raise ValueError("Cgroup cleanup resume authority is ambiguous")
        succeeded = True
    except BaseException:
        succeeded = False
    return LinuxCgroupRollbackReceiptV1.create(
        LinuxCgroupRollbackPayloadV1(
            implementation_commit=state.payload.implementation_commit,
            environment_instance_id=state.payload.environment_instance_id,
            linux_cgroup_setup_state_id=state.linux_cgroup_setup_state_id,
            unit_name=boundary.unit_name,
            control_group=boundary.control_group,
            cleanup_succeeded=succeeded,
            unit_absent=succeeded,
            cgroup_absent=succeeded,
        )
    )


def rollback(state: LinuxCgroupSetupStateV1) -> LinuxCgroupRollbackReceiptV1:
    boundary = state.payload.boundary
    succeeded = False
    try:
        remove_unit(state)
        succeeded = True
    except BaseException:
        succeeded = False
    return LinuxCgroupRollbackReceiptV1.create(
        LinuxCgroupRollbackPayloadV1(
            implementation_commit=state.payload.implementation_commit,
            environment_instance_id=state.payload.environment_instance_id,
            linux_cgroup_setup_state_id=state.linux_cgroup_setup_state_id,
            unit_name=boundary.unit_name,
            control_group=boundary.control_group,
            cleanup_succeeded=succeeded,
            unit_absent=succeeded,
            cgroup_absent=succeeded,
        )
    )


def read_state(path: Path) -> LinuxCgroupSetupStateV1:
    if path.is_symlink():
        raise ValueError("Cgroup setup state cannot be a symlink")
    return LinuxCgroupSetupStateV1.model_validate_json(path.read_bytes())


def read_state_v2(path: Path) -> LinuxCgroupSetupStateV2:
    if path.is_symlink():
        raise ValueError("Cgroup setup state cannot be a symlink")
    return LinuxCgroupSetupStateV2.model_validate_json(path.read_bytes())


def write_failure(
    path: Path,
    *,
    phase: Literal["setup", "run", "cleanup"],
    implementation_commit: str,
    environment_instance_id: str,
    state_id: str | None,
) -> None:
    reason = {
        "setup": "authority_invalid",
        "run": "service_execution_failed",
        "cleanup": "cleanup_failed",
    }[phase]
    failure = LinuxCgroupLifecycleFailureV1.create(
        LinuxCgroupLifecycleFailurePayloadV1(
            phase=phase,
            reason_code=reason,
            implementation_commit=implementation_commit,
            environment_instance_id=environment_instance_id,
            linux_cgroup_setup_state_id=state_id,
            cleanup_attempted=phase == "cleanup",
            cleanup_succeeded=False,
        )
    )
    write_new(path, canonical(failure.model_dump(mode="json")))


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    setup_parser = subparsers.add_parser("setup")
    setup_parser.add_argument("--implementation-commit", required=True)
    setup_parser.add_argument("--environment-instance-id", required=True)
    setup_parser.add_argument("--service-uid", type=int, required=True)
    setup_parser.add_argument("--service-gid", type=int, required=True)
    setup_parser.add_argument("--output", type=Path, required=True)
    setup_parser.add_argument("--failure-output", type=Path, required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--state", type=Path, required=True)
    run_parser.add_argument("--repo", type=Path, required=True)
    run_parser.add_argument("--implementation-commit", required=True)
    run_parser.add_argument("--environment-instance-id", required=True)
    run_parser.add_argument("--failure-output", type=Path, required=True)
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    cleanup_parser = subparsers.add_parser("cleanup")
    cleanup_parser.add_argument("--state", type=Path, required=True)
    cleanup_parser.add_argument("--mechanics", type=Path, required=True)
    cleanup_parser.add_argument("--cleanup-state", type=Path, required=True)
    cleanup_parser.add_argument("--output", type=Path, required=True)
    cleanup_parser.add_argument("--implementation-commit", required=True)
    cleanup_parser.add_argument("--environment-instance-id", required=True)
    cleanup_parser.add_argument("--failure-output", type=Path, required=True)
    rollback_parser = subparsers.add_parser("rollback")
    rollback_parser.add_argument("--state", type=Path, required=True)
    rollback_parser.add_argument("--output", type=Path, required=True)
    rollback_parser.add_argument("--implementation-commit", required=True)
    rollback_parser.add_argument("--environment-instance-id", required=True)
    rollback_parser.add_argument("--failure-output", type=Path, required=True)
    resume_parser = subparsers.add_parser("resume")
    resume_parser.add_argument("--state", type=Path, required=True)
    resume_parser.add_argument("--mechanics", type=Path, required=True)
    resume_parser.add_argument("--cleanup-state", type=Path, required=True)
    resume_parser.add_argument("--output", type=Path, required=True)
    resume_parser.add_argument("--implementation-commit", required=True)
    resume_parser.add_argument("--environment-instance-id", required=True)
    resume_parser.add_argument("--failure-output", type=Path, required=True)
    setup_v19 = subparsers.add_parser("setup-v19")
    setup_v19.add_argument("--implementation-commit", required=True)
    setup_v19.add_argument("--environment-instance-id", required=True)
    setup_v19.add_argument("--service-uid", type=int, required=True)
    setup_v19.add_argument("--service-gid", type=int, required=True)
    setup_v19.add_argument("--output", type=Path, required=True)
    setup_v19.add_argument("--failure-output", type=Path, required=True)
    control_probe_v19 = subparsers.add_parser("control-probe-v19")
    control_probe_v19.add_argument("--state", type=Path, required=True)
    control_probe_v19.add_argument("--execution-authority", type=Path, required=True)
    control_probe_v19.add_argument("--output", type=Path, required=True)
    control_v19 = subparsers.add_parser("control-v19")
    control_v19.add_argument("--state", type=Path, required=True)
    control_v19.add_argument("--repo", type=Path, required=True)
    control_v19.add_argument("--observation", type=Path, required=True)
    control_v19.add_argument("--execution-authority", type=Path, required=True)
    control_v19.add_argument("--output", type=Path, required=True)
    control_v19.add_argument("--implementation-commit", required=True)
    control_v19.add_argument("--environment-instance-id", required=True)
    control_v19.add_argument("--failure-output", type=Path, required=True)
    run_v19 = subparsers.add_parser("run-v19")
    run_v19.add_argument("--state", type=Path, required=True)
    run_v19.add_argument("--repo", type=Path, required=True)
    run_v19.add_argument("--policy-output", type=Path, required=True)
    run_v19.add_argument("--implementation-commit", required=True)
    run_v19.add_argument("--environment-instance-id", required=True)
    run_v19.add_argument("--failure-output", type=Path, required=True)
    run_v19.add_argument("command", nargs=argparse.REMAINDER)
    cleanup_v19_parser = subparsers.add_parser("cleanup-v19")
    cleanup_v19_parser.add_argument("--state", type=Path, required=True)
    cleanup_v19_parser.add_argument("--mechanics", type=Path, required=True)
    cleanup_v19_parser.add_argument("--unit-policy", type=Path, required=True)
    cleanup_v19_parser.add_argument("--cleanup-state", type=Path, required=True)
    cleanup_v19_parser.add_argument("--output", type=Path, required=True)
    cleanup_v19_parser.add_argument("--implementation-commit", required=True)
    cleanup_v19_parser.add_argument("--environment-instance-id", required=True)
    cleanup_v19_parser.add_argument("--failure-output", type=Path, required=True)
    rollback_v19_parser = subparsers.add_parser("rollback-v19")
    rollback_v19_parser.add_argument("--state", type=Path, required=True)
    rollback_v19_parser.add_argument("--output", type=Path, required=True)
    rollback_v19_parser.add_argument("--implementation-commit", required=True)
    rollback_v19_parser.add_argument("--environment-instance-id", required=True)
    rollback_v19_parser.add_argument("--failure-output", type=Path, required=True)
    resume_v19_parser = subparsers.add_parser("resume-v19")
    resume_v19_parser.add_argument("--state", type=Path, required=True)
    resume_v19_parser.add_argument("--mechanics", type=Path, required=True)
    resume_v19_parser.add_argument("--unit-policy", type=Path, required=True)
    resume_v19_parser.add_argument("--cleanup-state", type=Path, required=True)
    resume_v19_parser.add_argument("--output", type=Path, required=True)
    resume_v19_parser.add_argument("--implementation-commit", required=True)
    resume_v19_parser.add_argument("--environment-instance-id", required=True)
    resume_v19_parser.add_argument("--failure-output", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "control-probe-v19":
        control_probe(
            read_state_v2(args.state),
            args.state,
            args.execution_authority,
            args.output,
        )
        return
    state: LinuxCgroupSetupStateV1 | LinuxCgroupSetupStateV2 | None = None
    try:
        if args.operation == "setup":
            value = setup_state(
                args.implementation_commit,
                args.environment_instance_id,
                args.service_uid,
                args.service_gid,
            )
            write_new(args.output, canonical(value.model_dump(mode="json")))
        elif args.operation == "run":
            state = read_state(args.state)
            command = list(args.command)
            if command[:1] == ["--"]:
                command = command[1:]
            launch(state, args.repo, command)
        elif args.operation == "cleanup":
            state = read_state(args.state)
            value = cleanup(
                state,
                LinuxIsolationEvidenceV17.model_validate_json(args.mechanics.read_bytes()),
                args.cleanup_state,
            )
            write_new(args.output, canonical(value.model_dump(mode="json")))
        elif args.operation == "rollback":
            state = read_state(args.state)
            value = rollback(state)
            write_new(args.output, canonical(value.model_dump(mode="json")))
            if not value.payload.cleanup_succeeded:
                raise ValueError("Transient cgroup rollback failed")
        elif args.operation == "resume":
            state = read_state(args.state)
            value = resume_cleanup(
                state,
                LinuxIsolationEvidenceV17.model_validate_json(args.mechanics.read_bytes()),
                read_cleanup_state(args.cleanup_state),
            )
            write_new(args.output, canonical(value.model_dump(mode="json")))
            if not value.payload.cleanup_succeeded:
                raise ValueError("Transient cgroup cleanup resume failed")
        elif args.operation == "setup-v19":
            value_v19 = setup_state_v2(
                args.implementation_commit,
                args.environment_instance_id,
                args.service_uid,
                args.service_gid,
            )
            write_new(args.output, canonical(value_v19.model_dump(mode="json")))
        else:
            state_v19 = read_state_v2(args.state)
            state = state_v19
            if (
                state_v19.payload.implementation_commit != args.implementation_commit
                or state_v19.payload.environment_instance_id != args.environment_instance_id
            ):
                raise ValueError("V19 setup state invocation identity differs")
            if args.operation == "control-v19":
                receipt = launch_control_v2(
                    state_v19,
                    args.state,
                    args.repo,
                    Path(sys.executable),
                    Path(__file__),
                    args.execution_authority,
                    args.observation,
                )
                write_new(args.output, canonical(receipt.model_dump(mode="json")))
                args.observation.unlink()
            elif args.operation == "run-v19":
                command = list(args.command)
                if command[:1] == ["--"]:
                    command = command[1:]
                policy = launch_v2(state_v19, args.repo, command)
                write_new(args.policy_output, canonical(policy.model_dump(mode="json")))
            elif args.operation == "cleanup-v19":
                receipt_v19 = cleanup_v19(
                    state_v19,
                    LinuxIsolationEvidenceV18.model_validate_json(args.mechanics.read_bytes()),
                    LinuxSystemdUnitPolicyObservationV1.model_validate_json(
                        args.unit_policy.read_bytes()
                    ),
                    args.cleanup_state,
                )
                write_new(args.output, canonical(receipt_v19.model_dump(mode="json")))
            elif args.operation == "resume-v19":
                rollback_receipt = resume_cleanup_v19(
                    state_v19,
                    LinuxIsolationEvidenceV18.model_validate_json(args.mechanics.read_bytes()),
                    LinuxSystemdUnitPolicyObservationV1.model_validate_json(
                        args.unit_policy.read_bytes()
                    ),
                    read_cleanup_state(args.cleanup_state),
                )
                write_new(args.output, canonical(rollback_receipt.model_dump(mode="json")))
                if not rollback_receipt.payload.cleanup_succeeded:
                    raise ValueError("V19 transient cgroup cleanup resume failed")
            else:
                rollback_receipt = rollback_v19(state_v19)
                write_new(args.output, canonical(rollback_receipt.model_dump(mode="json")))
                if not rollback_receipt.payload.cleanup_succeeded:
                    raise ValueError("V19 transient cgroup rollback failed")
    except BaseException:
        if not args.failure_output.exists():
            if args.operation.startswith("setup"):
                failure_phase: Literal["setup", "run", "cleanup"] = "setup"
            elif args.operation in {
                "cleanup",
                "rollback",
                "resume",
                "cleanup-v19",
                "rollback-v19",
                "resume-v19",
            }:
                failure_phase = "cleanup"
            else:
                failure_phase = "run"
            write_failure(
                args.failure_output,
                phase=failure_phase,
                implementation_commit=args.implementation_commit,
                environment_instance_id=args.environment_instance_id,
                state_id=(state.linux_cgroup_setup_state_id if state is not None else None),
            )
        raise


if __name__ == "__main__":
    main()
