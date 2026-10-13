#!/usr/bin/env python3
"""Create, run, and clean one exact native-Linux transient service cgroup."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
import time
from pathlib import Path
from typing import Literal

from devhub.benchmark import canonical
from devhub.linux_isolation import (
    LINUX_CGROUP_ROOT,
    LINUX_SYSTEMCTL,
    LINUX_SYSTEMD_RUN,
    LinuxCgroupBoundaryAuthorityV1,
    LinuxCgroupCleanupPayloadV2,
    LinuxCgroupCleanupReceiptV2,
    LinuxCgroupCleanupStatePayloadV2,
    LinuxCgroupCleanupStateV2,
    LinuxCgroupLifecycleFailurePayloadV1,
    LinuxCgroupLifecycleFailureV1,
    LinuxCgroupRollbackPayloadV1,
    LinuxCgroupRollbackReceiptV1,
    LinuxCgroupSetupStatePayloadV1,
    LinuxCgroupSetupStateV1,
    LinuxIsolationEvidenceV17,
    LinuxNativePathIdentityV1,
    LinuxSystemdToolAuthorityV1,
    LinuxToolVersionEnvironmentV1,
)

_COMMIT = re.compile(r"^[a-f0-9]{40}$")
_ENVIRONMENT = re.compile(r"^[a-f0-9]{32}$")
_VERSION_ENVIRONMENT = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"}


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
    args = parser.parse_args()
    state: LinuxCgroupSetupStateV1 | None = None
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
        else:
            state = read_state(args.state)
            value = resume_cleanup(
                state,
                LinuxIsolationEvidenceV17.model_validate_json(args.mechanics.read_bytes()),
                read_cleanup_state(args.cleanup_state),
            )
            write_new(args.output, canonical(value.model_dump(mode="json")))
            if not value.payload.cleanup_succeeded:
                raise ValueError("Transient cgroup cleanup resume failed")
    except BaseException:
        if not args.failure_output.exists():
            write_failure(
                args.failure_output,
                phase=("cleanup" if args.operation in {"rollback", "resume"} else args.operation),
                implementation_commit=args.implementation_commit,
                environment_instance_id=args.environment_instance_id,
                state_id=(state.linux_cgroup_setup_state_id if state is not None else None),
            )
        raise


if __name__ == "__main__":
    main()
