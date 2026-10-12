#!/usr/bin/env python3
"""Provision and remove the exact temporary AppArmor authority for Linux qualification."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from devhub.benchmark import canonical, digest
from devhub.linux_isolation import (
    LINUX_APPARMOR_CURRENT,
    LINUX_APPARMOR_PROFILE_NAME,
    LINUX_PRIVATE_UNSHARE,
    LINUX_SYSTEM_UNSHARE,
    LinuxAppArmorCleanupPayloadV1,
    LinuxAppArmorCleanupReceiptV1,
    LinuxAppArmorLifecycleFailurePayloadV1,
    LinuxAppArmorLifecycleFailureV1,
    LinuxAppArmorSetupStatePayloadV1,
    LinuxAppArmorSetupStateV1,
    LinuxFileAuthorityV1,
    LinuxIsolationEvidenceV4,
    LinuxNativePathIdentityV1,
)

PROFILE_RELATIVE = Path("packaging/linux/apparmor/devfabric-linux-isolation-unshare")
INSTALLED_PROFILE = Path("/etc/apparmor.d/devfabric-linux-isolation-unshare")
PRIVATE_LAUNCHER = Path(LINUX_PRIVATE_UNSHARE)
SYSTEM_LAUNCHER = Path(LINUX_SYSTEM_UNSHARE)
PARSER = Path("/usr/sbin/apparmor_parser")
LOADED_PROFILES = Path("/sys/kernel/security/apparmor/profiles")
LOADED_SNAPSHOT = Path("/run/devfabric/devfabric-linux-isolation-profiles")
PRIVATE_PARENT = PRIVATE_LAUNCHER.parent
PRIVATE_ROOT = PRIVATE_PARENT.parent
RUNTIME_PARENT = LOADED_SNAPSHOT.parent
_COMMIT = re.compile(r"^[a-f0-9]{40}$")
_ENVIRONMENT = re.compile(r"^[a-f0-9]{32}$")
Runner = Callable[[list[str]], subprocess.CompletedProcess[bytes]]
LifecyclePhase = Literal["setup", "rollback", "cleanup", "finalization"]


class LifecycleOperationError(Exception):
    def __init__(
        self,
        *,
        phase: str,
        state_id: str | None,
        cleanup_attempted: bool,
        cleanup_succeeded: bool,
    ) -> None:
        super().__init__("Privileged AppArmor lifecycle operation failed")
        self.phase = phase
        self.state_id = state_id
        self.cleanup_attempted = cleanup_attempted
        self.cleanup_succeeded = cleanup_succeeded


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def run(command: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, capture_output=True, check=False, timeout=30)


def checked(command: list[str], runner: Runner = run) -> bytes:
    result = runner(command)
    if result.returncode != 0:
        raise ValueError("Privileged AppArmor lifecycle command failed")
    return result.stdout


def git(repo: Path, arguments: list[str], runner: Runner = run) -> bytes:
    return checked(
        ["git", "-c", f"safe.directory={repo}", "--no-replace-objects", *arguments], runner
    )


def verify_repo(repo: Path, implementation_commit: str, runner: Runner = run) -> None:
    if git(repo, ["rev-parse", "HEAD"], runner).decode("ascii").strip() != implementation_commit:
        raise ValueError("AppArmor setup commit differs from the exact checkout")
    if git(repo, ["status", "--porcelain"], runner):
        raise ValueError("AppArmor setup requires a clean checkout")


def git_blob_sha256(repo: Path, implementation_commit: str, runner: Runner = run) -> str:
    raw = git(
        repo,
        ["cat-file", "blob", f"{implementation_commit}:{PROFILE_RELATIVE.as_posix()}"],
        runner,
    )
    return sha256(raw)


def safe_root_file(path: Path, *, executable: bool = False) -> None:
    if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
        raise ValueError("Required root authority is not a regular non-symlink file")
    info = path.stat()
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != 0 or info.st_gid != 0 or mode & 0o022 or mode & 0o7000:
        raise ValueError("Required root authority has unsafe ownership or mode")
    if executable and not mode & 0o100:
        raise ValueError("Required root authority is not executable")


def safe_root_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path:
        raise ValueError("AppArmor parent is not a regular non-symlink directory")
    info = path.stat()
    if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError("AppArmor parent directory has unsafe ownership or mode")


def loaded_profile_lines() -> tuple[str, ...]:
    return tuple(LOADED_PROFILES.read_text(encoding="utf-8").splitlines())


def profile_is_loaded() -> bool:
    return bool(named_profile_lines())


def named_profile_lines() -> tuple[str, ...]:
    return tuple(
        line
        for line in loaded_profile_lines()
        if line.split(" ", 1)[0] == LINUX_APPARMOR_PROFILE_NAME
    )


def exact_profile_is_loaded() -> bool:
    return named_profile_lines() == (LINUX_APPARMOR_CURRENT,)


def write_exclusive(path: Path, raw: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    os.chown(path, 0, 0)
    os.chmod(path, mode)


def write_state(path: Path, payload: LinuxAppArmorSetupStatePayloadV1) -> None:
    state = LinuxAppArmorSetupStateV1.create(payload)
    temporary = path.with_name(path.name + ".new")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("AppArmor setup state temporary path already exists")
    write_exclusive(temporary, canonical(state.model_dump(mode="json")), 0o600)
    os.replace(temporary, path)


def update_state(
    path: Path, payload: LinuxAppArmorSetupStatePayloadV1, **changes: object
) -> LinuxAppArmorSetupStatePayloadV1:
    updated = LinuxAppArmorSetupStatePayloadV1.model_validate(
        payload.model_dump(mode="python") | changes
    )
    write_state(path, updated)
    return updated


def create_parent(path: Path, mode: int) -> bool:
    if path.exists() or path.is_symlink():
        safe_root_directory(path)
        return False
    path.mkdir(parents=False, mode=mode)
    os.chown(path, 0, 0)
    os.chmod(path, mode)
    safe_root_directory(path)
    return True


def native_identity(path: Path) -> LinuxNativePathIdentityV1:
    info = path.stat()
    return LinuxNativePathIdentityV1(device=info.st_dev, inode=info.st_ino)


def ensure_absent_before_setup(state_output: Path) -> None:
    for path in (PRIVATE_LAUNCHER, INSTALLED_PROFILE, LOADED_SNAPSHOT, state_output):
        if path.exists() or path.is_symlink():
            raise ValueError("AppArmor setup target already exists")
    if profile_is_loaded():
        raise ValueError("AppArmor qualification profile is already loaded")


def setup(
    repo: Path,
    implementation_commit: str,
    environment_instance_id: str,
    state_output: Path,
    runner: Runner = run,
) -> None:
    if os.geteuid() != 0:
        raise ValueError("AppArmor setup must run as root")
    if not _COMMIT.fullmatch(implementation_commit) or not _ENVIRONMENT.fullmatch(
        environment_instance_id
    ):
        raise ValueError("AppArmor setup identity is invalid")
    repo = repo.resolve(strict=True)
    verify_repo(repo, implementation_commit, runner)
    source = repo / PROFILE_RELATIVE
    safe_root_file(SYSTEM_LAUNCHER, executable=True)
    safe_root_file(PARSER, executable=True)
    source_sha = file_sha256(source)
    blob_sha = git_blob_sha256(repo, implementation_commit, runner)
    if source_sha != blob_sha:
        raise ValueError("Checked-out AppArmor policy differs from the reviewed Git blob")
    ensure_absent_before_setup(state_output)
    payload = LinuxAppArmorSetupStatePayloadV1(
        implementation_commit=implementation_commit,
        environment_instance_id=environment_instance_id,
        source_git_blob_sha256=blob_sha,
        source_sha256=source_sha,
        system_unshare_sha256=file_sha256(SYSTEM_LAUNCHER),
        parser_sha256=file_sha256(PARSER),
    )
    write_state(state_output, payload)
    try:
        if not PRIVATE_ROOT.exists():
            payload = update_state(state_output, payload, private_root_created=True)
        if create_parent(PRIVATE_ROOT, 0o755):
            payload = update_state(
                state_output,
                payload,
                private_root_identity=native_identity(PRIVATE_ROOT),
            )
        if not PRIVATE_PARENT.exists():
            payload = update_state(state_output, payload, private_parent_created=True)
        if create_parent(PRIVATE_PARENT, 0o755):
            payload = update_state(
                state_output,
                payload,
                private_parent_identity=native_identity(PRIVATE_PARENT),
            )
        if not RUNTIME_PARENT.exists():
            payload = update_state(state_output, payload, runtime_parent_created=True)
        if create_parent(RUNTIME_PARENT, 0o755):
            payload = update_state(
                state_output,
                payload,
                runtime_parent_identity=native_identity(RUNTIME_PARENT),
            )

        payload = update_state(state_output, payload, private_launcher_created=True)
        write_exclusive(PRIVATE_LAUNCHER, SYSTEM_LAUNCHER.read_bytes(), 0o755)
        if file_sha256(PRIVATE_LAUNCHER) != payload.system_unshare_sha256:
            raise ValueError("Private launcher differs from reviewed system unshare")

        payload = update_state(state_output, payload, installed_profile_created=True)
        write_exclusive(INSTALLED_PROFILE, source.read_bytes(), 0o644)
        if file_sha256(INSTALLED_PROFILE) != payload.source_sha256:
            raise ValueError("Installed AppArmor profile differs from reviewed source")

        payload = update_state(state_output, payload, profile_loaded=True)
        checked([str(PARSER), "-r", str(INSTALLED_PROFILE)], runner)
        if loaded_profile_lines().count(LINUX_APPARMOR_CURRENT) != 1:
            raise ValueError("Exact AppArmor qualification profile did not load")

        payload = update_state(state_output, payload, loaded_snapshot_created=True)
        write_exclusive(LOADED_SNAPSHOT, (LINUX_APPARMOR_CURRENT + "\n").encode(), 0o444)
        update_state(state_output, payload, setup_complete=True)
    except BaseException as error:
        state_id = read_state(state_output).linux_apparmor_setup_state_id
        try:
            cleanup_owned(
                state_output,
                runner=runner,
                require_complete=False,
                expected_state_id=state_id,
            )
        except BaseException as cleanup_error:
            try:
                state_id = read_state(state_output).linux_apparmor_setup_state_id
            except BaseException:
                pass
            raise LifecycleOperationError(
                phase="setup",
                state_id=state_id,
                cleanup_attempted=True,
                cleanup_succeeded=False,
            ) from cleanup_error
        raise LifecycleOperationError(
            phase="setup",
            state_id=state_id,
            cleanup_attempted=True,
            cleanup_succeeded=True,
        ) from error


def read_state(path: Path) -> LinuxAppArmorSetupStateV1:
    if path.is_symlink() or not path.is_file():
        raise ValueError("AppArmor setup state is unavailable")
    info = path.stat()
    if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("AppArmor setup state has unsafe ownership or mode")
    return LinuxAppArmorSetupStateV1.model_validate_json(path.read_bytes())


def remove_owned_file(path: Path, expected_sha256: str, expected_mode: int) -> None:
    safe_root_file(path, executable=bool(expected_mode & 0o100))
    if file_sha256(path) != expected_sha256 or stat.S_IMODE(path.stat().st_mode) != expected_mode:
        raise ValueError("Owned AppArmor lifecycle file changed before cleanup")
    path.unlink()


def validate_owned_file(path: Path, expected_sha256: str, expected_mode: int) -> None:
    if not path.exists() or path.is_symlink():
        raise ValueError("Owned AppArmor lifecycle file is unavailable before cleanup")
    safe_root_file(path, executable=bool(expected_mode & 0o100))
    if file_sha256(path) != expected_sha256 or stat.S_IMODE(path.stat().st_mode) != expected_mode:
        raise ValueError("Owned AppArmor lifecycle file changed before cleanup")


def validate_completed_cleanup_authority(state: LinuxAppArmorSetupStateV1) -> None:
    payload = state.payload
    if not payload.setup_complete:
        raise ValueError("AppArmor setup did not complete")
    lines = named_profile_lines()
    if payload.profile_unloaded:
        if lines:
            raise ValueError("Removed AppArmor profile unexpectedly remains loaded")
    elif payload.profile_unload_started:
        if lines not in ((), (LINUX_APPARMOR_CURRENT,)):
            raise ValueError("Pending AppArmor profile unload authority is ambiguous")
    elif lines != (LINUX_APPARMOR_CURRENT,):
        raise ValueError("Exact loaded AppArmor profile authority is absent or changed")
    validate_owned_file(PARSER, payload.parser_sha256, stat.S_IMODE(PARSER.stat().st_mode))
    validate_journal_file(
        INSTALLED_PROFILE,
        created=payload.installed_profile_created,
        started=payload.installed_profile_removal_started,
        removed=payload.installed_profile_removed,
        expected_sha256=payload.source_sha256,
        expected_mode=0o644,
        require_complete=True,
    )
    validate_journal_file(
        PRIVATE_LAUNCHER,
        created=payload.private_launcher_created,
        started=payload.private_launcher_removal_started,
        removed=payload.private_launcher_removed,
        expected_sha256=payload.system_unshare_sha256,
        expected_mode=0o755,
        require_complete=True,
    )
    validate_journal_file(
        LOADED_SNAPSHOT,
        created=payload.loaded_snapshot_created,
        started=payload.loaded_snapshot_removal_started,
        removed=payload.loaded_snapshot_removed,
        expected_sha256=sha256((LINUX_APPARMOR_CURRENT + "\n").encode()),
        expected_mode=0o444,
        require_complete=True,
    )
    validate_journal_directory(
        PRIVATE_PARENT,
        created=payload.private_parent_created,
        started=payload.private_parent_removal_started,
        removed=payload.private_parent_removed,
        identity=payload.private_parent_identity,
        expected_children=(PRIVATE_LAUNCHER.name,) if not path_is_absent(PRIVATE_LAUNCHER) else (),
        require_complete=True,
    )
    validate_journal_directory(
        PRIVATE_ROOT,
        created=payload.private_root_created,
        started=payload.private_root_removal_started,
        removed=payload.private_root_removed,
        identity=payload.private_root_identity,
        expected_children=(PRIVATE_PARENT.name,) if not path_is_absent(PRIVATE_PARENT) else (),
        require_complete=True,
    )
    validate_journal_directory(
        RUNTIME_PARENT,
        created=payload.runtime_parent_created,
        started=payload.runtime_parent_removal_started,
        removed=payload.runtime_parent_removed,
        identity=payload.runtime_parent_identity,
        expected_children=(LOADED_SNAPSHOT.name,) if not path_is_absent(LOADED_SNAPSHOT) else (),
        require_complete=True,
    )


def path_is_absent(path: Path) -> bool:
    return not path.exists() and not path.is_symlink()


def validate_journal_file(
    path: Path,
    *,
    created: bool,
    started: bool,
    removed: bool,
    expected_sha256: str,
    expected_mode: int,
    require_complete: bool,
) -> None:
    if not created:
        return
    if removed:
        if not path_is_absent(path):
            raise ValueError("Removed AppArmor lifecycle file reappeared")
        return
    if path_is_absent(path):
        if require_complete and not started:
            raise ValueError("Owned AppArmor lifecycle file is unavailable before cleanup")
        return
    validate_owned_file(path, expected_sha256, expected_mode)


def validate_journal_directory(
    path: Path,
    *,
    created: bool,
    started: bool,
    removed: bool,
    identity: LinuxNativePathIdentityV1 | None,
    expected_children: tuple[str, ...],
    require_complete: bool,
) -> None:
    if not created:
        return
    if removed:
        if not path_is_absent(path):
            raise ValueError("Removed AppArmor lifecycle directory reappeared")
        return
    if path_is_absent(path):
        if require_complete and not started:
            raise ValueError("Owned AppArmor lifecycle directory is unavailable before cleanup")
        return
    if identity is None:
        raise ValueError("Owned AppArmor lifecycle directory lacks native identity")
    safe_root_directory(path)
    info = path.stat()
    if (info.st_dev, info.st_ino) != (identity.device, identity.inode):
        raise ValueError("Owned AppArmor lifecycle directory identity changed before cleanup")
    if tuple(sorted(item.name for item in path.iterdir())) != tuple(sorted(expected_children)):
        raise ValueError("Owned AppArmor lifecycle directory contents changed before cleanup")


def validate_file_authority(path: Path, authority: LinuxFileAuthorityV1) -> None:
    validate_owned_file(path, authority.sha256, int(authority.mode, 8))
    info = path.stat()
    if (
        info.st_uid != authority.owner_uid
        or info.st_gid != authority.owner_gid
        or info.st_dev != authority.native_identity.device
        or info.st_ino != authority.native_identity.inode
    ):
        raise ValueError("AppArmor mechanics file authority changed before cleanup")


def validate_journal_file_authority(
    path: Path,
    authority: LinuxFileAuthorityV1,
    *,
    created: bool,
    started: bool,
    removed: bool,
) -> None:
    validate_journal_file(
        path,
        created=created,
        started=started,
        removed=removed,
        expected_sha256=authority.sha256,
        expected_mode=int(authority.mode, 8),
        require_complete=True,
    )
    if created and not removed and not path_is_absent(path):
        validate_file_authority(path, authority)


def cleanup_owned(
    state_path: Path,
    *,
    runner: Runner = run,
    require_complete: bool = True,
    expected_state_id: str | None = None,
) -> LinuxAppArmorSetupStateV1:
    state = read_state(state_path)
    payload = state.payload
    if expected_state_id is not None and state.linux_apparmor_setup_state_id != expected_state_id:
        raise ValueError("AppArmor setup state changed before cleanup")
    if require_complete:
        validate_completed_cleanup_authority(state)
    else:
        lines = named_profile_lines()
        if lines and lines != (LINUX_APPARMOR_CURRENT,):
            raise ValueError("AppArmor rollback profile authority is ambiguous")
        if (
            payload.profile_loaded
            and not payload.profile_unloaded
            and file_sha256(PARSER) != payload.parser_sha256
        ):
            raise ValueError("AppArmor parser changed before cleanup")
        validate_journal_file(
            INSTALLED_PROFILE,
            created=payload.installed_profile_created,
            started=payload.installed_profile_removal_started,
            removed=payload.installed_profile_removed,
            expected_sha256=payload.source_sha256,
            expected_mode=0o644,
            require_complete=False,
        )
        validate_journal_file(
            PRIVATE_LAUNCHER,
            created=payload.private_launcher_created,
            started=payload.private_launcher_removal_started,
            removed=payload.private_launcher_removed,
            expected_sha256=payload.system_unshare_sha256,
            expected_mode=0o755,
            require_complete=False,
        )
        validate_journal_file(
            LOADED_SNAPSHOT,
            created=payload.loaded_snapshot_created,
            started=payload.loaded_snapshot_removal_started,
            removed=payload.loaded_snapshot_removed,
            expected_sha256=sha256((LINUX_APPARMOR_CURRENT + "\n").encode()),
            expected_mode=0o444,
            require_complete=False,
        )
        validate_journal_directory(
            PRIVATE_PARENT,
            created=payload.private_parent_created,
            started=payload.private_parent_removal_started,
            removed=payload.private_parent_removed,
            identity=payload.private_parent_identity,
            expected_children=(PRIVATE_LAUNCHER.name,) if PRIVATE_LAUNCHER.exists() else (),
            require_complete=False,
        )
        validate_journal_directory(
            PRIVATE_ROOT,
            created=payload.private_root_created,
            started=payload.private_root_removal_started,
            removed=payload.private_root_removed,
            identity=payload.private_root_identity,
            expected_children=(PRIVATE_PARENT.name,) if PRIVATE_PARENT.exists() else (),
            require_complete=False,
        )
        validate_journal_directory(
            RUNTIME_PARENT,
            created=payload.runtime_parent_created,
            started=payload.runtime_parent_removal_started,
            removed=payload.runtime_parent_removed,
            identity=payload.runtime_parent_identity,
            expected_children=(LOADED_SNAPSHOT.name,) if LOADED_SNAPSHOT.exists() else (),
            require_complete=False,
        )

    failures: list[str] = []

    def advance(started_field: str, completed_field: str, action: Callable[[], None]) -> None:
        nonlocal payload
        if not getattr(payload, started_field):
            try:
                payload = update_state(state_path, payload, **{started_field: True})
            except BaseException:
                failures.append(started_field)
                return
        try:
            action()
        except BaseException:
            failures.append(completed_field)
            return
        try:
            payload = update_state(state_path, payload, **{completed_field: True})
        except BaseException:
            failures.append(completed_field)

    if payload.profile_loaded and not payload.profile_unloaded:

        def unload() -> None:
            if exact_profile_is_loaded():
                checked([str(PARSER), "-R", str(INSTALLED_PROFILE)], runner)
            if profile_is_loaded():
                raise ValueError("AppArmor qualification profile remains loaded")

        advance("profile_unload_started", "profile_unloaded", unload)

    for created, removed, path, expected_sha256, expected_mode, started_field, field in (
        (
            payload.loaded_snapshot_created,
            payload.loaded_snapshot_removed,
            LOADED_SNAPSHOT,
            sha256((LINUX_APPARMOR_CURRENT + "\n").encode()),
            0o444,
            "loaded_snapshot_removal_started",
            "loaded_snapshot_removed",
        ),
        (
            payload.installed_profile_created,
            payload.installed_profile_removed,
            INSTALLED_PROFILE,
            payload.source_sha256,
            0o644,
            "installed_profile_removal_started",
            "installed_profile_removed",
        ),
        (
            payload.private_launcher_created,
            payload.private_launcher_removed,
            PRIVATE_LAUNCHER,
            payload.system_unshare_sha256,
            0o755,
            "private_launcher_removal_started",
            "private_launcher_removed",
        ),
    ):
        if created and not removed:
            advance(
                started_field,
                field,
                lambda path=path, expected_sha256=expected_sha256, expected_mode=expected_mode: (
                    remove_owned_file(path, expected_sha256, expected_mode)
                    if not path_is_absent(path)
                    else None
                ),
            )

    for created, removed, path, started_field, field in (
        (
            payload.private_parent_created,
            payload.private_parent_removed,
            PRIVATE_PARENT,
            "private_parent_removal_started",
            "private_parent_removed",
        ),
        (
            payload.private_root_created,
            payload.private_root_removed,
            PRIVATE_ROOT,
            "private_root_removal_started",
            "private_root_removed",
        ),
        (
            payload.runtime_parent_created,
            payload.runtime_parent_removed,
            RUNTIME_PARENT,
            "runtime_parent_removal_started",
            "runtime_parent_removed",
        ),
    ):
        if created and not removed:
            advance(
                started_field,
                field,
                lambda path=path: path.rmdir() if not path_is_absent(path) else None,
            )

    if failures:
        raise ValueError("AppArmor cleanup did not remove every independently safe owned object")
    state_path.unlink()
    return state


def cleanup(
    state_path: Path,
    mechanics_path: Path,
    output: Path,
    runner: Runner = run,
) -> None:
    if output.exists() or output.is_symlink():
        raise ValueError("AppArmor cleanup receipt already exists")
    mechanics = LinuxIsolationEvidenceV4.model_validate_json(mechanics_path.read_bytes())
    state = read_state(state_path)
    profile = mechanics.payload.profile.payload
    apparmor = profile.host.apparmor
    if (
        state.payload.implementation_commit != profile.implementation_commit
        or state.payload.environment_instance_id != profile.environment_instance_id
        or state.payload.source_git_blob_sha256 != apparmor.source_git_blob_sha256
        or state.payload.source_sha256 != apparmor.source_sha256
        or state.payload.system_unshare_sha256 != profile.system_unshare.sha256
        or state.payload.system_unshare_sha256 != profile.unshare.sha256
        or state.payload.parser_sha256 != apparmor.parser.sha256
    ):
        raise ValueError("AppArmor setup state differs from mechanics authority")
    validate_file_authority(SYSTEM_LAUNCHER, profile.system_unshare)
    validate_file_authority(PARSER, apparmor.parser)
    validate_journal_file_authority(
        PRIVATE_LAUNCHER,
        profile.unshare,
        created=state.payload.private_launcher_created,
        started=state.payload.private_launcher_removal_started,
        removed=state.payload.private_launcher_removed,
    )
    validate_journal_file_authority(
        INSTALLED_PROFILE,
        apparmor.installed_profile,
        created=state.payload.installed_profile_created,
        started=state.payload.installed_profile_removal_started,
        removed=state.payload.installed_profile_removed,
    )
    validate_journal_file_authority(
        LOADED_SNAPSHOT,
        apparmor.loaded_profiles_snapshot,
        created=state.payload.loaded_snapshot_created,
        started=state.payload.loaded_snapshot_removal_started,
        removed=state.payload.loaded_snapshot_removed,
    )
    cleanup_owned(
        state_path,
        runner=runner,
        expected_state_id=state.linux_apparmor_setup_state_id,
    )
    authority_sha = digest(canonical(apparmor.model_dump(mode="json")))
    receipt = LinuxAppArmorCleanupReceiptV1.create(
        LinuxAppArmorCleanupPayloadV1(
            implementation_commit=profile.implementation_commit,
            environment_instance_id=profile.environment_instance_id,
            linux_isolation_profile_id=mechanics.payload.profile.linux_isolation_profile_id,
            linux_isolation_evidence_id=mechanics.linux_isolation_evidence_id,
            apparmor_authority_sha256=authority_sha,
        )
    )
    write_exclusive(output, canonical(receipt.model_dump(mode="json")), 0o444)


def write_lifecycle_failure(
    output: Path,
    *,
    phase: LifecyclePhase,
    implementation_commit: str,
    environment_instance_id: str,
    state_id: str | None,
    cleanup_attempted: bool,
    cleanup_succeeded: bool,
) -> None:
    failure = LinuxAppArmorLifecycleFailureV1.create(
        LinuxAppArmorLifecycleFailurePayloadV1(
            phase=phase,
            reason_code="cleanup_failed"
            if cleanup_attempted and not cleanup_succeeded
            else "unexpected_internal_failure",
            implementation_commit=implementation_commit,
            environment_instance_id=environment_instance_id,
            linux_apparmor_setup_state_id=state_id,
            cleanup_attempted=cleanup_attempted,
            cleanup_succeeded=cleanup_succeeded,
        )
    )
    write_exclusive(output, canonical(failure.model_dump(mode="json")), 0o444)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    setup_parser = subparsers.add_parser("setup")
    setup_parser.add_argument("--repo", type=Path, required=True)
    setup_parser.add_argument("--implementation-commit", required=True)
    setup_parser.add_argument("--environment-instance-id", required=True)
    setup_parser.add_argument("--state-output", type=Path, required=True)
    setup_parser.add_argument("--failure-output", type=Path, required=True)
    cleanup_parser = subparsers.add_parser("cleanup")
    cleanup_parser.add_argument("--state", type=Path, required=True)
    cleanup_parser.add_argument("--mechanics", type=Path, required=True)
    cleanup_parser.add_argument("--output", type=Path, required=True)
    cleanup_parser.add_argument("--implementation-commit", required=True)
    cleanup_parser.add_argument("--environment-instance-id", required=True)
    cleanup_parser.add_argument("--failure-output", type=Path, required=True)
    rollback_parser = subparsers.add_parser("rollback")
    rollback_parser.add_argument("--state", type=Path, required=True)
    rollback_parser.add_argument("--implementation-commit", required=True)
    rollback_parser.add_argument("--environment-instance-id", required=True)
    rollback_parser.add_argument("--failure-output", type=Path, required=True)
    args = parser.parse_args()
    if not _COMMIT.fullmatch(args.implementation_commit) or not _ENVIRONMENT.fullmatch(
        args.environment_instance_id
    ):
        raise ValueError("AppArmor lifecycle identity is invalid")
    state_id: str | None = None
    cleanup_attempted = False
    cleanup_succeeded = False
    try:
        if args.command == "setup":
            setup(
                args.repo,
                args.implementation_commit,
                args.environment_instance_id,
                args.state_output,
            )
        else:
            state = read_state(args.state)
            state_id = state.linux_apparmor_setup_state_id
            if (
                state.payload.implementation_commit != args.implementation_commit
                or state.payload.environment_instance_id != args.environment_instance_id
            ):
                raise ValueError("AppArmor lifecycle invocation identity differs from setup")
            cleanup_attempted = True
            if args.command == "cleanup":
                cleanup(args.state, args.mechanics, args.output)
            else:
                cleanup_owned(
                    args.state,
                    require_complete=False,
                    expected_state_id=state_id,
                )
            cleanup_succeeded = True
    except BaseException as error:
        if isinstance(error, LifecycleOperationError):
            state_id = error.state_id
            cleanup_attempted = error.cleanup_attempted
            cleanup_succeeded = error.cleanup_succeeded
        state_path = getattr(args, "state", getattr(args, "state_output", None))
        if state_path is not None and Path(state_path).is_file():
            try:
                state_id = read_state(Path(state_path)).linux_apparmor_setup_state_id
            except BaseException:
                pass
        write_lifecycle_failure(
            args.failure_output,
            phase=args.command,
            implementation_commit=args.implementation_commit,
            environment_instance_id=args.environment_instance_id,
            state_id=state_id,
            cleanup_attempted=cleanup_attempted,
            cleanup_succeeded=cleanup_succeeded,
        )
        raise


if __name__ == "__main__":
    main()
