"""Strict contracts for the native Linux isolation qualification baseline.

The contracts in this module describe one exact Linux host and one closed
namespace launch.  They intentionally do not turn a native bundle into an
execution-ready package: cgroup and syscall-filter qualification remain
separate required gates, and a qualified cgroup receipt does not imply the
remaining syscall, executor or package gates.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from devhub.benchmark import Digest, canonical, digest
from devhub.models import Contract, ContractV2

LINUX_ISOLATION_PROFILE_KIND = "linux_native_isolation_v1"
LINUX_ISOLATION_RECEIPT_KIND = "linux_native_isolation_receipt_v1"
LINUX_ISOLATION_PROFILE_KIND_V2 = "linux_native_isolation_v2"
LINUX_ISOLATION_RECEIPT_KIND_V2 = "linux_native_isolation_receipt_v2"
LINUX_ISOLATION_PROFILE_KIND_V3 = "linux_native_isolation_v3"
LINUX_ISOLATION_RECEIPT_KIND_V3 = "linux_native_isolation_receipt_v3"
LINUX_ISOLATION_PROFILE_KIND_V4 = "linux_native_isolation_v4"
LINUX_ISOLATION_RECEIPT_KIND_V4 = "linux_native_isolation_receipt_v4"
LINUX_ISOLATION_PROFILE_KIND_V5 = "linux_native_isolation_v5"
LINUX_ISOLATION_RECEIPT_KIND_V5 = "linux_native_isolation_receipt_v5"
LINUX_ISOLATION_PROFILE_KIND_V6 = "linux_native_isolation_v6"
LINUX_ISOLATION_RECEIPT_KIND_V6 = "linux_native_isolation_receipt_v6"
LINUX_TARGET_OS = "ubuntu"
LINUX_TARGET_VERSION = "24.04"
LINUX_TARGET_ARCH = "x86_64"
LINUX_SANDBOX_UID = 1000
LINUX_SANDBOX_GID = 1000
LINUX_SYSTEM_UNSHARE = "/usr/bin/unshare"
LINUX_PRIVATE_UNSHARE = "/opt/devfabric/libexec/unshare"
LINUX_APPARMOR_PROFILE_NAME = "devfabric-linux-isolation-unshare"
LINUX_APPARMOR_PROFILE_ATTACHMENT = LINUX_PRIVATE_UNSHARE
LINUX_APPARMOR_PROFILE_MODE = "unconfined"
LINUX_APPARMOR_CURRENT = f"{LINUX_APPARMOR_PROFILE_NAME} ({LINUX_APPARMOR_PROFILE_MODE})"
LINUX_SYSTEMD_RUN = "/usr/bin/systemd-run"
LINUX_SYSTEMCTL = "/usr/bin/systemctl"
LINUX_SYSTEMD_ANALYZE: Literal["/usr/bin/systemd-analyze"] = "/usr/bin/systemd-analyze"
LINUX_SYSTEMD_MANAGER: Literal["/usr/lib/systemd/systemd"] = "/usr/lib/systemd/systemd"
LINUX_REVIEWED_SYSTEMD_VERSION_SHA256 = (
    "24e682030f54829600ce9c96ef9d8be4297eb4cd1b11eca8fa7f83c5c4595fc7"
)
LINUX_SYSCALL_ALLOWLIST_SHA256 = "0f380c5848c32586f2614fcb8272760accf03a7995ba562c2a34a262ef8c1eda"
LINUX_SYSCALL_ALLOWLIST_COUNT = 390
LINUX_CGROUP_ROOT: Literal["/sys/fs/cgroup"] = "/sys/fs/cgroup"
LINUX_CGROUP_MEMORY_MAX: Literal["2147483648"] = "2147483648"
LINUX_CGROUP_PIDS_MAX: Literal["128"] = "128"
LINUX_CGROUP_CPU_MAX: Literal["200000 100000"] = "200000 100000"
LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15
LANDLOCK_ACCESS_FS_ABI3 = (1 << 15) - 1
MINIMUM_REVIEWED_LANDLOCK_ABI = 3
MAXIMUM_REVIEWED_LANDLOCK_ABI = 6


def canonical_syscall_allowlist(names: tuple[str, ...]) -> bytes:
    """Return the frozen V19 compact-JSON representation of an allowlist."""

    return json.dumps(
        list(names),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def syscall_allowlist_sha256(names: tuple[str, ...]) -> str:
    """Hash the exact frozen V19 syscall-allowlist representation."""

    return hashlib.sha256(canonical_syscall_allowlist(names)).hexdigest()


def landlock_handled_access(abi: int) -> int:
    """Return the complete filesystem access mask supported by the reviewed ABI."""

    if abi not in {3, 4, 5, 6}:
        raise ValueError("Linux qualification supports exactly Landlock ABI 3 through 6")
    return LANDLOCK_ACCESS_FS_ABI3 | (LANDLOCK_ACCESS_FS_IOCTL_DEV if abi >= 5 else 0)


def enforced_landlock_abi(kernel_abi: int) -> int:
    """Select the reviewed policy ABI without hiding the observed kernel ABI."""

    if kernel_abi < MINIMUM_REVIEWED_LANDLOCK_ABI:
        raise ValueError("Linux qualification requires Landlock kernel ABI 3 or newer")
    return min(kernel_abi, MAXIMUM_REVIEWED_LANDLOCK_ABI)


def _mount_path(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def observed_private_mount_targets(
    raw: bytes, expected_targets: tuple[str, ...]
) -> tuple[str, ...]:
    """Parse mountinfo and verify the exact reviewed private-root mounts."""

    entries: dict[str, tuple[str, set[str]]] = {}
    for line in raw.decode("utf-8", errors="strict").splitlines():
        fields = line.split(" ")
        separator = fields.index("-")
        target = _mount_path(fields[4])
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


class LinuxNativePathIdentityV1(Contract):
    device: Annotated[int, Field(ge=0)]
    inode: Annotated[int, Field(ge=1)]


class LinuxFileAuthorityV1(Contract):
    """Content and ownership identity for one required host file."""

    locator: Annotated[str, Field(min_length=2, max_length=4096, pattern=r"^/[^\x00\r\n]+$")]
    sha256: Digest
    size: Annotated[int, Field(ge=1)]
    owner_uid: Annotated[int, Field(ge=0)]
    owner_gid: Annotated[int, Field(ge=0)]
    mode: Annotated[str, Field(pattern=r"^0[0-7]{3}$")]
    native_identity: LinuxNativePathIdentityV1


class LinuxDirectoryAuthorityV1(Contract):
    locator: Annotated[str, Field(min_length=2, max_length=4096, pattern=r"^/[^\x00\r\n]+$")]
    role: Literal["fixture", "state", "output", "broker", "scratch_root"]
    owner_uid: Annotated[int, Field(ge=1)]
    owner_gid: Annotated[int, Field(ge=1)]
    mode: Literal["0700"] = "0700"
    native_identity: LinuxNativePathIdentityV1


class LinuxBundleDirectoryAuthorityV1(LinuxDirectoryAuthorityV1):
    """Exact extracted native bundle root, retained at its published 0755 mode."""

    role: Literal["fixture"] = "fixture"
    mode: Literal["0755"] = "0755"  # type: ignore[assignment]


class LinuxToolAuthorityV1(LinuxFileAuthorityV1):
    """Exact host tool used before the child drops namespace capabilities."""

    name: Literal["unshare", "mount"]
    version_output_sha256: Digest

    @model_validator(mode="after")
    def root_owned_non_writable_tool(self) -> LinuxToolAuthorityV1:
        mode = int(self.mode, 8)
        if self.owner_uid != 0 or self.owner_gid != 0:
            raise ValueError("Linux namespace tools must be root-owned")
        if mode & 0o022 or not mode & 0o100 or mode & 0o7000:
            raise ValueError("Linux namespace tool mode is unsafe")
        return self


class LinuxToolAuthorityV4(ContractV2):
    """Complete authority for a host tool whose special mode bits matter."""

    schema_version: Literal[4] = 4  # type: ignore[assignment]
    name: Literal["unshare", "mount"]
    locator: Annotated[str, Field(min_length=2, max_length=4096, pattern=r"^/[^\x00\r\n]+$")]
    sha256: Digest
    size: Annotated[int, Field(ge=1)]
    owner_uid: Annotated[int, Field(ge=0)]
    owner_gid: Annotated[int, Field(ge=0)]
    permission_bits: Annotated[str, Field(pattern=r"^0[0-7]{3}$")]
    special_bits: Annotated[str, Field(pattern=r"^0[0-7]000$")]
    full_mode: Annotated[str, Field(pattern=r"^0[0-7]{4}$")]
    native_identity: LinuxNativePathIdentityV1
    version_output_sha256: Digest

    @model_validator(mode="after")
    def exact_safe_tool_mode(self) -> LinuxToolAuthorityV4:
        permissions = int(self.permission_bits, 8)
        special = int(self.special_bits, 8)
        full = int(self.full_mode, 8)
        if full != permissions | special:
            raise ValueError("Linux tool full mode differs from its permission components")
        if self.owner_uid != 0 or self.owner_gid != 0:
            raise ValueError("Linux namespace tools must be root-owned")
        if permissions & 0o022 or not permissions & 0o100:
            raise ValueError("Linux namespace tool permissions are unsafe")
        if special & (0o2000 | 0o1000):
            raise ValueError("Linux namespace tool has forbidden setgid or sticky bits")
        if special:
            if special != 0o4000 or self.name != "mount" or self.locator != "/usr/bin/mount":
                raise ValueError("Only exact /usr/bin/mount may carry setuid")
        return self


class LinuxAppArmorParserAuthorityV2(LinuxFileAuthorityV1):
    locator: Literal["/usr/sbin/apparmor_parser"] = "/usr/sbin/apparmor_parser"
    version_output_sha256: Digest

    @model_validator(mode="after")
    def root_owned_non_writable_parser(self) -> LinuxAppArmorParserAuthorityV2:
        mode = int(self.mode, 8)
        if self.owner_uid != 0 or self.owner_gid != 0:
            raise ValueError("AppArmor parser must be root-owned")
        if mode & 0o022 or not mode & 0o100 or mode & 0o7000:
            raise ValueError("AppArmor parser mode is unsafe")
        return self


class LinuxSystemdToolAuthorityV1(LinuxFileAuthorityV1):
    """Exact root-owned systemd client used for one transient cgroup."""

    name: Literal["systemd-run", "systemctl"]
    version_output_sha256: Digest

    @model_validator(mode="after")
    def root_owned_non_writable_tool(self) -> LinuxSystemdToolAuthorityV1:
        mode = int(self.mode, 8)
        if self.owner_uid != 0 or self.owner_gid != 0:
            raise ValueError("Linux systemd tools must be root-owned")
        if mode & 0o022 or not mode & 0o100 or mode & 0o7000:
            raise ValueError("Linux systemd tool mode is unsafe")
        return self


class LinuxAppArmorAuthorityV2(Contract):
    """Exact narrow user-namespace exception attached to the private launcher."""

    profile_name: Literal["devfabric-linux-isolation-unshare"] = "devfabric-linux-isolation-unshare"
    attachment: Literal["/opt/devfabric/libexec/unshare"] = "/opt/devfabric/libexec/unshare"
    mode: Literal["unconfined"] = "unconfined"
    source_relative_path: Literal["packaging/linux/apparmor/devfabric-linux-isolation-unshare"] = (
        "packaging/linux/apparmor/devfabric-linux-isolation-unshare"
    )
    source_git_blob_sha256: Digest
    source_sha256: Digest
    installed_profile: LinuxFileAuthorityV1
    parser: LinuxAppArmorParserAuthorityV2
    loaded_profiles_snapshot: LinuxFileAuthorityV1
    loaded_profile_line: Literal["devfabric-linux-isolation-unshare (unconfined)"] = (
        "devfabric-linux-isolation-unshare (unconfined)"
    )

    @model_validator(mode="after")
    def exact_installed_authority(self) -> LinuxAppArmorAuthorityV2:
        installed = self.installed_profile
        snapshot = self.loaded_profiles_snapshot
        expected_snapshot = (self.loaded_profile_line + "\n").encode("utf-8")
        if self.source_git_blob_sha256 != self.source_sha256:
            raise ValueError("AppArmor Git blob and checked-out source differ")
        if (
            installed.locator != "/etc/apparmor.d/devfabric-linux-isolation-unshare"
            or installed.sha256 != self.source_sha256
            or installed.owner_uid != 0
            or installed.owner_gid != 0
            or installed.mode != "0644"
        ):
            raise ValueError("Installed AppArmor profile differs from reviewed source authority")
        if (
            snapshot.locator != "/run/devfabric/devfabric-linux-isolation-profiles"
            or snapshot.sha256 != digest(expected_snapshot)
            or snapshot.size != len(expected_snapshot)
            or snapshot.owner_uid != 0
            or snapshot.owner_gid != 0
            or snapshot.mode != "0444"
        ):
            raise ValueError("AppArmor loaded-profile snapshot authority is unsafe")
        return self


class LinuxHostAuthorityV1(Contract):
    """Exact host observations that affect rootless isolation semantics."""

    os_id: Literal["ubuntu"] = "ubuntu"
    os_version_id: Literal["24.04"] = "24.04"
    architecture: Literal["x86_64"] = "x86_64"
    os_release_sha256: Digest
    kernel_release: Annotated[str, Field(min_length=1, max_length=256)]
    kernel_version_sha256: Digest
    user_namespace_clone_enabled: Literal[True] = True
    apparmor_userns_restriction_present: bool
    apparmor_userns_restriction: Annotated[int, Field(ge=0, le=1)] | None
    landlock_abi: Annotated[int, Field(ge=3, le=6)]
    cgroup_v2: Literal[True] = True
    delegated_cgroup_available: bool

    @model_validator(mode="after")
    def exact_apparmor_observation(self) -> LinuxHostAuthorityV1:
        if self.apparmor_userns_restriction_present != (
            self.apparmor_userns_restriction is not None
        ):
            raise ValueError("AppArmor userns sysctl presence and value disagree")
        return self


class LinuxHostAuthorityV2(Contract):
    """Exact Ubuntu 24.04 authority with a narrow private-launcher profile."""

    os_id: Literal["ubuntu"] = "ubuntu"
    os_version_id: Literal["24.04"] = "24.04"
    architecture: Literal["x86_64"] = "x86_64"
    os_release_sha256: Digest
    kernel_release: Annotated[str, Field(min_length=1, max_length=256)]
    kernel_version_sha256: Digest
    user_namespace_clone_enabled: Literal[True] = True
    apparmor_userns_restriction_present: Literal[True] = True
    apparmor_userns_restriction: Literal[1] = 1
    apparmor: LinuxAppArmorAuthorityV2
    landlock_abi: Annotated[int, Field(ge=3, le=6)]
    cgroup_v2: Literal[True] = True
    delegated_cgroup_available: bool


class LinuxHostAuthorityV3(ContractV2):
    """Exact host authority with distinct observed and enforced Landlock ABIs."""

    schema_version: Literal[3] = 3  # type: ignore[assignment]
    os_id: Literal["ubuntu"] = "ubuntu"
    os_version_id: Literal["24.04"] = "24.04"
    architecture: Literal["x86_64"] = "x86_64"
    os_release_sha256: Digest
    kernel_release: Annotated[str, Field(min_length=1, max_length=256)]
    kernel_version_sha256: Digest
    user_namespace_clone_enabled: Literal[True] = True
    apparmor_userns_restriction_present: Literal[True] = True
    apparmor_userns_restriction: Literal[1] = 1
    apparmor: LinuxAppArmorAuthorityV2
    kernel_landlock_abi: Annotated[int, Field(ge=3)]
    enforced_landlock_abi: Annotated[int, Field(ge=3, le=6)]
    cgroup_v2: Literal[True] = True
    delegated_cgroup_available: bool

    @model_validator(mode="after")
    def exact_enforced_abi(self) -> LinuxHostAuthorityV3:
        if self.enforced_landlock_abi != enforced_landlock_abi(self.kernel_landlock_abi):
            raise ValueError("Enforced Landlock ABI differs from the reviewed policy ceiling")
        return self

    @property
    def landlock_abi(self) -> int:
        """Compatibility accessor for the shared V2 profile validator."""

        return self.enforced_landlock_abi


class LinuxRlimitsV1(Contract):
    """Per-process limits used by the metadata-only namespace probe."""

    cpu_seconds: Annotated[int, Field(ge=1, le=900)] = 60
    address_space_bytes: Annotated[int, Field(ge=128 * 1024**2)] = 2 * 1024**3
    file_size_bytes: Annotated[int, Field(ge=1024**2)] = 64 * 1024**2
    open_files: Annotated[int, Field(ge=16, le=1024)] = 128
    processes: Annotated[int, Field(ge=2, le=128)] = 32
    core_bytes: Literal[0] = 0


class LinuxMountAuthorityV1(Contract):
    """One explicit mount inside the private native root."""

    target: Annotated[str, Field(min_length=1, max_length=4096, pattern=r"^/[^\x00\r\n]*$")]
    kind: Literal[
        "bundle_read_only",
        "state_read_write",
        "output_read_write",
        "broker_read_only",
        "tmpfs_home",
        "tmpfs_tmp",
        "proc",
        "dev_tmpfs",
    ]
    source_identity_sha256: Digest | None = None
    read_only: bool
    nosuid: Literal[True] = True
    nodev: bool
    noexec: bool

    @model_validator(mode="after")
    def source_is_bound_when_required(self) -> LinuxMountAuthorityV1:
        bind_kinds = {
            "bundle_read_only",
            "state_read_write",
            "output_read_write",
            "broker_read_only",
        }
        if (self.kind in bind_kinds) != (self.source_identity_sha256 is not None):
            raise ValueError("Bind mounts require exactly one source identity")
        if self.kind.endswith("read_only") and not self.read_only:
            raise ValueError("Read-only mount kind cannot be writable")
        return self


class LinuxBrokerExpectationV1(Contract):
    """Exact fixed-destination broker contract visible to the isolated child."""

    transport: Literal["af_unix_stream"] = "af_unix_stream"
    socket_target: Literal["/run/devfabric/ollama.sock"] = "/run/devfabric/ollama.sock"
    destination_host: Literal["127.0.0.1"] = "127.0.0.1"
    destination_port: Literal[11434] = 11434
    expected_model: Literal["qwen2.5:14b-instruct"] = "qwen2.5:14b-instruct"
    allowed_paths: tuple[
        Literal["/api/version", "/api/tags", "/api/show"],
        Literal["/api/version", "/api/tags", "/api/show"],
        Literal["/api/version", "/api/tags", "/api/show"],
    ] = ("/api/show", "/api/tags", "/api/version")
    generation_path_allowed: Literal[False] = False
    exact_peer_pid_required: Literal[True] = True
    exact_peer_start_time_required: Literal[True] = True
    exact_peer_uid_required: Literal[True] = True
    broker_host_pid: Annotated[int, Field(ge=1)]
    broker_host_start_time_ticks: Annotated[int, Field(ge=1)]
    broker_host_uid: Annotated[int, Field(ge=1)]
    broker_module_sha256: Digest
    child_observed_broker_pid: Literal[0] = 0
    child_observed_broker_uid: Literal[1000] = 1000
    max_request_bytes: Annotated[int, Field(ge=1024, le=1024**2)] = 64 * 1024
    max_response_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**2)] = 4 * 1024**2

    @field_validator("allowed_paths")
    @classmethod
    def exact_sorted_metadata_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        expected = ("/api/show", "/api/tags", "/api/version")
        if value != expected:
            raise ValueError("Linux broker must expose exactly the sorted metadata endpoints")
        return value


class LinuxSyntheticUpstreamAuthorityV1(Contract):
    """Retained host listener used only by the synthetic mechanics fixture."""

    schema_version: Literal[1] = 1
    authority_kind: Literal["linux_synthetic_ollama_upstream_v1"] = (
        "linux_synthetic_ollama_upstream_v1"
    )
    host: Literal["127.0.0.1"] = "127.0.0.1"
    port: Annotated[int, Field(ge=1, le=65535)]
    socket_inode: Annotated[int, Field(ge=1)]
    owner_pid: Annotated[int, Field(ge=1)]
    owner_start_time_ticks: Annotated[int, Field(ge=1)]
    owner_uid: Annotated[int, Field(ge=0)]


class LinuxIsolationProfilePayloadV1(Contract):
    schema_version: Literal[1] = 1
    profile_kind: Literal["linux_native_isolation_v1"] = "linux_native_isolation_v1"
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    native_bundle_id: Digest
    bundle_manifest_sha256: Digest
    bootstrap_python: LinuxFileAuthorityV1
    probe_sha256: Digest
    child_probe_sha256: Digest
    host: LinuxHostAuthorityV1
    unshare: LinuxToolAuthorityV1
    mount: LinuxToolAuthorityV1
    source_directories: Annotated[tuple[LinuxDirectoryAuthorityV1, ...], Field(min_length=5)]
    mounts: Annotated[tuple[LinuxMountAuthorityV1, ...], Field(min_length=8)]
    broker: LinuxBrokerExpectationV1
    sandbox_uid: Literal[1000] = 1000
    sandbox_gid: Literal[1000] = 1000
    namespace_kinds: tuple[
        Literal["user", "mount", "pid", "network"],
        Literal["user", "mount", "pid", "network"],
        Literal["user", "mount", "pid", "network"],
        Literal["user", "mount", "pid", "network"],
    ] = ("mount", "network", "pid", "user")
    mount_propagation: Literal["private"] = "private"
    private_root_required: Literal[True] = True
    fresh_proc_required: Literal[True] = True
    no_new_privs_required: Literal[True] = True
    zero_capability_sets_required: Literal[True] = True
    minimum_landlock_abi: Literal[3] = 3
    maximum_landlock_abi: Literal[6] = 6
    landlock_handled_access: Annotated[int, Field(gt=0)]
    seccomp_filter_qualified: Literal[False] = False
    delegated_cgroup_required_for_readiness: Literal[True] = True
    rlimits: LinuxRlimitsV1 = Field(default_factory=LinuxRlimitsV1)

    @model_validator(mode="after")
    def closed_profile(self) -> LinuxIsolationProfilePayloadV1:
        if self.unshare.name != "unshare" or self.unshare.locator != "/usr/bin/unshare":
            raise ValueError("Profile requires exact /usr/bin/unshare authority")
        if self.mount.name != "mount" or self.mount.locator != "/usr/bin/mount":
            raise ValueError("Profile requires exact /usr/bin/mount authority")
        if self.namespace_kinds != ("mount", "network", "pid", "user"):
            raise ValueError("Linux namespace set must be exact and canonical")
        source_roles = tuple(item.role for item in self.source_directories)
        if source_roles != ("broker", "fixture", "output", "scratch_root", "state"):
            raise ValueError("Isolation source directories must be exact and canonical")
        source_hashes = {
            item.role: digest(canonical(item.model_dump(mode="json")))
            for item in self.source_directories
        }
        mount_source_roles: dict[
            Literal[
                "bundle_read_only",
                "state_read_write",
                "output_read_write",
                "broker_read_only",
                "tmpfs_home",
                "tmpfs_tmp",
                "proc",
                "dev_tmpfs",
            ],
            Literal["fixture", "state", "output", "broker", "scratch_root"] | None,
        ] = {
            "bundle_read_only": "fixture",
            "output_read_write": "output",
            "broker_read_only": "broker",
            "state_read_write": "state",
            "tmpfs_home": None,
            "tmpfs_tmp": None,
            "proc": None,
            "dev_tmpfs": None,
        }
        for item in self.mounts:
            role = mount_source_roles.get(item.kind)
            if role is not None and item.source_identity_sha256 != source_hashes[role]:
                raise ValueError("Mount source identity differs from directory authority")
        mount_targets = tuple(item.target for item in self.mounts)
        if mount_targets != tuple(sorted(set(mount_targets))):
            raise ValueError("Mount targets must be sorted and unique")
        required_kinds = {
            "bundle_read_only",
            "state_read_write",
            "output_read_write",
            "broker_read_only",
            "tmpfs_home",
            "tmpfs_tmp",
            "proc",
            "dev_tmpfs",
        }
        if not required_kinds.issubset({item.kind for item in self.mounts}):
            raise ValueError("Linux private root is missing a required mount kind")
        if self.landlock_handled_access != landlock_handled_access(self.host.landlock_abi):
            raise ValueError("Landlock access mask differs from the exact reviewed host ABI")
        return self


class LinuxIsolationProfilePayloadV2(LinuxIsolationProfilePayloadV1):
    """Forward-only profile for the exact private AppArmor launcher."""

    schema_version: Literal[2] = 2  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v2"] = "linux_native_isolation_v2"  # type: ignore[assignment]
    host: LinuxHostAuthorityV2  # type: ignore[assignment]
    system_unshare: LinuxToolAuthorityV1
    unshare: LinuxToolAuthorityV1

    @model_validator(mode="after")
    def closed_profile(self) -> LinuxIsolationProfilePayloadV2:
        if (
            self.system_unshare.name != "unshare"
            or self.system_unshare.locator != LINUX_SYSTEM_UNSHARE
            or self.unshare.name != "unshare"
            or self.unshare.locator != LINUX_PRIVATE_UNSHARE
        ):
            raise ValueError("Profile requires exact system and private unshare authorities")
        if (
            self.system_unshare.sha256 != self.unshare.sha256
            or self.system_unshare.size != self.unshare.size
            or self.system_unshare.version_output_sha256 != self.unshare.version_output_sha256
            or self.system_unshare.native_identity == self.unshare.native_identity
        ):
            raise ValueError("Private unshare does not match the reviewed system binary")
        if self.mount.name != "mount" or self.mount.locator != "/usr/bin/mount":
            raise ValueError("Profile requires exact /usr/bin/mount authority")
        if self.namespace_kinds != ("mount", "network", "pid", "user"):
            raise ValueError("Linux namespace set must be exact and canonical")
        source_roles = tuple(item.role for item in self.source_directories)
        if source_roles != ("broker", "fixture", "output", "scratch_root", "state"):
            raise ValueError("Isolation source directories must be exact and canonical")
        source_hashes: dict[str, str] = {
            item.role: digest(canonical(item.model_dump(mode="json")))
            for item in self.source_directories
        }
        mount_source_roles = {
            "bundle_read_only": "fixture",
            "output_read_write": "output",
            "broker_read_only": "broker",
            "state_read_write": "state",
        }
        for item in self.mounts:
            role = mount_source_roles.get(item.kind)
            if role is not None and item.source_identity_sha256 != source_hashes[role]:
                raise ValueError("Mount source identity differs from directory authority")
        mount_targets = tuple(item.target for item in self.mounts)
        if mount_targets != tuple(sorted(set(mount_targets))):
            raise ValueError("Mount targets must be sorted and unique")
        required_kinds = {
            "bundle_read_only",
            "state_read_write",
            "output_read_write",
            "broker_read_only",
            "tmpfs_home",
            "tmpfs_tmp",
            "proc",
            "dev_tmpfs",
        }
        if not required_kinds.issubset({item.kind for item in self.mounts}):
            raise ValueError("Linux private root is missing a required mount kind")
        if self.landlock_handled_access != landlock_handled_access(self.host.landlock_abi):
            raise ValueError("Landlock access mask differs from the exact reviewed host ABI")
        return self


class LinuxIsolationProfilePayloadV3(LinuxIsolationProfilePayloadV2):
    """Forward-only profile that records kernel and reviewed policy ABIs separately."""

    schema_version: Literal[3] = 3  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v3"] = "linux_native_isolation_v3"  # type: ignore[assignment]
    host: LinuxHostAuthorityV3  # type: ignore[assignment]

    @model_validator(mode="after")
    def exact_v3_landlock_authority(self) -> LinuxIsolationProfilePayloadV3:
        expected = enforced_landlock_abi(self.host.kernel_landlock_abi)
        if self.host.enforced_landlock_abi != expected:
            raise ValueError("Profile Landlock policy ABI differs from the kernel observation")
        if self.landlock_handled_access != landlock_handled_access(expected):
            raise ValueError("Landlock access mask differs from the reviewed enforced ABI")
        return self


class LinuxIsolationProfilePayloadV4(LinuxIsolationProfilePayloadV3):
    """Forward-only profile binding the complete mount executable mode."""

    schema_version: Literal[4] = 4  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v4"] = "linux_native_isolation_v4"  # type: ignore[assignment]
    mount: LinuxToolAuthorityV4  # type: ignore[assignment]

    @model_validator(mode="after")
    def exact_v4_mount_authority(self) -> LinuxIsolationProfilePayloadV4:
        if self.mount.name != "mount" or self.mount.locator != "/usr/bin/mount":
            raise ValueError("V4 profile requires exact /usr/bin/mount authority")
        return self


class LinuxIsolationProfilePayloadV5(LinuxIsolationProfilePayloadV4):
    """Forward-only profile binding the retained synthetic upstream listener."""

    schema_version: Literal[5] = 5  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v5"] = "linux_native_isolation_v5"  # type: ignore[assignment]
    synthetic_upstream: LinuxSyntheticUpstreamAuthorityV1

    @model_validator(mode="after")
    def exact_v5_synthetic_upstream_authority(self) -> LinuxIsolationProfilePayloadV5:
        owner = (
            self.synthetic_upstream.owner_pid,
            self.synthetic_upstream.owner_start_time_ticks,
            self.synthetic_upstream.owner_uid,
        )
        broker_host = (
            self.broker.broker_host_pid,
            self.broker.broker_host_start_time_ticks,
            self.broker.broker_host_uid,
        )
        if owner != broker_host:
            raise ValueError("Synthetic upstream owner differs from broker host authority")
        if self.synthetic_upstream.port == self.broker.destination_port:
            raise ValueError("Synthetic upstream must not use the production Ollama port")
        return self


class LinuxIsolationProfilePayloadV6(LinuxIsolationProfilePayloadV5):
    """Forward-only profile binding the stdlib-only isolated child bootstrap."""

    schema_version: Literal[6] = 6  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v6"] = "linux_native_isolation_v6"  # type: ignore[assignment]
    child_python_flags: tuple[Literal["-I"], Literal["-B"]] = ("-I", "-B")
    child_stdlib_only: Literal[True] = True


class LinuxNamespaceOwnerProjectionExpectationV1(Contract):
    host_owner_uid: Literal[0] = 0
    host_owner_gid: Literal[0] = 0
    overflow_uid: Annotated[int, Field(ge=1, le=2**32 - 1)]
    overflow_gid: Annotated[int, Field(ge=1, le=2**32 - 1)]


class LinuxToolVersionEnvironmentV1(Contract):
    """Exact non-sensitive environment for a tool identity observation."""

    lang: Literal["C.UTF-8"] = "C.UTF-8"
    lc_all: Literal["C.UTF-8"] = "C.UTF-8"
    path: Literal["/usr/bin:/bin"] = "/usr/bin:/bin"


class LinuxCgroupLimitsV1(Contract):
    memory_max: Literal["2147483648"] = LINUX_CGROUP_MEMORY_MAX
    pids_max: Literal["128"] = LINUX_CGROUP_PIDS_MAX
    cpu_max: Literal["200000 100000"] = LINUX_CGROUP_CPU_MAX


class LinuxCgroupBoundaryAuthorityV1(Contract):
    """Host-owned authority for one environment-scoped transient service cgroup."""

    unit_name: Annotated[
        str,
        Field(pattern=r"^devfabric-linux-isolation-[a-f0-9]{32}\.service$"),
    ]
    control_group: Annotated[
        str,
        Field(pattern=r"^/system\.slice/devfabric-linux-isolation-[a-f0-9]{32}\.service$"),
    ]
    cgroup_root: Literal["/sys/fs/cgroup"] = LINUX_CGROUP_ROOT
    service_uid: Annotated[int, Field(ge=1)]
    service_gid: Annotated[int, Field(ge=1)]
    systemd_run: LinuxSystemdToolAuthorityV1
    systemctl: LinuxSystemdToolAuthorityV1
    version_environment: LinuxToolVersionEnvironmentV1 = LinuxToolVersionEnvironmentV1()
    limits: LinuxCgroupLimitsV1 = LinuxCgroupLimitsV1()

    @model_validator(mode="after")
    def exact_unit_and_tools(self) -> LinuxCgroupBoundaryAuthorityV1:
        if self.control_group != f"/system.slice/{self.unit_name}":
            raise ValueError("Linux cgroup unit and control-group path differ")
        if (
            self.systemd_run.name != "systemd-run"
            or self.systemd_run.locator != LINUX_SYSTEMD_RUN
            or self.systemctl.name != "systemctl"
            or self.systemctl.locator != LINUX_SYSTEMCTL
        ):
            raise ValueError("Linux cgroup systemd tool authority differs")
        return self


class LinuxCgroupSetupStatePayloadV1(Contract):
    schema_version: Literal[1] = 1
    state_kind: Literal["linux_cgroup_setup_state_v1"] = "linux_cgroup_setup_state_v1"
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    boundary: LinuxCgroupBoundaryAuthorityV1


class LinuxCgroupSetupStateV1(Contract):
    linux_cgroup_setup_state_id: Digest
    payload: LinuxCgroupSetupStatePayloadV1

    @classmethod
    def create(cls, payload: LinuxCgroupSetupStatePayloadV1) -> LinuxCgroupSetupStateV1:
        return cls(
            linux_cgroup_setup_state_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxCgroupSetupStateV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_cgroup_setup_state_id != expected:
            raise ValueError("Linux cgroup setup state hash mismatch")
        return self


class LinuxIsolationProfilePayloadV7(LinuxIsolationProfilePayloadV6):
    """Forward-only profile binding namespace ownership projection and registration."""

    schema_version: Literal[7] = 7  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v7"] = "linux_native_isolation_v7"  # type: ignore[assignment]
    child_registration_protocol: Literal["linux_child_registration_v2"] = (
        "linux_child_registration_v2"
    )
    mount_owner_projection: LinuxNamespaceOwnerProjectionExpectationV1


class LinuxIsolationProfilePayloadV8(LinuxIsolationProfilePayloadV7):
    """Forward-only profile binding staged mount authority observation."""

    schema_version: Literal[8] = 8  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v8"] = "linux_native_isolation_v8"  # type: ignore[assignment]
    child_registration_protocol: Literal["linux_child_registration_v3"] = (
        "linux_child_registration_v3"  # type: ignore[assignment]
    )
    child_bootstrap_failure_protocol: Literal["linux_child_bootstrap_failure_v2"] = (
        "linux_child_bootstrap_failure_v2"
    )
    mount_authority_protocol: Literal["linux_mount_authority_observation_v1"] = (
        "linux_mount_authority_observation_v1"
    )
    mount_version_environment: LinuxToolVersionEnvironmentV1 = LinuxToolVersionEnvironmentV1()


class LinuxIsolationProfilePayloadV9(LinuxIsolationProfilePayloadV8):
    """Forward-only profile binding typed native-identity mismatch evidence."""

    schema_version: Literal[9] = 9  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v9"] = "linux_native_isolation_v9"  # type: ignore[assignment]
    child_bootstrap_failure_protocol: Literal["linux_child_bootstrap_failure_v3"] = (
        "linux_child_bootstrap_failure_v3"  # type: ignore[assignment]
    )


class LinuxIsolationProfilePayloadV10(LinuxIsolationProfilePayloadV9):
    """Forward-only profile binding typed post-registration child failures."""

    schema_version: Literal[10] = 10  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v10"] = "linux_native_isolation_v10"  # type: ignore[assignment]
    child_runtime_failure_protocol: Literal["linux_child_runtime_failure_v1"] = (
        "linux_child_runtime_failure_v1"
    )


class LinuxIsolationProfilePayloadV11(LinuxIsolationProfilePayloadV10):
    """Forward-only profile binding bounded broker failure diagnostics."""

    schema_version: Literal[11] = 11  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v11"] = "linux_native_isolation_v11"  # type: ignore[assignment]
    child_runtime_failure_protocol: Literal["linux_child_runtime_failure_v2"] = (
        "linux_child_runtime_failure_v2"  # type: ignore[assignment]
    )
    host_broker_failure_protocol: Literal["linux_host_broker_failure_v1"] = (
        "linux_host_broker_failure_v1"
    )


class LinuxPackageAuthorityV1(Contract):
    """Exact package authority consumed by native Linux isolation V12."""

    schema_version: Literal[1] = 1
    predecessor_bundle_id: Literal[
        "27dd89b9a82879778a9d31115c43ebc12306087b54fe84b414f71b234aff6bf2"
    ] = "27dd89b9a82879778a9d31115c43ebc12306087b54fe84b414f71b234aff6bf2"
    predecessor_archive_id: Literal[
        "c1dc8bd2181a334d50219e92723a605f1473f887c54d6e9966b4f604f7efe419"
    ] = "c1dc8bd2181a334d50219e92723a605f1473f887c54d6e9966b4f604f7efe419"
    predecessor_archive_sha256: Literal[
        "a03b097115cd003797766c0816de4af631413925aa290d55557daff4a6439f43"
    ] = "a03b097115cd003797766c0816de4af631413925aa290d55557daff4a6439f43"
    predecessor_build_id: Literal["linux-build-010"] = "linux-build-010"
    predecessor_build_run_id: Literal[38330846665] = 38330846665
    predecessor_bundle_run_id: Literal[38336960375] = 38336960375
    bundle_workflow_path: Literal[".github/workflows/linux-native-bundle.yml"] = (
        ".github/workflows/linux-native-bundle.yml"
    )
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    build_id: Literal["linux-build-011"] = "linux-build-011"
    build_run_id: Annotated[int, Field(ge=1)]
    build_run_attempt: Annotated[int, Field(ge=1)]
    bundle_run_id: Annotated[int, Field(ge=1)]
    bundle_run_attempt: Annotated[int, Field(ge=1)]
    archive_id: Digest
    archive_sha256: Digest
    archive_size: Annotated[int, Field(ge=1, le=2 * 1024 * 1024 * 1024)]
    bundle_id: Digest
    bundle_manifest_sha256: Digest
    build_receipt_sha256: Digest
    build_inventory_sha256: Digest
    linux_native_codex_build_id: Digest
    codex_sha256: Digest
    code_mode_host_sha256: Digest
    python_runtime_id: Digest
    python_executable_sha256: Digest
    child_module_path: Literal[
        "python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"
    ] = "python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"
    child_module_sha256: Digest
    child_module_name: Literal["devhub.linux_native_isolation_child"] = (
        "devhub.linux_native_isolation_child"
    )


class LinuxIsolationProfilePayloadV12(LinuxIsolationProfilePayloadV11):
    """Package-bound profile using only the exact V5 native release."""

    schema_version: Literal[12] = 12  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v12"] = "linux_native_isolation_v12"  # type: ignore[assignment]
    child_module_argv: tuple[
        Literal["-I"],
        Literal["-B"],
        Literal["-m"],
        Literal["devhub.linux_native_isolation_child"],
    ] = ("-I", "-B", "-m", "devhub.linux_native_isolation_child")
    source_directories: Annotated[
        tuple[LinuxDirectoryAuthorityV1 | LinuxBundleDirectoryAuthorityV1, ...],
        Field(min_length=5),
    ]
    package: LinuxPackageAuthorityV1

    @model_validator(mode="after")
    def exact_package_join(self) -> LinuxIsolationProfilePayloadV12:
        if (
            self.package.implementation_commit != self.implementation_commit
            or self.package.bundle_id != self.native_bundle_id
            or self.package.bundle_manifest_sha256 != self.bundle_manifest_sha256
            or self.package.python_executable_sha256 != self.bootstrap_python.sha256
            or self.package.child_module_sha256 != self.child_probe_sha256
        ):
            raise ValueError("Linux isolation package authority differs from the profile")
        fixture = next(item for item in self.source_directories if item.role == "fixture")
        if not isinstance(fixture, LinuxBundleDirectoryAuthorityV1):
            raise ValueError("Linux isolation V12 fixture is not the exact published bundle root")
        return self


class LinuxPackageAuthorityV2(Contract):
    """Exact Build-012/Bundle V6 authority consumed by isolation V13."""

    schema_version: Literal[2] = 2  # type: ignore[assignment]
    bundle_schema_version: Literal[6] = 6
    archive_schema_version: Literal[6] = 6
    bundle_workflow_path: Literal[".github/workflows/linux-native-bundle.yml"] = (
        ".github/workflows/linux-native-bundle.yml"
    )
    package_implementation_commit: Literal["c272ed6169a718204f2830a4aa34a5548a650652"] = (
        "c272ed6169a718204f2830a4aa34a5548a650652"
    )
    build_id: Literal["linux-build-012"] = "linux-build-012"
    build_run_id: Literal[38354927618] = 38354927618
    build_run_attempt: Literal[1] = 1
    bundle_run_id: Literal[38359494446] = 38359494446
    bundle_run_attempt: Literal[1] = 1
    archive_id: Literal["412276753153a6d534ab1f2a0dfe1187c63dbb2339f9c28762f9a4e4667cbd44"] = (
        "412276753153a6d534ab1f2a0dfe1187c63dbb2339f9c28762f9a4e4667cbd44"
    )
    archive_sha256: Literal["9b071ce938b4baf716dff1904d4d51fc49f8ab2bd3d5ee834b5bc849dbe576b6"] = (
        "9b071ce938b4baf716dff1904d4d51fc49f8ab2bd3d5ee834b5bc849dbe576b6"
    )
    archive_size: Literal[517499293] = 517499293
    bundle_id: Literal["db39cc867dc2e89419b44d774980324c055d258a383e895bf8eae40ca991290c"] = (
        "db39cc867dc2e89419b44d774980324c055d258a383e895bf8eae40ca991290c"
    )
    bundle_manifest_sha256: Literal[
        "c2b45924e971972513f38b92942de01b13cb4150ef99e66a79edabc852e4fa74"
    ] = "c2b45924e971972513f38b92942de01b13cb4150ef99e66a79edabc852e4fa74"
    build_receipt_sha256: Literal[
        "17a5d5268c0f7fb01dff2c0de464409244c2a530ae8c2f4c13032906c8110e19"
    ] = "17a5d5268c0f7fb01dff2c0de464409244c2a530ae8c2f4c13032906c8110e19"
    build_inventory_sha256: Literal[
        "09f75ca01f614e53a502e593bf10e2b3630bfea80d7f80472fca2d581a73b899"
    ] = "09f75ca01f614e53a502e593bf10e2b3630bfea80d7f80472fca2d581a73b899"
    linux_native_codex_build_id: Literal[
        "f186f5b54f591bac3d86d67317769ee99df451b81c095590fcfc57c5990d94bb"
    ] = "f186f5b54f591bac3d86d67317769ee99df451b81c095590fcfc57c5990d94bb"
    codex_sha256: Literal["e9e67728a0483232ae22572bda0c1c8e688bd78d01ab1c065b1cd5207652c2d9"] = (
        "e9e67728a0483232ae22572bda0c1c8e688bd78d01ab1c065b1cd5207652c2d9"
    )
    code_mode_host_sha256: Literal[
        "d770fa924c6aaff3398f77dff5eef7a68399686727875a439826b07a73930555"
    ] = "d770fa924c6aaff3398f77dff5eef7a68399686727875a439826b07a73930555"
    python_runtime_id: Literal[
        "a984027af64696e563f483f7a76df4b61620d6c86c152ef6624504847607990d"
    ] = "a984027af64696e563f483f7a76df4b61620d6c86c152ef6624504847607990d"
    python_executable_sha256: Literal[
        "96b570567fe6afa8e7fe2278b1302be7f5320d8afa5f3ccd8d627796039499b2"
    ] = "96b570567fe6afa8e7fe2278b1302be7f5320d8afa5f3ccd8d627796039499b2"
    child_module_path: Literal[
        "python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"
    ] = "python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"
    child_module_sha256: Literal[
        "9f6894edb23a3938ec990abaa50636867ee9aaea00bf0a6f736567dd8d6bd11c"
    ] = "9f6894edb23a3938ec990abaa50636867ee9aaea00bf0a6f736567dd8d6bd11c"
    child_module_name: Literal["devhub.linux_native_isolation_child"] = (
        "devhub.linux_native_isolation_child"
    )


class LinuxPackageAuthorityV3(Contract):
    """Exact Bundle V7 authority with current Python and retained Build-012 binaries."""

    schema_version: Literal[3] = 3  # type: ignore[assignment]
    bundle_schema_version: Literal[7] = 7
    archive_schema_version: Literal[7] = 7
    bundle_workflow_path: Literal[".github/workflows/linux-native-bundle.yml"] = (
        ".github/workflows/linux-native-bundle.yml"
    )
    package_implementation_commit: Literal["0c39acf9afca1106985a1c35fca846c86d5789c7"] = (
        "0c39acf9afca1106985a1c35fca846c86d5789c7"
    )
    retained_codex_implementation_commit: Literal["c272ed6169a718204f2830a4aa34a5548a650652"] = (
        "c272ed6169a718204f2830a4aa34a5548a650652"
    )
    build_id: Literal["linux-build-012"] = "linux-build-012"
    build_run_id: Literal[38354927618] = 38354927618
    build_run_attempt: Literal[1] = 1
    bundle_run_id: Literal[38374815599] = 38374815599
    bundle_run_attempt: Literal[1] = 1
    archive_id: Literal["8de888cacb2725cd760ebf4deb6d5ee0f5723f6d16f3accca6b8ca716b123e2a"] = (
        "8de888cacb2725cd760ebf4deb6d5ee0f5723f6d16f3accca6b8ca716b123e2a"
    )
    archive_sha256: Literal["9e06fabd15871cd44f325c84424def80c714f6e21d83905b7651b0551e13bf63"] = (
        "9e06fabd15871cd44f325c84424def80c714f6e21d83905b7651b0551e13bf63"
    )
    archive_size: Literal[517512542] = 517512542
    bundle_id: Literal["7761d0f34d03983aaea1349ac6ac3b5b7a0720c8df93b66037db71ec1cbef176"] = (
        "7761d0f34d03983aaea1349ac6ac3b5b7a0720c8df93b66037db71ec1cbef176"
    )
    bundle_manifest_sha256: Literal[
        "cc67d1d6e5bb5ec1a76bc2a517dd6f6d43b424afe4ae189ca66416c233dbcb5c"
    ] = "cc67d1d6e5bb5ec1a76bc2a517dd6f6d43b424afe4ae189ca66416c233dbcb5c"
    build_receipt_sha256: Literal[
        "17a5d5268c0f7fb01dff2c0de464409244c2a530ae8c2f4c13032906c8110e19"
    ] = "17a5d5268c0f7fb01dff2c0de464409244c2a530ae8c2f4c13032906c8110e19"
    build_inventory_sha256: Literal[
        "09f75ca01f614e53a502e593bf10e2b3630bfea80d7f80472fca2d581a73b899"
    ] = "09f75ca01f614e53a502e593bf10e2b3630bfea80d7f80472fca2d581a73b899"
    linux_native_codex_build_id: Literal[
        "f186f5b54f591bac3d86d67317769ee99df451b81c095590fcfc57c5990d94bb"
    ] = "f186f5b54f591bac3d86d67317769ee99df451b81c095590fcfc57c5990d94bb"
    codex_sha256: Literal["e9e67728a0483232ae22572bda0c1c8e688bd78d01ab1c065b1cd5207652c2d9"] = (
        "e9e67728a0483232ae22572bda0c1c8e688bd78d01ab1c065b1cd5207652c2d9"
    )
    code_mode_host_sha256: Literal[
        "d770fa924c6aaff3398f77dff5eef7a68399686727875a439826b07a73930555"
    ] = "d770fa924c6aaff3398f77dff5eef7a68399686727875a439826b07a73930555"
    python_runtime_id: Literal[
        "59a13ae87cdbd93afccae35d89f75b72e565208e5f432cdd40deb5707b6e24f9"
    ] = "59a13ae87cdbd93afccae35d89f75b72e565208e5f432cdd40deb5707b6e24f9"
    python_executable_sha256: Literal[
        "96b570567fe6afa8e7fe2278b1302be7f5320d8afa5f3ccd8d627796039499b2"
    ] = "96b570567fe6afa8e7fe2278b1302be7f5320d8afa5f3ccd8d627796039499b2"
    child_module_path: Literal[
        "python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"
    ] = "python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"
    child_module_sha256: Literal[
        "ede095e72a626c131e96fee6e98944ec7ea42e4fd366544960c3067d9547f75c"
    ] = "ede095e72a626c131e96fee6e98944ec7ea42e4fd366544960c3067d9547f75c"
    child_module_name: Literal["devhub.linux_native_isolation_child"] = (
        "devhub.linux_native_isolation_child"
    )


class LinuxPackageAuthorityV4(Contract):
    """Exact Bundle V8 authority with the corrected packaged child contract."""

    schema_version: Literal[4] = 4  # type: ignore[assignment]
    bundle_schema_version: Literal[8] = 8
    archive_schema_version: Literal[8] = 8
    bundle_workflow_path: Literal[".github/workflows/linux-native-bundle.yml"] = (
        ".github/workflows/linux-native-bundle.yml"
    )
    package_implementation_commit: Literal["cffb59052eb7f0c026a6fffb056b301ef3f90458"] = (
        "cffb59052eb7f0c026a6fffb056b301ef3f90458"
    )
    retained_codex_implementation_commit: Literal["c272ed6169a718204f2830a4aa34a5548a650652"] = (
        "c272ed6169a718204f2830a4aa34a5548a650652"
    )
    build_id: Literal["linux-build-012"] = "linux-build-012"
    build_run_id: Literal[38354927618] = 38354927618
    build_run_attempt: Literal[1] = 1
    bundle_run_id: Literal[38387100992] = 38387100992
    bundle_run_attempt: Literal[1] = 1
    archive_id: Literal["4955e9cd2b0d58a1fb5a5a6d2eff57f785dcddca8df0b3a6c4cd9cb1c5ce3e40"] = (
        "4955e9cd2b0d58a1fb5a5a6d2eff57f785dcddca8df0b3a6c4cd9cb1c5ce3e40"
    )
    archive_sha256: Literal["a234a484c18ffaadb6269ac41015b85f6b734359abd9d4cec2a09f2c964a4ea5"] = (
        "a234a484c18ffaadb6269ac41015b85f6b734359abd9d4cec2a09f2c964a4ea5"
    )
    archive_size: Literal[517509002] = 517509002
    bundle_id: Literal["ccbe5b4f86421e95b77293c04969c66b23e491d6713f015d6b5c6e65ecb7c474"] = (
        "ccbe5b4f86421e95b77293c04969c66b23e491d6713f015d6b5c6e65ecb7c474"
    )
    bundle_manifest_sha256: Literal[
        "50f8694edd5c347962266c72b0e3575c716a3d7c7c0b704c2db92debf718605e"
    ] = "50f8694edd5c347962266c72b0e3575c716a3d7c7c0b704c2db92debf718605e"
    build_receipt_sha256: Literal[
        "17a5d5268c0f7fb01dff2c0de464409244c2a530ae8c2f4c13032906c8110e19"
    ] = "17a5d5268c0f7fb01dff2c0de464409244c2a530ae8c2f4c13032906c8110e19"
    build_inventory_sha256: Literal[
        "09f75ca01f614e53a502e593bf10e2b3630bfea80d7f80472fca2d581a73b899"
    ] = "09f75ca01f614e53a502e593bf10e2b3630bfea80d7f80472fca2d581a73b899"
    linux_native_codex_build_id: Literal[
        "f186f5b54f591bac3d86d67317769ee99df451b81c095590fcfc57c5990d94bb"
    ] = "f186f5b54f591bac3d86d67317769ee99df451b81c095590fcfc57c5990d94bb"
    codex_sha256: Literal["e9e67728a0483232ae22572bda0c1c8e688bd78d01ab1c065b1cd5207652c2d9"] = (
        "e9e67728a0483232ae22572bda0c1c8e688bd78d01ab1c065b1cd5207652c2d9"
    )
    code_mode_host_sha256: Literal[
        "d770fa924c6aaff3398f77dff5eef7a68399686727875a439826b07a73930555"
    ] = "d770fa924c6aaff3398f77dff5eef7a68399686727875a439826b07a73930555"
    python_runtime_id: Literal[
        "f92225f8f8e72f11cc2db07f277123ad46bf0a53ea5857edd97c6847105d5689"
    ] = "f92225f8f8e72f11cc2db07f277123ad46bf0a53ea5857edd97c6847105d5689"
    python_executable_sha256: Literal[
        "96b570567fe6afa8e7fe2278b1302be7f5320d8afa5f3ccd8d627796039499b2"
    ] = "96b570567fe6afa8e7fe2278b1302be7f5320d8afa5f3ccd8d627796039499b2"
    child_module_path: Literal[
        "python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"
    ] = "python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"
    child_module_sha256: Literal[
        "5f4499d613904359a5a972fa71fb1df79a62708aa43a1b7e3a9277102fc82793"
    ] = "5f4499d613904359a5a972fa71fb1df79a62708aa43a1b7e3a9277102fc82793"
    child_module_name: Literal["devhub.linux_native_isolation_child"] = (
        "devhub.linux_native_isolation_child"
    )


class LinuxPackageAuthorityV5(Contract):
    """Exact Bundle V11 authority with loader-bound packaged subprocesses."""

    schema_version: Literal[5] = 5  # type: ignore[assignment]
    bundle_schema_version: Literal[11] = 11
    archive_schema_version: Literal[11] = 11
    bundle_workflow_path: Literal[".github/workflows/linux-native-bundle.yml"] = (
        ".github/workflows/linux-native-bundle.yml"
    )
    package_implementation_commit: Literal["5d3942f103180dd3834a4c2096ded9149b13da64"] = (
        "5d3942f103180dd3834a4c2096ded9149b13da64"
    )
    retained_codex_implementation_commit: Literal["c272ed6169a718204f2830a4aa34a5548a650652"] = (
        "c272ed6169a718204f2830a4aa34a5548a650652"
    )
    build_id: Literal["linux-build-012"] = "linux-build-012"
    build_run_id: Literal[38354927618] = 38354927618
    build_run_attempt: Literal[1] = 1
    bundle_run_id: Literal[38426368741] = 38426368741
    bundle_run_attempt: Literal[1] = 1
    archive_id: Literal["22efb9172d5e72f6e6e88de6f38619294074955695eae642dd0cea744443f331"] = (
        "22efb9172d5e72f6e6e88de6f38619294074955695eae642dd0cea744443f331"
    )
    archive_sha256: Literal["c20bd3b099d7b745ea8880ab456ab431b89c00f7360c42bfc519638e848db033"] = (
        "c20bd3b099d7b745ea8880ab456ab431b89c00f7360c42bfc519638e848db033"
    )
    archive_size: Literal[538818995] = 538818995
    bundle_id: Literal["818b94f6cb922b0a233c8729a17fc12ddd11ad962c9a2cafaff8dfb1e1fc16cf"] = (
        "818b94f6cb922b0a233c8729a17fc12ddd11ad962c9a2cafaff8dfb1e1fc16cf"
    )
    bundle_manifest_sha256: Literal[
        "41644e752c211db85bdaccfec8d83833be915d4d7b504a3dc552322c4b165f63"
    ] = "41644e752c211db85bdaccfec8d83833be915d4d7b504a3dc552322c4b165f63"
    build_receipt_sha256: Literal[
        "17a5d5268c0f7fb01dff2c0de464409244c2a530ae8c2f4c13032906c8110e19"
    ] = "17a5d5268c0f7fb01dff2c0de464409244c2a530ae8c2f4c13032906c8110e19"
    build_inventory_sha256: Literal[
        "09f75ca01f614e53a502e593bf10e2b3630bfea80d7f80472fca2d581a73b899"
    ] = "09f75ca01f614e53a502e593bf10e2b3630bfea80d7f80472fca2d581a73b899"
    linux_native_codex_build_id: Literal[
        "f186f5b54f591bac3d86d67317769ee99df451b81c095590fcfc57c5990d94bb"
    ] = "f186f5b54f591bac3d86d67317769ee99df451b81c095590fcfc57c5990d94bb"
    codex_sha256: Literal["e9e67728a0483232ae22572bda0c1c8e688bd78d01ab1c065b1cd5207652c2d9"] = (
        "e9e67728a0483232ae22572bda0c1c8e688bd78d01ab1c065b1cd5207652c2d9"
    )
    code_mode_host_sha256: Literal[
        "d770fa924c6aaff3398f77dff5eef7a68399686727875a439826b07a73930555"
    ] = "d770fa924c6aaff3398f77dff5eef7a68399686727875a439826b07a73930555"
    python_runtime_id: Literal[
        "f2049cc5fc926d54a613bf6861b40166ceac92ef8a8ef01eb360348962e8808a"
    ] = "f2049cc5fc926d54a613bf6861b40166ceac92ef8a8ef01eb360348962e8808a"
    python_executable_sha256: Literal[
        "29c00b75d5e7296e86eb563af4b9256125c9aed7afcbe6a56ac54a1b0eed32ca"
    ] = "29c00b75d5e7296e86eb563af4b9256125c9aed7afcbe6a56ac54a1b0eed32ca"
    child_module_path: Literal[
        "python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"
    ] = "python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"
    child_module_sha256: Literal[
        "4aaaaa7d982f2ce69aafbd58e79da6d732698b074a0fe3f69b7c1e3d2ecd6302"
    ] = "4aaaaa7d982f2ce69aafbd58e79da6d732698b074a0fe3f69b7c1e3d2ecd6302"
    child_module_name: Literal["devhub.linux_native_isolation_child"] = (
        "devhub.linux_native_isolation_child"
    )
    loader_path: Literal["runtime/loader/ld-linux-x86-64.so.2"] = (
        "runtime/loader/ld-linux-x86-64.so.2"
    )
    loader_sha256: Literal["c20a2dc8917c755f02b94049356320fe1f62ac7d9f8994731f807d9df39302da"] = (
        "c20a2dc8917c755f02b94049356320fe1f62ac7d9f8994731f807d9df39302da"
    )
    loader_size: Literal[236616] = 236616
    runtime_library_directory: Literal["runtime/lib"] = "runtime/lib"
    loader_arguments: tuple[Literal["--inhibit-cache"], Literal["--library-path"]] = (
        "--inhibit-cache",
        "--library-path",
    )
    runtime_library_authority_sha256: Literal[
        "8ed4575a3b564b05aef264540ec8617eed3daeecd61ea37ac4998d0135de3442"
    ] = "8ed4575a3b564b05aef264540ec8617eed3daeecd61ea37ac4998d0135de3442"


class LinuxIsolationProfilePayloadV13(LinuxIsolationProfilePayloadV11):
    """Forward package-bound profile consuming only Build-012/Bundle V6."""

    schema_version: Literal[13] = 13  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v13"] = "linux_native_isolation_v13"  # type: ignore[assignment]
    child_module_argv: tuple[
        Literal["-I"],
        Literal["-B"],
        Literal["-m"],
        Literal["devhub.linux_native_isolation_child"],
    ] = ("-I", "-B", "-m", "devhub.linux_native_isolation_child")
    source_directories: Annotated[
        tuple[LinuxDirectoryAuthorityV1 | LinuxBundleDirectoryAuthorityV1, ...],
        Field(min_length=5),
    ]
    package: LinuxPackageAuthorityV2

    @model_validator(mode="after")
    def exact_package_join(self) -> LinuxIsolationProfilePayloadV13:
        if (
            self.package.bundle_id != self.native_bundle_id
            or self.package.bundle_manifest_sha256 != self.bundle_manifest_sha256
            or self.package.python_executable_sha256 != self.bootstrap_python.sha256
            or self.package.child_module_sha256 != self.child_probe_sha256
        ):
            raise ValueError("Linux isolation V13 package authority differs from the profile")
        fixture = next(item for item in self.source_directories if item.role == "fixture")
        if not isinstance(fixture, LinuxBundleDirectoryAuthorityV1):
            raise ValueError("Linux isolation V13 fixture is not the exact published bundle root")
        return self


class LinuxIsolationProfilePayloadV14(LinuxIsolationProfilePayloadV11):
    """Forward package-bound profile consuming only Build-012/Bundle V7."""

    schema_version: Literal[14] = 14  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v14"] = "linux_native_isolation_v14"  # type: ignore[assignment]
    child_runtime_failure_protocol: Literal["linux_child_runtime_failure_v3"] = (
        "linux_child_runtime_failure_v3"  # type: ignore[assignment]
    )
    child_module_argv: tuple[
        Literal["-I"],
        Literal["-B"],
        Literal["-m"],
        Literal["devhub.linux_native_isolation_child"],
    ] = ("-I", "-B", "-m", "devhub.linux_native_isolation_child")
    source_directories: Annotated[
        tuple[LinuxDirectoryAuthorityV1 | LinuxBundleDirectoryAuthorityV1, ...],
        Field(min_length=5),
    ]
    package: LinuxPackageAuthorityV3

    @model_validator(mode="after")
    def exact_package_join(self) -> LinuxIsolationProfilePayloadV14:
        if (
            self.package.bundle_id != self.native_bundle_id
            or self.package.bundle_manifest_sha256 != self.bundle_manifest_sha256
            or self.package.python_executable_sha256 != self.bootstrap_python.sha256
            or self.package.child_module_sha256 != self.child_probe_sha256
        ):
            raise ValueError("Linux isolation V14 package authority differs from the profile")
        fixture = next(item for item in self.source_directories if item.role == "fixture")
        if not isinstance(fixture, LinuxBundleDirectoryAuthorityV1):
            raise ValueError("Linux isolation V14 fixture is not the exact published bundle root")
        return self


class LinuxIsolationProfilePayloadV15(LinuxIsolationProfilePayloadV11):
    """Forward package-bound profile consuming only Build-012/Bundle V8."""

    schema_version: Literal[15] = 15  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v15"] = "linux_native_isolation_v15"  # type: ignore[assignment]
    child_runtime_failure_protocol: Literal["linux_child_runtime_failure_v3"] = (
        "linux_child_runtime_failure_v3"  # type: ignore[assignment]
    )
    child_module_argv: tuple[
        Literal["-I"],
        Literal["-B"],
        Literal["-m"],
        Literal["devhub.linux_native_isolation_child"],
    ] = ("-I", "-B", "-m", "devhub.linux_native_isolation_child")
    source_directories: Annotated[
        tuple[LinuxDirectoryAuthorityV1 | LinuxBundleDirectoryAuthorityV1, ...],
        Field(min_length=5),
    ]
    package: LinuxPackageAuthorityV4

    @model_validator(mode="after")
    def exact_package_join(self) -> LinuxIsolationProfilePayloadV15:
        if (
            self.package.bundle_id != self.native_bundle_id
            or self.package.bundle_manifest_sha256 != self.bundle_manifest_sha256
            or self.package.python_executable_sha256 != self.bootstrap_python.sha256
            or self.package.child_module_sha256 != self.child_probe_sha256
        ):
            raise ValueError("Linux isolation V15 package authority differs from the profile")
        fixture = next(item for item in self.source_directories if item.role == "fixture")
        if not isinstance(fixture, LinuxBundleDirectoryAuthorityV1):
            raise ValueError("Linux isolation V15 fixture is not the exact published bundle root")
        return self


class LinuxIsolationProfilePayloadV16(LinuxIsolationProfilePayloadV11):
    """Forward package-bound profile consuming only Build-012/Bundle V11."""

    schema_version: Literal[16] = 16  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v16"] = "linux_native_isolation_v16"  # type: ignore[assignment]
    child_runtime_failure_protocol: Literal["linux_child_runtime_failure_v3"] = (
        "linux_child_runtime_failure_v3"  # type: ignore[assignment]
    )
    child_module_argv: tuple[
        Literal["-I"],
        Literal["-B"],
        Literal["-m"],
        Literal["devhub.linux_native_isolation_child"],
    ] = ("-I", "-B", "-m", "devhub.linux_native_isolation_child")
    source_directories: Annotated[
        tuple[LinuxDirectoryAuthorityV1 | LinuxBundleDirectoryAuthorityV1, ...],
        Field(min_length=5),
    ]
    package: LinuxPackageAuthorityV5

    @model_validator(mode="after")
    def exact_package_join(self) -> LinuxIsolationProfilePayloadV16:
        if (
            self.package.bundle_id != self.native_bundle_id
            or self.package.bundle_manifest_sha256 != self.bundle_manifest_sha256
            or self.package.python_executable_sha256 != self.bootstrap_python.sha256
            or self.package.child_module_sha256 != self.child_probe_sha256
        ):
            raise ValueError("Linux isolation V16 package authority differs from the profile")
        fixture = next(item for item in self.source_directories if item.role == "fixture")
        if not isinstance(fixture, LinuxBundleDirectoryAuthorityV1):
            raise ValueError("Linux isolation V16 fixture is not the exact published bundle root")
        return self


class LinuxIsolationProfilePayloadV17(LinuxIsolationProfilePayloadV16):
    """V17 adds one exact transient-service cgroup resource authority."""

    schema_version: Literal[17] = 17  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v17"] = "linux_native_isolation_v17"  # type: ignore[assignment]
    cgroup_setup_state_id: Digest
    cgroup: LinuxCgroupBoundaryAuthorityV1


class LinuxIsolationProfileV1(Contract):
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV1

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV1) -> LinuxIsolationProfileV1:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation profile hash mismatch")
        return self


class LinuxIsolationProfileV2(Contract):
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV2

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV2) -> LinuxIsolationProfileV2:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V2 profile hash mismatch")
        return self


class LinuxIsolationProfileV3(Contract):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV3

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV3) -> LinuxIsolationProfileV3:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV3:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V3 profile hash mismatch")
        return self


class LinuxIsolationProfileV4(ContractV2):
    schema_version: Literal[4] = 4  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV4

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV4) -> LinuxIsolationProfileV4:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV4:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V4 profile hash mismatch")
        return self


class LinuxIsolationProfileV5(ContractV2):
    schema_version: Literal[5] = 5  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV5

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV5) -> LinuxIsolationProfileV5:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV5:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V5 profile hash mismatch")
        return self


class LinuxIsolationProfileV6(ContractV2):
    schema_version: Literal[6] = 6  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV6

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV6) -> LinuxIsolationProfileV6:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV6:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V6 profile hash mismatch")
        return self


class LinuxIsolationProfileV7(ContractV2):
    schema_version: Literal[7] = 7  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV7

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV7) -> LinuxIsolationProfileV7:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV7:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V7 profile hash mismatch")
        return self


class LinuxIsolationProfileV8(ContractV2):
    schema_version: Literal[8] = 8  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV8

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV8) -> LinuxIsolationProfileV8:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV8:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V8 profile hash mismatch")
        return self


class LinuxIsolationProfileV9(ContractV2):
    schema_version: Literal[9] = 9  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV9

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV9) -> LinuxIsolationProfileV9:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV9:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V9 profile hash mismatch")
        return self


class LinuxIsolationProfileV10(ContractV2):
    schema_version: Literal[10] = 10  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV10

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV10) -> LinuxIsolationProfileV10:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV10:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V10 profile hash mismatch")
        return self


class LinuxIsolationProfileV11(ContractV2):
    schema_version: Literal[11] = 11  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV11

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV11) -> LinuxIsolationProfileV11:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV11:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V11 profile hash mismatch")
        return self


class LinuxIsolationProfileV12(ContractV2):
    schema_version: Literal[12] = 12  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV12

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV12) -> LinuxIsolationProfileV12:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV12:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V12 profile hash mismatch")
        return self


class LinuxIsolationProfileV13(ContractV2):
    schema_version: Literal[13] = 13  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV13

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV13) -> LinuxIsolationProfileV13:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV13:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V13 profile hash mismatch")
        return self


class LinuxIsolationProfileV14(ContractV2):
    schema_version: Literal[14] = 14  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV14

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV14) -> LinuxIsolationProfileV14:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV14:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V14 profile hash mismatch")
        return self


class LinuxIsolationProfileV15(ContractV2):
    schema_version: Literal[15] = 15  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV15

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV15) -> LinuxIsolationProfileV15:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV15:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V15 profile hash mismatch")
        return self


class LinuxIsolationProfileV16(ContractV2):
    schema_version: Literal[16] = 16  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV16

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV16) -> LinuxIsolationProfileV16:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV16:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V16 profile hash mismatch")
        return self


class LinuxIsolationProfileV17(ContractV2):
    schema_version: Literal[17] = 17  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV17

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV17) -> LinuxIsolationProfileV17:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV17:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_profile_id != expected:
            raise ValueError("Linux isolation V17 profile hash mismatch")
        return self


class LinuxNamespaceObservationV1(Contract):
    host_user_namespace_id: Annotated[str, Field(pattern=r"^user:\[[0-9]+\]$")]
    child_user_namespace_id: Annotated[str, Field(pattern=r"^user:\[[0-9]+\]$")]
    host_mount_namespace_id: Annotated[str, Field(pattern=r"^mnt:\[[0-9]+\]$")]
    child_mount_namespace_id: Annotated[str, Field(pattern=r"^mnt:\[[0-9]+\]$")]
    host_pid_namespace_id: Annotated[str, Field(pattern=r"^pid:\[[0-9]+\]$")]
    child_pid_namespace_id: Annotated[str, Field(pattern=r"^pid:\[[0-9]+\]$")]
    host_network_namespace_id: Annotated[str, Field(pattern=r"^net:\[[0-9]+\]$")]
    child_network_namespace_id: Annotated[str, Field(pattern=r"^net:\[[0-9]+\]$")]
    uid_map_sha256: Digest
    gid_map_sha256: Digest
    child_uid: Literal[1000] = 1000
    child_gid: Literal[1000] = 1000

    @model_validator(mode="after")
    def namespaces_are_fresh(self) -> LinuxNamespaceObservationV1:
        pairs = (
            (self.host_user_namespace_id, self.child_user_namespace_id),
            (self.host_mount_namespace_id, self.child_mount_namespace_id),
            (self.host_pid_namespace_id, self.child_pid_namespace_id),
            (self.host_network_namespace_id, self.child_network_namespace_id),
        )
        if any(host == child for host, child in pairs):
            raise ValueError("Linux isolation namespace was not replaced")
        return self


class LinuxBrokerObservationV1(Contract):
    socket_parent_mode: Literal["0700"] = "0700"
    socket_mode: Literal["0600"] = "0600"
    peer_pid_matched: Literal[True] = True
    peer_start_time_matched: Literal[True] = True
    peer_uid_matched: Literal[True] = True
    pid_namespace_translation_validated: Literal[True] = True
    child_verified_broker_pid_translation: Literal[True] = True
    child_verified_broker_uid: Literal[True] = True
    socket_inode: Annotated[int, Field(ge=1)]
    version_allowed: Literal[True] = True
    tags_allowed: Literal[True] = True
    show_allowed: Literal[True] = True
    generate_denied: Literal[True] = True
    oversized_request_denied: Literal[True] = True


class LinuxIsolationObservationV1(Contract):
    schema_version: Literal[1] = 1
    namespaces: LinuxNamespaceObservationV1
    private_mount_root: Literal[True] = True
    mount_table_sha256: Digest
    observed_mount_targets: tuple[str, ...]
    bundle_read_only: Literal[True] = True
    state_read_write: Literal[True] = True
    output_read_write: Literal[True] = True
    home_tmpfs: Literal[True] = True
    tmp_tmpfs: Literal[True] = True
    fresh_proc: Literal[True] = True
    minimal_dev: Literal[True] = True
    host_root_hidden: Literal[True] = True
    host_home_hidden: Literal[True] = True
    no_new_privs: Literal[True] = True
    cap_effective: Literal[0] = 0
    cap_permitted: Literal[0] = 0
    cap_inheritable: Literal[0] = 0
    cap_ambient: Literal[0] = 0
    cap_bounding: Literal[0] = 0
    capability_regain_denied: Literal[True] = True
    landlock_abi: Annotated[int, Field(ge=3, le=6)]
    landlock_handled_access: Annotated[int, Field(gt=0)]
    landlock_rule_targets: tuple[str, ...]
    landlock_ruleset_sha256: Digest
    landlock_allowed_operations_passed: Literal[True] = True
    landlock_denied_operations_passed: Literal[True] = True
    direct_loopback_denied: Literal[True] = True
    direct_lan_denied: Literal[True] = True
    direct_dns_denied: Literal[True] = True
    direct_public_denied: Literal[True] = True
    rlimits_applied: Literal[True] = True
    rlimits_sha256: Digest
    broker: LinuxBrokerObservationV1
    descendant_cleanup_passed: Literal[True] = True
    cleanup_failures: tuple[()] = ()


class LinuxIsolationObservationV2(LinuxIsolationObservationV1):
    schema_version: Literal[2] = 2  # type: ignore[assignment]
    apparmor_current_profile: Literal["devfabric-linux-isolation-unshare (unconfined)"] = (
        "devfabric-linux-isolation-unshare (unconfined)"
    )


class LinuxIsolationObservationV3(ContractV2):
    """V3 observation with exact kernel and reviewed Landlock policy ABIs."""

    schema_version: Literal[3] = 3  # type: ignore[assignment]
    apparmor_current_profile: Literal["devfabric-linux-isolation-unshare (unconfined)"] = (
        "devfabric-linux-isolation-unshare (unconfined)"
    )
    namespaces: LinuxNamespaceObservationV1
    private_mount_root: Literal[True] = True
    mount_table_sha256: Digest
    observed_mount_targets: tuple[str, ...]
    bundle_read_only: Literal[True] = True
    state_read_write: Literal[True] = True
    output_read_write: Literal[True] = True
    home_tmpfs: Literal[True] = True
    tmp_tmpfs: Literal[True] = True
    fresh_proc: Literal[True] = True
    minimal_dev: Literal[True] = True
    host_root_hidden: Literal[True] = True
    host_home_hidden: Literal[True] = True
    no_new_privs: Literal[True] = True
    cap_effective: Literal[0] = 0
    cap_permitted: Literal[0] = 0
    cap_inheritable: Literal[0] = 0
    cap_ambient: Literal[0] = 0
    cap_bounding: Literal[0] = 0
    capability_regain_denied: Literal[True] = True
    kernel_landlock_abi: Annotated[int, Field(ge=3)]
    enforced_landlock_abi: Annotated[int, Field(ge=3, le=6)]
    landlock_handled_access: Annotated[int, Field(gt=0)]
    landlock_rule_targets: tuple[str, ...]
    landlock_ruleset_sha256: Digest
    landlock_allowed_operations_passed: Literal[True] = True
    landlock_denied_operations_passed: Literal[True] = True
    direct_loopback_denied: Literal[True] = True
    direct_lan_denied: Literal[True] = True
    direct_dns_denied: Literal[True] = True
    direct_public_denied: Literal[True] = True
    rlimits_applied: Literal[True] = True
    rlimits_sha256: Digest
    broker: LinuxBrokerObservationV1
    descendant_cleanup_passed: Literal[True] = True
    cleanup_failures: tuple[()] = ()

    @model_validator(mode="after")
    def exact_landlock_authority(self) -> LinuxIsolationObservationV3:
        expected = enforced_landlock_abi(self.kernel_landlock_abi)
        if self.enforced_landlock_abi != expected:
            raise ValueError("Observed enforced Landlock ABI differs from the policy ceiling")
        if self.landlock_handled_access != landlock_handled_access(expected):
            raise ValueError("Observed Landlock mask differs from the enforced ABI")
        return self


class LinuxIsolationObservationV4(LinuxIsolationObservationV3):
    """V4 observation includes child-side mount authority revalidation."""

    schema_version: Literal[4] = 4  # type: ignore[assignment]
    mount_authority_revalidated: Literal[True] = True


class LinuxSyntheticUpstreamObservationV1(Contract):
    authority: LinuxSyntheticUpstreamAuthorityV1
    listener_identity_matched: Literal[True] = True
    listener_retained_through_broker: Literal[True] = True


class LinuxIsolationObservationV5(LinuxIsolationObservationV4):
    """V5 observation joins mechanics traffic to one retained fixture listener."""

    schema_version: Literal[5] = 5  # type: ignore[assignment]
    synthetic_upstream: LinuxSyntheticUpstreamObservationV1


class LinuxChildBootstrapObservationV1(Contract):
    isolated_python: Literal[True] = True
    bytecode_disabled: Literal[True] = True
    stdlib_only: Literal[True] = True


class LinuxNamespaceOwnerProjectionObservationV1(Contract):
    host_owner_uid: Literal[0] = 0
    host_owner_gid: Literal[0] = 0
    host_root_uid_mapped: Literal[False] = False
    host_root_gid_mapped: Literal[False] = False
    overflow_uid: Annotated[int, Field(ge=1, le=2**32 - 1)]
    overflow_gid: Annotated[int, Field(ge=1, le=2**32 - 1)]
    observed_owner_uid: Annotated[int, Field(ge=1, le=2**32 - 1)]
    observed_owner_gid: Annotated[int, Field(ge=1, le=2**32 - 1)]

    @model_validator(mode="after")
    def exact_overflow_projection(self) -> LinuxNamespaceOwnerProjectionObservationV1:
        if (
            self.observed_owner_uid != self.overflow_uid
            or self.observed_owner_gid != self.overflow_gid
        ):
            raise ValueError("Namespace owner observation differs from configured overflow IDs")
        return self


class LinuxChildRegistrationPayloadV2(ContractV2):
    schema_version: Literal[2] = 2
    frame_kind: Literal["linux_child_registration_v2"] = "linux_child_registration_v2"
    apparmor_current_profile: Literal["devfabric-linux-isolation-unshare (unconfined)"] = (
        "devfabric-linux-isolation-unshare (unconfined)"
    )
    outer_pid: Annotated[int, Field(ge=1)]
    inner_pid: Literal[1] = 1
    outer_uid: Annotated[int, Field(ge=0)]
    inner_uid: Literal[1000] = 1000
    start_time_ticks: Annotated[int, Field(ge=1)]
    mount_owner_projection: LinuxNamespaceOwnerProjectionObservationV1


class LinuxChildRegistrationV2(ContractV2):
    child_registration_id: Digest
    payload: LinuxChildRegistrationPayloadV2

    @classmethod
    def create(cls, payload: LinuxChildRegistrationPayloadV2) -> LinuxChildRegistrationV2:
        return cls(
            child_registration_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxChildRegistrationV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.child_registration_id != expected:
            raise ValueError("Linux child registration hash mismatch")
        return self


class LinuxMountAuthorityObservationV1(Contract):
    pre_exec_authority_matched: Literal[True] = True
    version_environment_matched: Literal[True] = True
    version_execution_succeeded: Literal[True] = True
    version_output_matched: Literal[True] = True
    post_exec_authority_matched: Literal[True] = True


class LinuxChildRegistrationPayloadV3(LinuxChildRegistrationPayloadV2):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    frame_kind: Literal["linux_child_registration_v3"] = "linux_child_registration_v3"  # type: ignore[assignment]
    mount_authority: LinuxMountAuthorityObservationV1


class LinuxChildRegistrationV3(ContractV2):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    child_registration_id: Digest
    payload: LinuxChildRegistrationPayloadV3

    @classmethod
    def create(cls, payload: LinuxChildRegistrationPayloadV3) -> LinuxChildRegistrationV3:
        return cls(
            child_registration_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxChildRegistrationV3:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.child_registration_id != expected:
            raise ValueError("Linux child V3 registration hash mismatch")
        return self


class LinuxChildBootstrapFailurePayloadV1(Contract):
    schema_version: Literal[1] = 1
    frame_kind: Literal["linux_child_bootstrap_failure_v1"] = "linux_child_bootstrap_failure_v1"
    stage: Literal[
        "interpreter_flags",
        "apparmor_identity",
        "mount_authority",
        "process_identity",
    ]
    reason_code: Literal[
        "interpreter_flags_invalid",
        "apparmor_identity_invalid",
        "mount_host_authority_not_root",
        "namespace_host_root_mapped",
        "namespace_overflow_invalid",
        "namespace_owner_projection_mismatch",
        "mount_authority_mismatch",
        "process_identity_invalid",
    ]

    @model_validator(mode="after")
    def exact_stage_reason(self) -> LinuxChildBootstrapFailurePayloadV1:
        allowed = {
            "interpreter_flags": {"interpreter_flags_invalid"},
            "apparmor_identity": {"apparmor_identity_invalid"},
            "mount_authority": {
                "mount_host_authority_not_root",
                "namespace_host_root_mapped",
                "namespace_overflow_invalid",
                "namespace_owner_projection_mismatch",
                "mount_authority_mismatch",
            },
            "process_identity": {"process_identity_invalid"},
        }
        if self.reason_code not in allowed[self.stage]:
            raise ValueError("Linux child bootstrap stage and reason differ")
        return self


class LinuxChildBootstrapFailureV1(Contract):
    child_bootstrap_failure_id: Digest
    payload: LinuxChildBootstrapFailurePayloadV1

    @classmethod
    def create(cls, payload: LinuxChildBootstrapFailurePayloadV1) -> LinuxChildBootstrapFailureV1:
        return cls(
            child_bootstrap_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxChildBootstrapFailureV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.child_bootstrap_failure_id != expected:
            raise ValueError("Linux child bootstrap failure hash mismatch")
        return self


class LinuxChildBootstrapFailurePayloadV2(ContractV2):
    schema_version: Literal[2] = 2
    frame_kind: Literal["linux_child_bootstrap_failure_v2"] = "linux_child_bootstrap_failure_v2"
    stage: Literal[
        "interpreter_flags",
        "apparmor_identity",
        "mount_authority",
        "process_identity",
    ]
    reason_code: Literal[
        "interpreter_flags_invalid",
        "apparmor_identity_invalid",
        "mount_host_authority_not_root",
        "namespace_host_root_mapped",
        "namespace_overflow_invalid",
        "namespace_owner_projection_mismatch",
        "mount_pre_exec_path_invalid",
        "mount_pre_exec_content_mismatch",
        "mount_pre_exec_mode_mismatch",
        "mount_pre_exec_identity_mismatch",
        "mount_version_environment_invalid",
        "mount_version_execution_failed",
        "mount_version_exit_nonzero",
        "mount_version_output_mismatch",
        "mount_post_exec_substitution",
        "mount_authority_internal_failure",
        "process_identity_invalid",
    ]

    @model_validator(mode="after")
    def exact_stage_reason(self) -> LinuxChildBootstrapFailurePayloadV2:
        mount_reasons = {
            "mount_host_authority_not_root",
            "namespace_host_root_mapped",
            "namespace_overflow_invalid",
            "namespace_owner_projection_mismatch",
            "mount_pre_exec_path_invalid",
            "mount_pre_exec_content_mismatch",
            "mount_pre_exec_mode_mismatch",
            "mount_pre_exec_identity_mismatch",
            "mount_version_environment_invalid",
            "mount_version_execution_failed",
            "mount_version_exit_nonzero",
            "mount_version_output_mismatch",
            "mount_post_exec_substitution",
            "mount_authority_internal_failure",
        }
        allowed = {
            "interpreter_flags": {"interpreter_flags_invalid"},
            "apparmor_identity": {"apparmor_identity_invalid"},
            "mount_authority": mount_reasons,
            "process_identity": {"process_identity_invalid"},
        }
        if self.reason_code not in allowed[self.stage]:
            raise ValueError("Linux child V2 bootstrap stage and reason differ")
        return self


class LinuxChildBootstrapFailureV2(ContractV2):
    schema_version: Literal[2] = 2
    child_bootstrap_failure_id: Digest
    payload: LinuxChildBootstrapFailurePayloadV2

    @classmethod
    def create(cls, payload: LinuxChildBootstrapFailurePayloadV2) -> LinuxChildBootstrapFailureV2:
        return cls(
            child_bootstrap_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxChildBootstrapFailureV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.child_bootstrap_failure_id != expected:
            raise ValueError("Linux child V2 bootstrap failure hash mismatch")
        return self


class LinuxChildBootstrapFailurePayloadV3(LinuxChildBootstrapFailurePayloadV2):
    """Bounded diagnostic evidence for a child-side native identity mismatch."""

    schema_version: Literal[3] = 3  # type: ignore[assignment]
    frame_kind: Literal["linux_child_bootstrap_failure_v3"] = "linux_child_bootstrap_failure_v3"  # type: ignore[assignment]
    expected_native_identity: LinuxNativePathIdentityV1 | None = None
    observed_native_identity: LinuxNativePathIdentityV1 | None = None

    @model_validator(mode="after")
    def exact_native_identity_diagnostic(self) -> LinuxChildBootstrapFailurePayloadV3:
        is_identity_mismatch = self.reason_code == "mount_pre_exec_identity_mismatch"
        identities_present = (
            self.expected_native_identity is not None and self.observed_native_identity is not None
        )
        if is_identity_mismatch != identities_present:
            raise ValueError("Linux child V3 native identity evidence differs from failure reason")
        if is_identity_mismatch and self.expected_native_identity == self.observed_native_identity:
            raise ValueError("Linux child V3 native identity mismatch records equal identities")
        return self


class LinuxChildBootstrapFailureV3(ContractV2):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    child_bootstrap_failure_id: Digest
    payload: LinuxChildBootstrapFailurePayloadV3

    @classmethod
    def create(cls, payload: LinuxChildBootstrapFailurePayloadV3) -> LinuxChildBootstrapFailureV3:
        return cls(
            child_bootstrap_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxChildBootstrapFailureV3:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.child_bootstrap_failure_id != expected:
            raise ValueError("Linux child V3 bootstrap failure hash mismatch")
        return self


class LinuxChildRuntimeFailurePayloadV1(Contract):
    """Bounded post-registration diagnostic with no raw text or host paths."""

    schema_version: Literal[1] = 1
    frame_kind: Literal["linux_child_runtime_failure_v1"] = "linux_child_runtime_failure_v1"
    stage: Literal[
        "private_root",
        "rlimits",
        "capability_drop",
        "landlock",
        "negative_probes",
        "broker",
        "result_assembly",
    ]
    reason_code: Literal[
        "private_root_failed",
        "rlimits_failed",
        "capability_drop_failed",
        "landlock_failed",
        "negative_probes_failed",
        "broker_failed",
        "result_assembly_failed",
    ]

    @model_validator(mode="after")
    def exact_stage_reason(self) -> LinuxChildRuntimeFailurePayloadV1:
        expected = {
            "private_root": "private_root_failed",
            "rlimits": "rlimits_failed",
            "capability_drop": "capability_drop_failed",
            "landlock": "landlock_failed",
            "negative_probes": "negative_probes_failed",
            "broker": "broker_failed",
            "result_assembly": "result_assembly_failed",
        }[self.stage]
        if self.reason_code != expected:
            raise ValueError("Linux child runtime stage and reason differ")
        return self


class LinuxChildRuntimeFailureV1(Contract):
    schema_version: Literal[1] = 1
    child_runtime_failure_id: Digest
    payload: LinuxChildRuntimeFailurePayloadV1

    @classmethod
    def create(cls, payload: LinuxChildRuntimeFailurePayloadV1) -> LinuxChildRuntimeFailureV1:
        return cls(
            child_runtime_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxChildRuntimeFailureV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.child_runtime_failure_id != expected:
            raise ValueError("Linux child runtime failure hash mismatch")
        return self


class LinuxChildRuntimeFailurePayloadV2(ContractV2):
    """Forward-only bounded child diagnostic for broker sub-operations."""

    schema_version: Literal[2] = 2
    frame_kind: Literal["linux_child_runtime_failure_v2"] = "linux_child_runtime_failure_v2"
    linux_isolation_profile_id: Digest
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    stage: Literal[
        "private_root",
        "rlimits",
        "capability_drop",
        "landlock",
        "negative_probes",
        "broker",
        "result_assembly",
    ]
    reason_code: Literal[
        "private_root_failed",
        "rlimits_failed",
        "capability_drop_failed",
        "landlock_failed",
        "negative_probes_failed",
        "broker_socket_missing",
        "broker_connect_failed",
        "broker_peer_credentials_failed",
        "broker_socket_stat_failed",
        "broker_socket_type_invalid",
        "broker_socket_mode_invalid",
        "broker_parent_mode_invalid",
        "broker_peer_pid_invalid",
        "broker_peer_uid_invalid",
        "broker_send_failed",
        "broker_shutdown_failed",
        "broker_receive_failed",
        "broker_response_bound_exceeded",
        "broker_response_status_invalid",
        "broker_inode_substitution",
        "broker_internal_failure",
        "result_assembly_failed",
    ]
    broker_checkpoint: (
        Literal[
            "socket_wait",
            "version",
            "tags",
            "show",
            "generate_denial",
            "oversized_denial",
            "inode_stability",
        ]
        | None
    ) = None
    broker_operation: (
        Literal[
            "wait",
            "connect",
            "socket_type",
            "socket_mode",
            "parent_mode",
            "peer_pid",
            "peer_uid",
            "peer_credentials",
            "path_stat",
            "send",
            "shutdown_write",
            "receive",
            "response_bound",
            "response_status",
            "inode_compare",
            "internal",
        ]
        | None
    ) = None
    errno_category: (
        Literal[
            "connection_refused",
            "connection_reset",
            "broken_pipe",
            "timed_out",
            "permission_denied",
            "other_os_error",
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def exact_diagnostic_shape(self) -> LinuxChildRuntimeFailurePayloadV2:
        generic = {
            "private_root": "private_root_failed",
            "rlimits": "rlimits_failed",
            "capability_drop": "capability_drop_failed",
            "landlock": "landlock_failed",
            "negative_probes": "negative_probes_failed",
            "result_assembly": "result_assembly_failed",
        }
        if self.stage != "broker":
            if self.reason_code != generic[self.stage]:
                raise ValueError("Linux child V2 runtime stage and reason differ")
            if (
                self.broker_checkpoint is not None
                or self.broker_operation is not None
                or self.errno_category is not None
            ):
                raise ValueError("Linux child V2 non-broker failure carries broker fields")
        elif self.broker_checkpoint is None or self.broker_operation is None:
            raise ValueError("Linux child V2 broker failure lacks a bounded checkpoint")
        else:
            exact = {
                "broker_socket_missing": ("socket_wait", "wait", False),
                "broker_connect_failed": (None, "connect", True),
                "broker_peer_credentials_failed": (None, "peer_credentials", True),
                "broker_socket_stat_failed": (None, "path_stat", True),
                "broker_socket_type_invalid": (None, "socket_type", False),
                "broker_socket_mode_invalid": (None, "socket_mode", False),
                "broker_parent_mode_invalid": (None, "parent_mode", False),
                "broker_peer_pid_invalid": (None, "peer_pid", False),
                "broker_peer_uid_invalid": (None, "peer_uid", False),
                "broker_send_failed": (None, "send", True),
                "broker_shutdown_failed": (None, "shutdown_write", True),
                "broker_receive_failed": (None, "receive", True),
                "broker_response_bound_exceeded": (None, "response_bound", False),
                "broker_response_status_invalid": (None, "response_status", False),
                "broker_inode_substitution": ("inode_stability", "inode_compare", False),
                "broker_internal_failure": ("socket_wait", "internal", False),
            }
            if self.reason_code not in exact:
                raise ValueError("Linux child V2 broker stage has a non-broker reason")
            expected_checkpoint, expected_operation, requires_errno = exact[self.reason_code]
            if expected_checkpoint is not None and self.broker_checkpoint != expected_checkpoint:
                raise ValueError("Linux child V2 broker reason and checkpoint differ")
            if self.broker_operation != expected_operation:
                raise ValueError("Linux child V2 broker reason and operation differ")
            ordinary_checkpoints = {
                "version",
                "tags",
                "show",
                "generate_denial",
                "oversized_denial",
            }
            if expected_checkpoint is None and self.broker_checkpoint not in ordinary_checkpoints:
                raise ValueError("Linux child V2 broker operation has an invalid checkpoint")
            if requires_errno != (self.errno_category is not None):
                raise ValueError("Linux child V2 broker errno shape differs from its reason")
        return self


class LinuxChildRuntimeFailureV2(ContractV2):
    schema_version: Literal[2] = 2
    child_runtime_failure_id: Digest
    payload: LinuxChildRuntimeFailurePayloadV2

    @classmethod
    def create(cls, payload: LinuxChildRuntimeFailurePayloadV2) -> LinuxChildRuntimeFailureV2:
        return cls(
            child_runtime_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxChildRuntimeFailureV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.child_runtime_failure_id != expected:
            raise ValueError("Linux child V2 runtime failure hash mismatch")
        return self


class LinuxPackagedSubprocessCaptureV1(Contract):
    """Bounded subprocess evidence; retained hashes never claim full-stream identity."""

    schema_version: Literal[1] = Field(...)
    process_started: bool
    returncode: int | None = None
    stdout_retained_bytes: Annotated[int, Field(ge=0, le=1024 * 1024)]
    stdout_observed_bytes: Annotated[int, Field(ge=0, le=(1024 + 64) * 1024)]
    stdout_retained_sha256: Digest
    stdout_truncated: bool
    stderr_retained_bytes: Annotated[int, Field(ge=0, le=1024 * 1024)]
    stderr_observed_bytes: Annotated[int, Field(ge=0, le=(1024 + 64) * 1024)]
    stderr_retained_sha256: Digest
    stderr_truncated: bool
    timed_out: bool
    output_limit_exceeded: bool

    @model_validator(mode="after")
    def exact_bounded_shape(self) -> LinuxPackagedSubprocessCaptureV1:
        empty = digest(b"")
        for name in ("stdout", "stderr"):
            retained = getattr(self, f"{name}_retained_bytes")
            observed = getattr(self, f"{name}_observed_bytes")
            truncated = getattr(self, f"{name}_truncated")
            retained_hash = getattr(self, f"{name}_retained_sha256")
            if retained > observed or truncated != (retained < observed):
                raise ValueError("Packaged subprocess stream bounds differ")
            if retained == 0 and retained_hash != empty:
                raise ValueError("Empty packaged subprocess stream hash differs")
        any_truncated = self.stdout_truncated or self.stderr_truncated
        if self.output_limit_exceeded != any_truncated:
            raise ValueError("Packaged subprocess output-limit state differs")
        if not self.process_started and (
            self.returncode is not None
            or self.stdout_observed_bytes != 0
            or self.stderr_observed_bytes != 0
            or self.timed_out
            or self.output_limit_exceeded
        ):
            raise ValueError("Unstarted packaged subprocess carries process evidence")
        if self.timed_out and self.returncode is not None:
            raise ValueError("Timed-out packaged subprocess has a final return code")
        return self


class LinuxChildRuntimeFailurePayloadV3(LinuxChildRuntimeFailurePayloadV2):
    """Forward-only result-assembly diagnostic for the packaged MCP lifecycle."""

    schema_version: Literal[3] = 3  # type: ignore[assignment]
    frame_kind: Literal["linux_child_runtime_failure_v3"] = "linux_child_runtime_failure_v3"  # type: ignore[assignment]
    packaged_mcp_checkpoint: (
        Literal[
            "python_authority",
            "state_config_preparation",
            "module_origin",
            "ledger_initialization",
            "mcp_exchange",
            "capture_publication",
            "response_parsing",
            "initialize_shape",
            "tools_shape",
            "observation_assembly",
            "result_frame_publication",
        ]
        | None
    ) = None
    packaged_subprocess: LinuxPackagedSubprocessCaptureV1 | None = None

    @model_validator(mode="after")
    def exact_packaged_diagnostic(self) -> LinuxChildRuntimeFailurePayloadV3:
        if self.stage == "result_assembly":
            if self.packaged_mcp_checkpoint is None:
                raise ValueError("Linux child V3 result failure lacks a packaged checkpoint")
        elif self.packaged_mcp_checkpoint is not None or self.packaged_subprocess is not None:
            raise ValueError("Linux child V3 non-result failure carries packaged diagnostics")
        capture_required = {
            "module_origin",
            "ledger_initialization",
            "mcp_exchange",
            "response_parsing",
            "initialize_shape",
            "tools_shape",
            "capture_publication",
        }
        if (self.packaged_mcp_checkpoint in capture_required) != (
            self.packaged_subprocess is not None
        ):
            raise ValueError("Linux child V3 checkpoint subprocess evidence differs")
        return self


class LinuxChildRuntimeFailureV3(ContractV2):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    child_runtime_failure_id: Digest
    payload: LinuxChildRuntimeFailurePayloadV3

    @classmethod
    def create(cls, payload: LinuxChildRuntimeFailurePayloadV3) -> LinuxChildRuntimeFailureV3:
        return cls(
            child_runtime_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxChildRuntimeFailureV3:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.child_runtime_failure_id != expected:
            raise ValueError("Linux child V3 runtime failure hash mismatch")
        return self


class LinuxHostBrokerFailurePayloadV1(Contract):
    """Bounded host broker diagnostic with no exception text or paths."""

    schema_version: Literal[1] = 1
    receipt_kind: Literal["linux_host_broker_failure_v1"] = "linux_host_broker_failure_v1"
    linux_isolation_profile_id: Digest
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    checkpoint: Literal[
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
    ]
    reason_code: Literal[
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
    ]
    failure_kind: Literal[
        "os_error",
        "authority_validation",
        "response_bound_exceeded",
        "cleanup_error",
        "internal_error",
    ]
    errno_category: (
        Literal[
            "address_in_use",
            "connection_refused",
            "connection_reset",
            "broken_pipe",
            "timed_out",
            "permission_denied",
            "other_os_error",
        ]
        | None
    ) = None
    completed_outcomes: tuple[Literal["/api/version", "/api/tags", "/api/show", "denied"], ...] = ()

    @model_validator(mode="after")
    def exact_outcome_prefix(self) -> LinuxHostBrokerFailurePayloadV1:
        expected = ("/api/version", "/api/tags", "/api/show", "denied", "denied")
        if (
            len(self.completed_outcomes) > len(expected)
            or self.completed_outcomes != expected[: len(self.completed_outcomes)]
        ):
            raise ValueError("Linux host broker failure outcomes are not a canonical prefix")
        expected_reason = f"{self.checkpoint}_failed"
        if self.reason_code != expected_reason:
            raise ValueError("Linux host broker checkpoint and reason differ")
        if (self.failure_kind == "os_error") != (self.errno_category is not None):
            raise ValueError("Linux host broker errno shape differs from its failure kind")
        if self.failure_kind == "authority_validation" and self.checkpoint not in {
            "parent_validation",
            "peer_credentials",
            "peer_start_time",
        }:
            raise ValueError("Linux host broker authority failure has an invalid checkpoint")
        if self.failure_kind == "response_bound_exceeded" and self.checkpoint != "upstream_read":
            raise ValueError("Linux host broker response bound has an invalid checkpoint")
        if self.failure_kind == "cleanup_error" and self.checkpoint != "cleanup":
            raise ValueError("Linux host broker cleanup failure has an invalid checkpoint")
        return self


class LinuxHostBrokerFailureV1(Contract):
    linux_host_broker_failure_id: Digest
    payload: LinuxHostBrokerFailurePayloadV1

    @classmethod
    def create(cls, payload: LinuxHostBrokerFailurePayloadV1) -> LinuxHostBrokerFailureV1:
        return cls(
            linux_host_broker_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxHostBrokerFailureV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_host_broker_failure_id != expected:
            raise ValueError("Linux host broker failure hash mismatch")
        return self


class LinuxIsolationObservationV6(LinuxIsolationObservationV5):
    """V6 observation proves the isolated stdlib-only child entry boundary."""

    schema_version: Literal[6] = 6  # type: ignore[assignment]
    child_bootstrap: LinuxChildBootstrapObservationV1


class LinuxIsolationObservationV7(LinuxIsolationObservationV6):
    """V7 observes the exact namespace projection of root-owned host tools."""

    schema_version: Literal[7] = 7  # type: ignore[assignment]
    mount_owner_projection: LinuxNamespaceOwnerProjectionObservationV1


class LinuxIsolationObservationV8(LinuxIsolationObservationV7):
    """V8 records staged child-side mount authority verification."""

    schema_version: Literal[8] = 8  # type: ignore[assignment]
    mount_authority: LinuxMountAuthorityObservationV1


class LinuxIsolationObservationV9(LinuxIsolationObservationV8):
    """V9 preserves the successful V8 observation contract."""

    schema_version: Literal[9] = 9  # type: ignore[assignment]


class LinuxIsolationObservationV10(LinuxIsolationObservationV9):
    """V10 preserves the successful V9 observation contract."""

    schema_version: Literal[10] = 10  # type: ignore[assignment]


class LinuxIsolationObservationV11(LinuxIsolationObservationV10):
    """V11 preserves the successful V10 observation contract."""

    schema_version: Literal[11] = 11  # type: ignore[assignment]


class LinuxPackagedMcpMetadataObservationV1(Contract):
    """Bounded metadata-only observation of the packaged delegate server."""

    schema_version: Literal[1] = 1
    python_executable_sha256: Digest
    module_origin: Literal[
        "/bundle/python/lib/python3.12/site-packages/devhub/delegate_server.py"
    ] = "/bundle/python/lib/python3.12/site-packages/devhub/delegate_server.py"
    argv: tuple[Literal["-I"], Literal["-B"], Literal["-m"], Literal["devhub.delegate_server"]] = (
        "-I",
        "-B",
        "-m",
        "devhub.delegate_server",
    )
    initialize_succeeded: Literal[True] = True
    tools_list_succeeded: Literal[True] = True
    tool_names: tuple[Literal["devhub_delegate"]] = ("devhub_delegate",)
    tools_call_sent: Literal[False] = False
    eof_sent: Literal[True] = True
    clean_exit: Literal[True] = True
    exit_code: Literal[0] = 0
    stdout_retained_sha256: Digest
    stderr_retained_sha256: Digest
    stdout_retained_bytes: Annotated[int, Field(ge=1, le=1024 * 1024)]
    stderr_retained_bytes: Annotated[int, Field(ge=0, le=1024 * 1024)]


class LinuxPackagedMcpMetadataObservationV2(LinuxPackagedMcpMetadataObservationV1):
    """V2 proves the packaged MCP process used the exact bundled ELF loader closure."""

    schema_version: Literal[2] = 2  # type: ignore[assignment]
    loader_sha256: Digest
    runtime_library_authority_sha256: Digest
    loader_arguments: tuple[Literal["--inhibit-cache"], Literal["--library-path"]]


class LinuxIsolationObservationV12(LinuxIsolationObservationV11):
    """V12 binds the installed child and packaged MCP metadata lifecycle."""

    schema_version: Literal[12] = 12  # type: ignore[assignment]
    child_module_origin: Literal[
        "/bundle/python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"
    ] = "/bundle/python/lib/python3.12/site-packages/devhub/linux_native_isolation_child.py"
    child_module_sha256: Digest
    packaged_mcp: LinuxPackagedMcpMetadataObservationV1


class LinuxIsolationObservationV13(LinuxIsolationObservationV12):
    """V13 preserves V12 mechanics while binding Bundle V6 authority."""

    schema_version: Literal[13] = 13  # type: ignore[assignment]


class LinuxIsolationObservationV14(LinuxIsolationObservationV12):
    """V14 preserves mechanics while binding Bundle V7 authority."""

    schema_version: Literal[14] = 14  # type: ignore[assignment]


class LinuxIsolationObservationV15(LinuxIsolationObservationV12):
    """V15 preserves mechanics while binding corrected Bundle V8 authority."""

    schema_version: Literal[15] = 15  # type: ignore[assignment]


class LinuxIsolationObservationV16(LinuxIsolationObservationV12):
    """V16 binds Bundle V11 and the loader-bound packaged MCP lifecycle."""

    schema_version: Literal[16] = 16  # type: ignore[assignment]
    packaged_mcp: LinuxPackagedMcpMetadataObservationV2


class LinuxCgroupMemberObservationV1(Contract):
    role: Literal["probe", "namespace_launcher", "namespace_child"]
    pid: Annotated[int, Field(ge=1)]
    start_time_ticks: Annotated[int, Field(ge=1)]
    control_group: Annotated[str, Field(pattern=r"^/system\.slice/[^\r\n]+\.service$")]


class LinuxCgroupBoundaryObservationV1(Contract):
    setup_state_id: Digest
    control_group: Annotated[
        str,
        Field(pattern=r"^/system\.slice/devfabric-linux-isolation-[a-f0-9]{32}\.service$"),
    ]
    cgroup_native_identity: LinuxNativePathIdentityV1
    observed_service_uid: Annotated[int, Field(ge=1)]
    observed_service_gid: Annotated[int, Field(ge=1)]
    cgroup_type: Literal["domain"] = "domain"
    memory_max: Literal["2147483648"] = LINUX_CGROUP_MEMORY_MAX
    pids_max: Literal["128"] = LINUX_CGROUP_PIDS_MAX
    cpu_max: Literal["200000 100000"] = LINUX_CGROUP_CPU_MAX
    initial_members_only_probe: Literal[True] = True
    active_members_all_descendants: Literal[True] = True
    terminal_members_only_probe: Literal[True] = True
    process_tree_inheritance_verified: Literal[True] = True
    cgroup_controls_not_writable: Literal[True] = True
    ancestor_controls_not_writable: Literal[True] = True
    observed_members: Annotated[tuple[LinuxCgroupMemberObservationV1, ...], Field(min_length=3)]

    @model_validator(mode="after")
    def exact_process_tree(self) -> LinuxCgroupBoundaryObservationV1:
        roles = [member.role for member in self.observed_members]
        pids = [member.pid for member in self.observed_members]
        if sorted(roles) != ["namespace_child", "namespace_launcher", "probe"]:
            raise ValueError("Linux cgroup observation must contain the exact process-tree roles")
        if len(set(pids)) != len(pids):
            raise ValueError("Linux cgroup observation contains duplicate process identities")
        if any(member.control_group != self.control_group for member in self.observed_members):
            raise ValueError("Linux cgroup process escaped the exact control group")
        return self


class LinuxIsolationObservationV17(LinuxIsolationObservationV16):
    """V17 preserves V16 mechanics and observes the exact cgroup boundary."""

    schema_version: Literal[17] = 17  # type: ignore[assignment]
    cgroup: LinuxCgroupBoundaryObservationV1


class LinuxHostCleanupObservationV1(Contract):
    child_exited: Literal[True] = True
    process_group_absent: Literal[True] = True
    broker_stopped: Literal[True] = True
    upstream_stub_stopped: Literal[True] = True
    broker_socket_absent: Literal[True] = True
    source_authorities_revalidated: Literal[True] = True
    scratch_root_removed: Literal[True] = True


class LinuxIsolationReceiptPayloadV1(Contract):
    schema_version: Literal[1] = 1
    receipt_kind: Literal["linux_native_isolation_receipt_v1"] = "linux_native_isolation_receipt_v1"
    linux_isolation_profile_id: Digest
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    observation: LinuxIsolationObservationV1
    model_requests: Literal[0] = 0
    provider_sends: Literal[0] = 0
    mcp_tool_executions: Literal[0] = 0
    real_task_executions: Literal[0] = 0
    metadata_isolation_baseline_qualified: Literal[True] = True
    cgroup_resource_boundary_qualified: Literal[False] = False
    syscall_filter_qualified: Literal[False] = False
    native_executor_isolation_qualified: Literal[False] = False
    package_readiness: Literal[False] = False


class LinuxIsolationReceiptV1(Contract):
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV1

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV1) -> LinuxIsolationReceiptV1:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation receipt hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV1(Contract):
    schema_version: Literal[1] = 1
    profile: LinuxIsolationProfileV1
    receipt: LinuxIsolationReceiptV1
    child_stdout_retained_sha256: Digest
    child_stderr_retained_sha256: Digest
    child_stdout_retained_bytes: Annotated[int, Field(ge=0, le=1024 * 1024)]
    child_stderr_retained_bytes: Annotated[int, Field(ge=0, le=1024 * 1024)]
    child_stdout_truncated: bool
    child_stderr_truncated: bool
    cleanup: LinuxHostCleanupObservationV1

    @model_validator(mode="after")
    def exact_profile_receipt_join(self) -> LinuxIsolationEvidencePayloadV1:
        if (
            self.receipt.payload.linux_isolation_profile_id
            != self.profile.linux_isolation_profile_id
            or self.receipt.payload.environment_instance_id
            != self.profile.payload.environment_instance_id
        ):
            raise ValueError("Linux isolation profile and receipt authority differ")
        profile = self.profile.payload
        observed = self.receipt.payload.observation
        if observed.landlock_abi != profile.host.landlock_abi:
            raise ValueError("Observed Landlock ABI differs from profile authority")
        if observed.landlock_handled_access != profile.landlock_handled_access:
            raise ValueError("Observed Landlock mask differs from profile authority")
        expected_targets = tuple(item.target for item in profile.mounts)
        if observed.observed_mount_targets != expected_targets:
            raise ValueError("Observed mount targets differ from profile authority")
        expected_rlimits = digest(canonical(profile.rlimits.model_dump(mode="json")))
        if observed.rlimits_sha256 != expected_rlimits:
            raise ValueError("Observed rlimits differ from profile authority")
        expected_rules = (
            "/bundle",
            "/home",
            "/output",
            "/proc",
            "/run/devfabric",
            "/state",
            "/tmp",
        )
        if observed.landlock_rule_targets != expected_rules:
            raise ValueError("Observed Landlock rules differ from the reviewed rule set")
        return self


class LinuxIsolationEvidenceV1(Contract):
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV1

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV1) -> LinuxIsolationEvidenceV1:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation evidence hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV2(ContractV2):
    schema_version: Literal[2] = 2
    receipt_kind: Literal["linux_native_isolation_receipt_v2"] = "linux_native_isolation_receipt_v2"
    linux_isolation_profile_id: Digest
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    observation: LinuxIsolationObservationV2
    model_requests: Literal[0] = 0
    provider_sends: Literal[0] = 0
    mcp_tool_executions: Literal[0] = 0
    real_task_executions: Literal[0] = 0
    metadata_isolation_baseline_qualified: Literal[True] = True
    cgroup_resource_boundary_qualified: Literal[False] = False
    syscall_filter_qualified: Literal[False] = False
    native_executor_isolation_qualified: Literal[False] = False
    package_readiness: Literal[False] = False


class LinuxIsolationReceiptV2(Contract):
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV2

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV2) -> LinuxIsolationReceiptV2:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V2 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV3(ContractV2):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v3"] = "linux_native_isolation_receipt_v3"
    linux_isolation_profile_id: Digest
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    observation: LinuxIsolationObservationV3
    model_requests: Literal[0] = 0
    provider_sends: Literal[0] = 0
    mcp_tool_executions: Literal[0] = 0
    real_task_executions: Literal[0] = 0
    metadata_isolation_baseline_qualified: Literal[True] = True
    cgroup_resource_boundary_qualified: Literal[False] = False
    syscall_filter_qualified: Literal[False] = False
    native_executor_isolation_qualified: Literal[False] = False
    package_readiness: Literal[False] = False


class LinuxIsolationReceiptV3(Contract):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV3

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV3) -> LinuxIsolationReceiptV3:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV3:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V3 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV4(LinuxIsolationReceiptPayloadV3):
    schema_version: Literal[4] = 4  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v4"] = "linux_native_isolation_receipt_v4"  # type: ignore[assignment]
    observation: LinuxIsolationObservationV4


class LinuxIsolationReceiptV4(ContractV2):
    schema_version: Literal[4] = 4  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV4

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV4) -> LinuxIsolationReceiptV4:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV4:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V4 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV5(LinuxIsolationReceiptPayloadV4):
    schema_version: Literal[5] = 5  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v5"] = "linux_native_isolation_receipt_v5"  # type: ignore[assignment]
    observation: LinuxIsolationObservationV5


class LinuxIsolationReceiptV5(ContractV2):
    schema_version: Literal[5] = 5  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV5

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV5) -> LinuxIsolationReceiptV5:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV5:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V5 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV6(LinuxIsolationReceiptPayloadV5):
    schema_version: Literal[6] = 6  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v6"] = "linux_native_isolation_receipt_v6"  # type: ignore[assignment]
    observation: LinuxIsolationObservationV6


class LinuxIsolationReceiptV6(ContractV2):
    schema_version: Literal[6] = 6  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV6

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV6) -> LinuxIsolationReceiptV6:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV6:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V6 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV7(LinuxIsolationReceiptPayloadV6):
    schema_version: Literal[7] = 7  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v7"] = "linux_native_isolation_receipt_v7"  # type: ignore[assignment]
    observation: LinuxIsolationObservationV7


class LinuxIsolationReceiptV7(ContractV2):
    schema_version: Literal[7] = 7  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV7

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV7) -> LinuxIsolationReceiptV7:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV7:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V7 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV8(LinuxIsolationReceiptPayloadV7):
    schema_version: Literal[8] = 8  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v8"] = "linux_native_isolation_receipt_v8"  # type: ignore[assignment]
    observation: LinuxIsolationObservationV8


class LinuxIsolationReceiptV8(ContractV2):
    schema_version: Literal[8] = 8  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV8

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV8) -> LinuxIsolationReceiptV8:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV8:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V8 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV9(LinuxIsolationReceiptPayloadV8):
    schema_version: Literal[9] = 9  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v9"] = "linux_native_isolation_receipt_v9"  # type: ignore[assignment]
    observation: LinuxIsolationObservationV9


class LinuxIsolationReceiptV9(ContractV2):
    schema_version: Literal[9] = 9  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV9

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV9) -> LinuxIsolationReceiptV9:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV9:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V9 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV10(LinuxIsolationReceiptPayloadV9):
    schema_version: Literal[10] = 10  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v10"] = (
        "linux_native_isolation_receipt_v10"  # type: ignore[assignment]
    )
    observation: LinuxIsolationObservationV10


class LinuxIsolationReceiptV10(ContractV2):
    schema_version: Literal[10] = 10  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV10

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV10) -> LinuxIsolationReceiptV10:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV10:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V10 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV11(LinuxIsolationReceiptPayloadV10):
    schema_version: Literal[11] = 11  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v11"] = (
        "linux_native_isolation_receipt_v11"  # type: ignore[assignment]
    )
    observation: LinuxIsolationObservationV11


class LinuxIsolationReceiptV11(ContractV2):
    schema_version: Literal[11] = 11  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV11

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV11) -> LinuxIsolationReceiptV11:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV11:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V11 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV12(LinuxIsolationReceiptPayloadV11):
    schema_version: Literal[12] = 12  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v12"] = (
        "linux_native_isolation_receipt_v12"  # type: ignore[assignment]
    )
    observation: LinuxIsolationObservationV12


class LinuxIsolationReceiptV12(ContractV2):
    schema_version: Literal[12] = 12  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV12

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV12) -> LinuxIsolationReceiptV12:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV12:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V12 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV13(LinuxIsolationReceiptPayloadV11):
    schema_version: Literal[13] = 13  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v13"] = (
        "linux_native_isolation_receipt_v13"  # type: ignore[assignment]
    )
    observation: LinuxIsolationObservationV13


class LinuxIsolationReceiptV13(ContractV2):
    schema_version: Literal[13] = 13  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV13

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV13) -> LinuxIsolationReceiptV13:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV13:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V13 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV14(LinuxIsolationReceiptPayloadV11):
    schema_version: Literal[14] = 14  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v14"] = (
        "linux_native_isolation_receipt_v14"  # type: ignore[assignment]
    )
    observation: LinuxIsolationObservationV14


class LinuxIsolationReceiptV14(ContractV2):
    schema_version: Literal[14] = 14  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV14

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV14) -> LinuxIsolationReceiptV14:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV14:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V14 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV15(LinuxIsolationReceiptPayloadV11):
    schema_version: Literal[15] = 15  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v15"] = (
        "linux_native_isolation_receipt_v15"  # type: ignore[assignment]
    )
    observation: LinuxIsolationObservationV15


class LinuxIsolationReceiptV15(ContractV2):
    schema_version: Literal[15] = 15  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV15

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV15) -> LinuxIsolationReceiptV15:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV15:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V15 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV16(LinuxIsolationReceiptPayloadV11):
    schema_version: Literal[16] = 16  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v16"] = (
        "linux_native_isolation_receipt_v16"  # type: ignore[assignment]
    )
    observation: LinuxIsolationObservationV16


class LinuxIsolationReceiptV16(ContractV2):
    schema_version: Literal[16] = 16  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV16

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV16) -> LinuxIsolationReceiptV16:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV16:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V16 receipt hash mismatch")
        return self


class LinuxIsolationReceiptPayloadV17(LinuxIsolationReceiptPayloadV16):
    schema_version: Literal[17] = 17  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v17"] = (
        "linux_native_isolation_receipt_v17"  # type: ignore[assignment]
    )
    observation: LinuxIsolationObservationV17
    cgroup_resource_boundary_qualified: Literal[True] = True  # type: ignore[assignment]


class LinuxIsolationReceiptV17(ContractV2):
    schema_version: Literal[17] = 17  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV17

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV17) -> LinuxIsolationReceiptV17:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV17:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_receipt_id != expected:
            raise ValueError("Linux isolation V17 receipt hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV2(ContractV2):
    schema_version: Literal[2] = 2
    profile: LinuxIsolationProfileV2
    receipt: LinuxIsolationReceiptV2
    child_stdout_retained_sha256: Digest
    child_stderr_retained_sha256: Digest
    child_stdout_retained_bytes: Annotated[int, Field(ge=0, le=1024 * 1024)]
    child_stderr_retained_bytes: Annotated[int, Field(ge=0, le=1024 * 1024)]
    child_stdout_truncated: bool
    child_stderr_truncated: bool
    cleanup: LinuxHostCleanupObservationV1

    @model_validator(mode="after")
    def exact_profile_receipt_join(self) -> LinuxIsolationEvidencePayloadV2:
        if (
            self.receipt.payload.linux_isolation_profile_id
            != self.profile.linux_isolation_profile_id
            or self.receipt.payload.environment_instance_id
            != self.profile.payload.environment_instance_id
        ):
            raise ValueError("Linux isolation V2 profile and receipt authority differ")
        profile = self.profile.payload
        observed = self.receipt.payload.observation
        if observed.apparmor_current_profile != profile.host.apparmor.loaded_profile_line:
            raise ValueError("Observed AppArmor profile differs from host authority")
        if observed.landlock_abi != profile.host.landlock_abi:
            raise ValueError("Observed Landlock ABI differs from profile authority")
        if observed.landlock_handled_access != profile.landlock_handled_access:
            raise ValueError("Observed Landlock mask differs from profile authority")
        expected_targets = tuple(item.target for item in profile.mounts)
        if observed.observed_mount_targets != expected_targets:
            raise ValueError("Observed mount targets differ from profile authority")
        expected_rlimits = digest(canonical(profile.rlimits.model_dump(mode="json")))
        if observed.rlimits_sha256 != expected_rlimits:
            raise ValueError("Observed rlimits differ from profile authority")
        expected_rules = (
            "/bundle",
            "/home",
            "/output",
            "/proc",
            "/run/devfabric",
            "/state",
            "/tmp",
        )
        if observed.landlock_rule_targets != expected_rules:
            raise ValueError("Observed Landlock rules differ from the reviewed rule set")
        return self


class LinuxIsolationEvidenceV2(Contract):
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV2

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV2) -> LinuxIsolationEvidenceV2:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V2 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV3(ContractV2):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    profile: LinuxIsolationProfileV3
    receipt: LinuxIsolationReceiptV3
    child_stdout_retained_sha256: Digest
    child_stderr_retained_sha256: Digest
    child_stdout_retained_bytes: Annotated[int, Field(ge=0, le=1024 * 1024)]
    child_stderr_retained_bytes: Annotated[int, Field(ge=0, le=1024 * 1024)]
    child_stdout_truncated: bool
    child_stderr_truncated: bool
    cleanup: LinuxHostCleanupObservationV1

    @model_validator(mode="after")
    def exact_profile_receipt_join(self) -> LinuxIsolationEvidencePayloadV3:
        profile = self.profile.payload
        observed = self.receipt.payload.observation
        if (
            self.receipt.payload.linux_isolation_profile_id
            != self.profile.linux_isolation_profile_id
            or self.receipt.payload.environment_instance_id != profile.environment_instance_id
        ):
            raise ValueError("Linux isolation V3 profile and receipt authority differ")
        if observed.apparmor_current_profile != profile.host.apparmor.loaded_profile_line:
            raise ValueError("Observed AppArmor profile differs from host authority")
        if observed.kernel_landlock_abi != profile.host.kernel_landlock_abi:
            raise ValueError("Observed Landlock kernel ABI differs from profile authority")
        if observed.enforced_landlock_abi != profile.host.enforced_landlock_abi:
            raise ValueError("Observed enforced Landlock ABI differs from profile authority")
        if observed.landlock_handled_access != profile.landlock_handled_access:
            raise ValueError("Observed Landlock mask differs from profile authority")
        expected_targets = tuple(item.target for item in profile.mounts)
        if observed.observed_mount_targets != expected_targets:
            raise ValueError("Observed mount targets differ from profile authority")
        expected_rlimits = digest(canonical(profile.rlimits.model_dump(mode="json")))
        if observed.rlimits_sha256 != expected_rlimits:
            raise ValueError("Observed rlimits differ from profile authority")
        expected_rules = (
            "/bundle",
            "/home",
            "/output",
            "/proc",
            "/run/devfabric",
            "/state",
            "/tmp",
        )
        if observed.landlock_rule_targets != expected_rules:
            raise ValueError("Observed Landlock rules differ from the reviewed rule set")
        return self


class LinuxIsolationEvidenceV3(Contract):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV3

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV3) -> LinuxIsolationEvidenceV3:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV3:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V3 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV4(LinuxIsolationEvidencePayloadV3):
    schema_version: Literal[4] = 4  # type: ignore[assignment]
    profile: LinuxIsolationProfileV4  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV4  # type: ignore[assignment]


class LinuxIsolationEvidenceV4(ContractV2):
    schema_version: Literal[4] = 4  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV4

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV4) -> LinuxIsolationEvidenceV4:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV4:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V4 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV5(LinuxIsolationEvidencePayloadV4):
    schema_version: Literal[5] = 5  # type: ignore[assignment]
    profile: LinuxIsolationProfileV5  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV5  # type: ignore[assignment]

    @model_validator(mode="after")
    def exact_synthetic_upstream_join(self) -> LinuxIsolationEvidencePayloadV5:
        if (
            self.receipt.payload.observation.synthetic_upstream.authority
            != self.profile.payload.synthetic_upstream
        ):
            raise ValueError("Linux V5 synthetic upstream authority differs")
        return self


class LinuxIsolationEvidenceV5(ContractV2):
    schema_version: Literal[5] = 5  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV5

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV5) -> LinuxIsolationEvidenceV5:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV5:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V5 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV6(LinuxIsolationEvidencePayloadV5):
    schema_version: Literal[6] = 6  # type: ignore[assignment]
    profile: LinuxIsolationProfileV6  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV6  # type: ignore[assignment]


class LinuxIsolationEvidenceV6(ContractV2):
    schema_version: Literal[6] = 6  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV6

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV6) -> LinuxIsolationEvidenceV6:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV6:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V6 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV7(LinuxIsolationEvidencePayloadV6):
    schema_version: Literal[7] = 7  # type: ignore[assignment]
    profile: LinuxIsolationProfileV7  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV7  # type: ignore[assignment]

    @model_validator(mode="after")
    def exact_owner_projection_join(self) -> LinuxIsolationEvidencePayloadV7:
        expected = self.profile.payload.mount_owner_projection
        observed = self.receipt.payload.observation.mount_owner_projection
        if (
            observed.host_owner_uid != expected.host_owner_uid
            or observed.host_owner_gid != expected.host_owner_gid
            or observed.overflow_uid != expected.overflow_uid
            or observed.overflow_gid != expected.overflow_gid
        ):
            raise ValueError("Linux V7 namespace owner projection authority differs")
        return self


class LinuxIsolationEvidenceV7(ContractV2):
    schema_version: Literal[7] = 7  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV7

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV7) -> LinuxIsolationEvidenceV7:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV7:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V7 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV8(LinuxIsolationEvidencePayloadV7):
    schema_version: Literal[8] = 8  # type: ignore[assignment]
    profile: LinuxIsolationProfileV8  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV8  # type: ignore[assignment]


class LinuxIsolationEvidenceV8(ContractV2):
    schema_version: Literal[8] = 8  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV8

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV8) -> LinuxIsolationEvidenceV8:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV8:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V8 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV9(LinuxIsolationEvidencePayloadV8):
    schema_version: Literal[9] = 9  # type: ignore[assignment]
    profile: LinuxIsolationProfileV9  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV9  # type: ignore[assignment]


class LinuxIsolationEvidenceV9(ContractV2):
    schema_version: Literal[9] = 9  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV9

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV9) -> LinuxIsolationEvidenceV9:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV9:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V9 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV10(LinuxIsolationEvidencePayloadV9):
    schema_version: Literal[10] = 10  # type: ignore[assignment]
    profile: LinuxIsolationProfileV10  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV10  # type: ignore[assignment]


class LinuxIsolationEvidenceV10(ContractV2):
    schema_version: Literal[10] = 10  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV10

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV10) -> LinuxIsolationEvidenceV10:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV10:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V10 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV11(LinuxIsolationEvidencePayloadV10):
    schema_version: Literal[11] = 11  # type: ignore[assignment]
    profile: LinuxIsolationProfileV11  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV11  # type: ignore[assignment]


class LinuxIsolationEvidenceV11(ContractV2):
    schema_version: Literal[11] = 11  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV11

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV11) -> LinuxIsolationEvidenceV11:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV11:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V11 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV12(LinuxIsolationEvidencePayloadV11):
    schema_version: Literal[12] = 12  # type: ignore[assignment]
    profile: LinuxIsolationProfileV12  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV12  # type: ignore[assignment]

    @model_validator(mode="after")
    def exact_package_observation_join(self) -> LinuxIsolationEvidencePayloadV12:
        package = self.profile.payload.package
        observed = self.receipt.payload.observation
        if (
            observed.child_module_sha256 != package.child_module_sha256
            or observed.packaged_mcp.python_executable_sha256 != package.python_executable_sha256
        ):
            raise ValueError("Linux isolation V12 package observation authority differs")
        return self


class LinuxIsolationEvidenceV12(ContractV2):
    schema_version: Literal[12] = 12  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV12

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV12) -> LinuxIsolationEvidenceV12:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV12:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V12 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV13(LinuxIsolationEvidencePayloadV11):
    schema_version: Literal[13] = 13  # type: ignore[assignment]
    profile: LinuxIsolationProfileV13  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV13  # type: ignore[assignment]

    @model_validator(mode="after")
    def exact_package_observation_join(self) -> LinuxIsolationEvidencePayloadV13:
        package = self.profile.payload.package
        observed = self.receipt.payload.observation
        if (
            observed.child_module_sha256 != package.child_module_sha256
            or observed.packaged_mcp.python_executable_sha256 != package.python_executable_sha256
        ):
            raise ValueError("Linux isolation V13 package observation authority differs")
        return self


class LinuxIsolationEvidenceV13(ContractV2):
    schema_version: Literal[13] = 13  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV13

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV13) -> LinuxIsolationEvidenceV13:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV13:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V13 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV14(LinuxIsolationEvidencePayloadV11):
    schema_version: Literal[14] = 14  # type: ignore[assignment]
    profile: LinuxIsolationProfileV14  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV14  # type: ignore[assignment]

    @model_validator(mode="after")
    def exact_package_observation_join(self) -> LinuxIsolationEvidencePayloadV14:
        package = self.profile.payload.package
        observed = self.receipt.payload.observation
        if (
            observed.child_module_sha256 != package.child_module_sha256
            or observed.packaged_mcp.python_executable_sha256 != package.python_executable_sha256
        ):
            raise ValueError("Linux isolation V14 package observation authority differs")
        return self


class LinuxIsolationEvidenceV14(ContractV2):
    schema_version: Literal[14] = 14  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV14

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV14) -> LinuxIsolationEvidenceV14:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV14:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V14 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV15(LinuxIsolationEvidencePayloadV11):
    schema_version: Literal[15] = 15  # type: ignore[assignment]
    profile: LinuxIsolationProfileV15  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV15  # type: ignore[assignment]

    @model_validator(mode="after")
    def exact_package_observation_join(self) -> LinuxIsolationEvidencePayloadV15:
        package = self.profile.payload.package
        observed = self.receipt.payload.observation
        if (
            observed.child_module_sha256 != package.child_module_sha256
            or observed.packaged_mcp.python_executable_sha256 != package.python_executable_sha256
        ):
            raise ValueError("Linux isolation V15 package observation authority differs")
        return self


class LinuxIsolationEvidenceV15(ContractV2):
    schema_version: Literal[15] = 15  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV15

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV15) -> LinuxIsolationEvidenceV15:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV15:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V15 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV16(LinuxIsolationEvidencePayloadV11):
    schema_version: Literal[16] = 16  # type: ignore[assignment]
    profile: LinuxIsolationProfileV16  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV16  # type: ignore[assignment]

    @model_validator(mode="after")
    def exact_package_observation_join(self) -> LinuxIsolationEvidencePayloadV16:
        package = self.profile.payload.package
        observed = self.receipt.payload.observation
        if (
            observed.child_module_sha256 != package.child_module_sha256
            or observed.packaged_mcp.python_executable_sha256 != package.python_executable_sha256
            or observed.packaged_mcp.loader_sha256 != package.loader_sha256
            or observed.packaged_mcp.runtime_library_authority_sha256
            != package.runtime_library_authority_sha256
            or observed.packaged_mcp.loader_arguments != package.loader_arguments
        ):
            raise ValueError("Linux isolation V16 package observation authority differs")
        return self


class LinuxIsolationEvidenceV16(ContractV2):
    schema_version: Literal[16] = 16  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV16

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV16) -> LinuxIsolationEvidenceV16:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV16:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V16 evidence hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV17(LinuxIsolationEvidencePayloadV16):
    schema_version: Literal[17] = 17  # type: ignore[assignment]
    profile: LinuxIsolationProfileV17  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV17  # type: ignore[assignment]

    @model_validator(mode="after")
    def exact_cgroup_join(self) -> LinuxIsolationEvidencePayloadV17:
        authority = self.profile.payload.cgroup
        observed = self.receipt.payload.observation.cgroup
        if (
            observed.setup_state_id != self.profile.payload.cgroup_setup_state_id
            or observed.control_group != authority.control_group
            or observed.memory_max != authority.limits.memory_max
            or observed.pids_max != authority.limits.pids_max
            or observed.cpu_max != authority.limits.cpu_max
            or observed.observed_service_uid != authority.service_uid
            or observed.observed_service_gid != authority.service_gid
        ):
            raise ValueError("Linux isolation V17 cgroup observation authority differs")
        return self


class LinuxIsolationEvidenceV17(ContractV2):
    schema_version: Literal[17] = 17  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV17

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV17) -> LinuxIsolationEvidenceV17:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV17:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_evidence_id != expected:
            raise ValueError("Linux isolation V17 evidence hash mismatch")
        return self


class LinuxAppArmorCleanupPayloadV1(Contract):
    schema_version: Literal[1] = 1
    receipt_kind: Literal["linux_apparmor_cleanup_receipt_v1"] = "linux_apparmor_cleanup_receipt_v1"
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    linux_isolation_profile_id: Digest
    linux_isolation_evidence_id: Digest
    apparmor_authority_sha256: Digest
    parser_unload_succeeded: Literal[True] = True
    loaded_profile_absent: Literal[True] = True
    installed_profile_removed: Literal[True] = True
    private_launcher_removed: Literal[True] = True
    loaded_snapshot_removed: Literal[True] = True
    private_root_removed_if_created: Literal[True] = True
    private_parent_removed_if_created: Literal[True] = True
    runtime_parent_removed_if_created: Literal[True] = True
    setup_state_removed: Literal[True] = True
    cleanup_complete: Literal[True] = True


class LinuxAppArmorCleanupReceiptV1(Contract):
    linux_apparmor_cleanup_receipt_id: Digest
    payload: LinuxAppArmorCleanupPayloadV1

    @classmethod
    def create(cls, payload: LinuxAppArmorCleanupPayloadV1) -> LinuxAppArmorCleanupReceiptV1:
        return cls(
            linux_apparmor_cleanup_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxAppArmorCleanupReceiptV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_apparmor_cleanup_receipt_id != expected:
            raise ValueError("Linux AppArmor cleanup receipt hash mismatch")
        return self


class LinuxCgroupCleanupPayloadV1(Contract):
    schema_version: Literal[1] = 1
    receipt_kind: Literal["linux_cgroup_cleanup_receipt_v1"] = "linux_cgroup_cleanup_receipt_v1"
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    linux_isolation_profile_id: Digest
    linux_isolation_evidence_id: Digest
    linux_cgroup_setup_state_id: Digest
    unit_name: Annotated[
        str,
        Field(pattern=r"^devfabric-linux-isolation-[a-f0-9]{32}\.service$"),
    ]
    control_group: Annotated[
        str,
        Field(pattern=r"^/system\.slice/devfabric-linux-isolation-[a-f0-9]{32}\.service$"),
    ]
    unit_absent: Literal[True] = True
    cgroup_absent: Literal[True] = True
    cleanup_complete: Literal[True] = True


class LinuxCgroupCleanupStatePayloadV1(Contract):
    schema_version: Literal[1] = 1
    state_kind: Literal["linux_cgroup_cleanup_state_v1"] = "linux_cgroup_cleanup_state_v1"
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    linux_cgroup_setup_state_id: Digest
    linux_isolation_profile_id: Digest
    linux_isolation_evidence_id: Digest
    unit_name: Annotated[
        str,
        Field(pattern=r"^devfabric-linux-isolation-[a-f0-9]{32}\.service$"),
    ]
    control_group: Annotated[
        str,
        Field(pattern=r"^/system\.slice/devfabric-linux-isolation-[a-f0-9]{32}\.service$"),
    ]
    cgroup_native_identity: LinuxNativePathIdentityV1
    stop_authorized: Literal[True] = True


class LinuxCgroupCleanupStateV1(Contract):
    linux_cgroup_cleanup_state_id: Digest
    payload: LinuxCgroupCleanupStatePayloadV1

    @classmethod
    def create(cls, payload: LinuxCgroupCleanupStatePayloadV1) -> LinuxCgroupCleanupStateV1:
        return cls(
            linux_cgroup_cleanup_state_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxCgroupCleanupStateV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_cgroup_cleanup_state_id != expected:
            raise ValueError("Linux cgroup cleanup state hash mismatch")
        return self


class LinuxCgroupCleanupReceiptV1(Contract):
    linux_cgroup_cleanup_receipt_id: Digest
    payload: LinuxCgroupCleanupPayloadV1

    @classmethod
    def create(cls, payload: LinuxCgroupCleanupPayloadV1) -> LinuxCgroupCleanupReceiptV1:
        return cls(
            linux_cgroup_cleanup_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxCgroupCleanupReceiptV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_cgroup_cleanup_receipt_id != expected:
            raise ValueError("Linux cgroup cleanup receipt hash mismatch")
        return self


class LinuxCgroupCleanupPayloadV2(LinuxCgroupCleanupPayloadV1):
    """V2 records the observed systemd post-exit cgroup lifecycle."""

    schema_version: Literal[2] = 2  # type: ignore[assignment]
    receipt_kind: Literal["linux_cgroup_cleanup_receipt_v2"] = "linux_cgroup_cleanup_receipt_v2"  # type: ignore[assignment]
    post_exit_state: Literal["systemd_removed_empty_cgroup"]


class LinuxCgroupCleanupStatePayloadV2(LinuxCgroupCleanupStatePayloadV1):
    schema_version: Literal[2] = 2  # type: ignore[assignment]
    state_kind: Literal["linux_cgroup_cleanup_state_v2"] = "linux_cgroup_cleanup_state_v2"  # type: ignore[assignment]
    post_exit_state: Literal["systemd_removed_empty_cgroup"]


class LinuxCgroupCleanupStateV2(Contract):
    linux_cgroup_cleanup_state_id: Digest
    payload: LinuxCgroupCleanupStatePayloadV2

    @classmethod
    def create(cls, payload: LinuxCgroupCleanupStatePayloadV2) -> LinuxCgroupCleanupStateV2:
        return cls(
            linux_cgroup_cleanup_state_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxCgroupCleanupStateV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_cgroup_cleanup_state_id != expected:
            raise ValueError("Linux cgroup cleanup V2 state hash mismatch")
        return self


class LinuxCgroupCleanupReceiptV2(Contract):
    linux_cgroup_cleanup_receipt_id: Digest
    payload: LinuxCgroupCleanupPayloadV2

    @classmethod
    def create(cls, payload: LinuxCgroupCleanupPayloadV2) -> LinuxCgroupCleanupReceiptV2:
        return cls(
            linux_cgroup_cleanup_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxCgroupCleanupReceiptV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_cgroup_cleanup_receipt_id != expected:
            raise ValueError("Linux cgroup cleanup V2 receipt hash mismatch")
        return self


class LinuxCgroupRollbackPayloadV1(Contract):
    schema_version: Literal[1] = 1
    receipt_kind: Literal["linux_cgroup_rollback_receipt_v1"] = "linux_cgroup_rollback_receipt_v1"
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    linux_cgroup_setup_state_id: Digest
    unit_name: Annotated[
        str,
        Field(pattern=r"^devfabric-linux-isolation-[a-f0-9]{32}\.service$"),
    ]
    control_group: Annotated[
        str,
        Field(pattern=r"^/system\.slice/devfabric-linux-isolation-[a-f0-9]{32}\.service$"),
    ]
    cleanup_attempted: Literal[True] = True
    cleanup_succeeded: bool
    unit_absent: bool
    cgroup_absent: bool
    model_requests: Literal[0] = 0
    provider_sends: Literal[0] = 0
    mcp_tool_executions: Literal[0] = 0
    real_task_executions: Literal[0] = 0

    @model_validator(mode="after")
    def truthful_success(self) -> LinuxCgroupRollbackPayloadV1:
        if self.cleanup_succeeded != (self.unit_absent and self.cgroup_absent):
            raise ValueError("Linux cgroup rollback success differs from absence observations")
        return self


class LinuxCgroupRollbackReceiptV1(Contract):
    linux_cgroup_rollback_receipt_id: Digest
    payload: LinuxCgroupRollbackPayloadV1

    @classmethod
    def create(cls, payload: LinuxCgroupRollbackPayloadV1) -> LinuxCgroupRollbackReceiptV1:
        return cls(
            linux_cgroup_rollback_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxCgroupRollbackReceiptV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_cgroup_rollback_receipt_id != expected:
            raise ValueError("Linux cgroup rollback receipt hash mismatch")
        return self


class LinuxCgroupLifecycleFailurePayloadV1(Contract):
    schema_version: Literal[1] = 1
    receipt_kind: Literal["linux_cgroup_lifecycle_failure_v1"] = "linux_cgroup_lifecycle_failure_v1"
    phase: Literal["setup", "run", "cleanup"]
    reason_code: Literal[
        "authority_invalid",
        "service_creation_failed",
        "service_execution_failed",
        "cleanup_failed",
        "unexpected_internal_failure",
    ]
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    linux_cgroup_setup_state_id: Digest | None = None
    cleanup_attempted: bool
    cleanup_succeeded: bool
    model_requests: Literal[0] = 0
    provider_sends: Literal[0] = 0
    mcp_tool_executions: Literal[0] = 0
    real_task_executions: Literal[0] = 0


class LinuxCgroupLifecycleFailureV1(Contract):
    linux_cgroup_lifecycle_failure_id: Digest
    payload: LinuxCgroupLifecycleFailurePayloadV1

    @classmethod
    def create(cls, payload: LinuxCgroupLifecycleFailurePayloadV1) -> LinuxCgroupLifecycleFailureV1:
        return cls(
            linux_cgroup_lifecycle_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxCgroupLifecycleFailureV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_cgroup_lifecycle_failure_id != expected:
            raise ValueError("Linux cgroup lifecycle failure hash mismatch")
        return self


class LinuxSystemdSelectorOutputDigestV1(Contract):
    selector: Annotated[str, Field(pattern=r"^@[a-z0-9-]+$")]
    raw_output_sha256: Digest


class LinuxSyscallAllowlistMismatchObservationV1(Contract):
    configured_allowlist_count: Annotated[int, Field(ge=0, le=4096)]
    configured_allowlist_sha256: Digest
    systemd_analyze_version_output_sha256: Digest
    systemd_manager_version_output_sha256: Digest
    selector_outputs: Annotated[
        tuple[LinuxSystemdSelectorOutputDigestV1, ...], Field(min_length=1, max_length=64)
    ]

    @model_validator(mode="after")
    def sorted_unique_selectors(self) -> LinuxSyscallAllowlistMismatchObservationV1:
        selectors = tuple(value.selector for value in self.selector_outputs)
        if selectors != tuple(sorted(set(selectors))):
            raise ValueError("Systemd selector output observations must be sorted and unique")
        return self


class LinuxCgroupLifecycleFailurePayloadV2(ContractV2):
    receipt_kind: Literal["linux_cgroup_lifecycle_failure_v2"] = "linux_cgroup_lifecycle_failure_v2"
    phase: Literal["setup"] = "setup"
    reason_code: Literal[
        "syscall_allowlist_count_mismatch",
        "syscall_allowlist_hash_mismatch",
        "systemd_version_output_mismatch",
    ]
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    linux_cgroup_setup_state_id: None = None
    cleanup_attempted: Literal[False] = False
    cleanup_succeeded: Literal[False] = False
    authority_observation: LinuxSyscallAllowlistMismatchObservationV1
    model_requests: Literal[0] = 0
    provider_sends: Literal[0] = 0
    mcp_tool_executions: Literal[0] = 0
    real_task_executions: Literal[0] = 0

    @model_validator(mode="after")
    def exact_mismatch_classification(self) -> LinuxCgroupLifecycleFailurePayloadV2:
        observed = self.authority_observation
        if (
            observed.systemd_analyze_version_output_sha256
            != observed.systemd_manager_version_output_sha256
        ):
            raise ValueError("Systemd analyzer and manager mismatch observations differ")
        if self.reason_code == "syscall_allowlist_count_mismatch":
            if observed.configured_allowlist_count == LINUX_SYSCALL_ALLOWLIST_COUNT:
                raise ValueError("Syscall allowlist count mismatch reason is not observed")
        elif self.reason_code == "syscall_allowlist_hash_mismatch":
            if (
                observed.configured_allowlist_count != LINUX_SYSCALL_ALLOWLIST_COUNT
                or observed.configured_allowlist_sha256 == LINUX_SYSCALL_ALLOWLIST_SHA256
            ):
                raise ValueError("Syscall allowlist hash mismatch reason is not the first mismatch")
        elif (
            observed.configured_allowlist_count != LINUX_SYSCALL_ALLOWLIST_COUNT
            or observed.configured_allowlist_sha256 != LINUX_SYSCALL_ALLOWLIST_SHA256
            or observed.systemd_analyze_version_output_sha256
            == LINUX_REVIEWED_SYSTEMD_VERSION_SHA256
        ):
            raise ValueError("Systemd version mismatch reason is not the first mismatch")
        return self


class LinuxCgroupLifecycleFailureV2(ContractV2):
    linux_cgroup_lifecycle_failure_id: Digest
    payload: LinuxCgroupLifecycleFailurePayloadV2

    @classmethod
    def create(cls, payload: LinuxCgroupLifecycleFailurePayloadV2) -> LinuxCgroupLifecycleFailureV2:
        return cls(
            linux_cgroup_lifecycle_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxCgroupLifecycleFailureV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_cgroup_lifecycle_failure_id != expected:
            raise ValueError("Linux cgroup lifecycle failure V2 hash mismatch")
        return self


class LinuxAppArmorSetupStatePayloadV1(Contract):
    """Root-owned ownership journal for the narrow temporary AppArmor authority."""

    schema_version: Literal[1] = 1
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    source_git_blob_sha256: Digest
    source_sha256: Digest
    system_unshare_sha256: Digest
    parser_sha256: Digest
    private_root_created: bool = False
    private_root_identity: LinuxNativePathIdentityV1 | None = None
    private_parent_created: bool = False
    private_parent_identity: LinuxNativePathIdentityV1 | None = None
    runtime_parent_created: bool = False
    runtime_parent_identity: LinuxNativePathIdentityV1 | None = None
    private_launcher_created: bool = False
    installed_profile_created: bool = False
    profile_loaded: bool = False
    loaded_snapshot_created: bool = False
    setup_complete: bool = False
    profile_unload_started: bool = False
    profile_unloaded: bool = False
    loaded_snapshot_removal_started: bool = False
    loaded_snapshot_removed: bool = False
    installed_profile_removal_started: bool = False
    installed_profile_removed: bool = False
    private_launcher_removal_started: bool = False
    private_launcher_removed: bool = False
    private_parent_removal_started: bool = False
    private_parent_removed: bool = False
    private_root_removal_started: bool = False
    private_root_removed: bool = False
    runtime_parent_removal_started: bool = False
    runtime_parent_removed: bool = False

    @model_validator(mode="after")
    def exact_source_join(self) -> LinuxAppArmorSetupStatePayloadV1:
        if self.source_git_blob_sha256 != self.source_sha256:
            raise ValueError("AppArmor setup source differs from reviewed Git blob")
        for created, identity in (
            (self.private_root_created, self.private_root_identity),
            (self.private_parent_created, self.private_parent_identity),
            (self.runtime_parent_created, self.runtime_parent_identity),
        ):
            if identity is not None and not created:
                raise ValueError("AppArmor directory identity lacks a creation journal entry")
        if self.setup_complete and not all(
            (
                self.private_launcher_created,
                self.installed_profile_created,
                self.profile_loaded,
                self.loaded_snapshot_created,
            )
        ):
            raise ValueError("Completed AppArmor setup has missing owned objects")
        if self.setup_complete and any(
            created and identity is None
            for created, identity in (
                (self.private_root_created, self.private_root_identity),
                (self.private_parent_created, self.private_parent_identity),
                (self.runtime_parent_created, self.runtime_parent_identity),
            )
        ):
            raise ValueError("Completed AppArmor setup lacks a created-directory identity")
        if self.private_root_created and self.setup_complete and not self.private_parent_created:
            raise ValueError("Created private root lacks its owned private parent")
        if (self.profile_unload_started or self.profile_unloaded) and not self.profile_loaded:
            raise ValueError("AppArmor profile cannot be unloaded before it was loaded")
        if self.profile_unloaded and not self.profile_unload_started:
            raise ValueError("AppArmor profile unload completion lacks a pending transition")
        for created, started, removed in (
            (
                self.loaded_snapshot_created,
                self.loaded_snapshot_removal_started,
                self.loaded_snapshot_removed,
            ),
            (
                self.installed_profile_created,
                self.installed_profile_removal_started,
                self.installed_profile_removed,
            ),
            (
                self.private_launcher_created,
                self.private_launcher_removal_started,
                self.private_launcher_removed,
            ),
            (
                self.private_parent_created,
                self.private_parent_removal_started,
                self.private_parent_removed,
            ),
            (
                self.private_root_created,
                self.private_root_removal_started,
                self.private_root_removed,
            ),
            (
                self.runtime_parent_created,
                self.runtime_parent_removal_started,
                self.runtime_parent_removed,
            ),
        ):
            if (started or removed) and not created:
                raise ValueError("AppArmor cleanup transition lacks a creation journal entry")
            if removed and not started:
                raise ValueError("AppArmor cleanup completion lacks a pending transition")
        return self


class LinuxAppArmorSetupStateV1(Contract):
    linux_apparmor_setup_state_id: Digest
    payload: LinuxAppArmorSetupStatePayloadV1

    @classmethod
    def create(cls, payload: LinuxAppArmorSetupStatePayloadV1) -> LinuxAppArmorSetupStateV1:
        return cls(
            linux_apparmor_setup_state_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxAppArmorSetupStateV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_apparmor_setup_state_id != expected:
            raise ValueError("Linux AppArmor setup state hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV2(ContractV2):
    schema_version: Literal[2] = 2
    mechanics: LinuxIsolationEvidenceV2
    apparmor_cleanup: LinuxAppArmorCleanupReceiptV1
    package_readiness: Literal[False] = False

    @model_validator(mode="after")
    def exact_mechanics_cleanup_join(self) -> LinuxIsolationQualificationPayloadV2:
        profile = self.mechanics.payload.profile.payload
        cleanup = self.apparmor_cleanup.payload
        apparmor_sha256 = digest(canonical(profile.host.apparmor.model_dump(mode="json")))
        if (
            cleanup.implementation_commit != profile.implementation_commit
            or cleanup.environment_instance_id != profile.environment_instance_id
            or cleanup.linux_isolation_profile_id
            != self.mechanics.payload.profile.linux_isolation_profile_id
            or cleanup.linux_isolation_evidence_id != self.mechanics.linux_isolation_evidence_id
            or cleanup.apparmor_authority_sha256 != apparmor_sha256
        ):
            raise ValueError("Linux mechanics and AppArmor cleanup authority differ")
        return self


class LinuxAppArmorLifecycleFailurePayloadV1(Contract):
    """Sanitized authority for failures in the privileged AppArmor lifecycle."""

    schema_version: Literal[1] = 1
    receipt_kind: Literal["linux_apparmor_lifecycle_failure_v1"] = (
        "linux_apparmor_lifecycle_failure_v1"
    )
    phase: Literal["setup", "rollback", "cleanup", "finalization"]
    reason_code: Literal[
        "authority_invalid",
        "command_failed",
        "cleanup_failed",
        "join_failed",
        "unexpected_internal_failure",
    ]
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    linux_apparmor_setup_state_id: Digest | None = None
    cleanup_attempted: bool
    cleanup_succeeded: bool
    model_requests: Literal[0] = 0
    provider_sends: Literal[0] = 0
    mcp_tool_executions: Literal[0] = 0
    real_task_executions: Literal[0] = 0


class LinuxAppArmorLifecycleFailureV1(Contract):
    linux_apparmor_lifecycle_failure_id: Digest
    payload: LinuxAppArmorLifecycleFailurePayloadV1

    @classmethod
    def create(
        cls, payload: LinuxAppArmorLifecycleFailurePayloadV1
    ) -> LinuxAppArmorLifecycleFailureV1:
        return cls(
            linux_apparmor_lifecycle_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxAppArmorLifecycleFailureV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_apparmor_lifecycle_failure_id != expected:
            raise ValueError("Linux AppArmor lifecycle failure hash mismatch")
        return self


class LinuxIsolationQualificationV2(Contract):
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV2

    @classmethod
    def create(cls, payload: LinuxIsolationQualificationPayloadV2) -> LinuxIsolationQualificationV2:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV3(ContractV2):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV3
    apparmor_cleanup: LinuxAppArmorCleanupReceiptV1
    package_readiness: Literal[False] = False

    @model_validator(mode="after")
    def exact_mechanics_cleanup_join(self) -> LinuxIsolationQualificationPayloadV3:
        profile = self.mechanics.payload.profile.payload
        cleanup = self.apparmor_cleanup.payload
        apparmor_sha256 = digest(canonical(profile.host.apparmor.model_dump(mode="json")))
        if (
            cleanup.implementation_commit != profile.implementation_commit
            or cleanup.environment_instance_id != profile.environment_instance_id
            or cleanup.linux_isolation_profile_id
            != self.mechanics.payload.profile.linux_isolation_profile_id
            or cleanup.linux_isolation_evidence_id != self.mechanics.linux_isolation_evidence_id
            or cleanup.apparmor_authority_sha256 != apparmor_sha256
        ):
            raise ValueError("Linux V3 mechanics and AppArmor cleanup authority differ")
        return self


class LinuxIsolationQualificationV3(Contract):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV3

    @classmethod
    def create(cls, payload: LinuxIsolationQualificationPayloadV3) -> LinuxIsolationQualificationV3:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV3:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V3 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV4(LinuxIsolationQualificationPayloadV3):
    schema_version: Literal[4] = 4  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV4  # type: ignore[assignment]


class LinuxIsolationQualificationV4(ContractV2):
    schema_version: Literal[4] = 4  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV4

    @classmethod
    def create(cls, payload: LinuxIsolationQualificationPayloadV4) -> LinuxIsolationQualificationV4:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV4:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V4 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV5(LinuxIsolationQualificationPayloadV4):
    schema_version: Literal[5] = 5  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV5  # type: ignore[assignment]


class LinuxIsolationQualificationV5(ContractV2):
    schema_version: Literal[5] = 5  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV5

    @classmethod
    def create(cls, payload: LinuxIsolationQualificationPayloadV5) -> LinuxIsolationQualificationV5:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV5:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V5 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV6(LinuxIsolationQualificationPayloadV5):
    schema_version: Literal[6] = 6  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV6  # type: ignore[assignment]


class LinuxIsolationQualificationV6(ContractV2):
    schema_version: Literal[6] = 6  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV6

    @classmethod
    def create(cls, payload: LinuxIsolationQualificationPayloadV6) -> LinuxIsolationQualificationV6:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV6:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V6 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV7(LinuxIsolationQualificationPayloadV6):
    schema_version: Literal[7] = 7  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV7  # type: ignore[assignment]


class LinuxIsolationQualificationV7(ContractV2):
    schema_version: Literal[7] = 7  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV7

    @classmethod
    def create(cls, payload: LinuxIsolationQualificationPayloadV7) -> LinuxIsolationQualificationV7:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV7:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V7 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV8(LinuxIsolationQualificationPayloadV7):
    schema_version: Literal[8] = 8  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV8  # type: ignore[assignment]


class LinuxIsolationQualificationV8(ContractV2):
    schema_version: Literal[8] = 8  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV8

    @classmethod
    def create(cls, payload: LinuxIsolationQualificationPayloadV8) -> LinuxIsolationQualificationV8:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV8:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V8 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV9(LinuxIsolationQualificationPayloadV8):
    schema_version: Literal[9] = 9  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV9  # type: ignore[assignment]


class LinuxIsolationQualificationV9(ContractV2):
    schema_version: Literal[9] = 9  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV9

    @classmethod
    def create(cls, payload: LinuxIsolationQualificationPayloadV9) -> LinuxIsolationQualificationV9:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV9:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V9 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV10(LinuxIsolationQualificationPayloadV9):
    schema_version: Literal[10] = 10  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV10  # type: ignore[assignment]


class LinuxIsolationQualificationV10(ContractV2):
    schema_version: Literal[10] = 10  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV10

    @classmethod
    def create(
        cls, payload: LinuxIsolationQualificationPayloadV10
    ) -> LinuxIsolationQualificationV10:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV10:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V10 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV11(LinuxIsolationQualificationPayloadV10):
    schema_version: Literal[11] = 11  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV11  # type: ignore[assignment]


class LinuxIsolationQualificationV11(ContractV2):
    schema_version: Literal[11] = 11  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV11

    @classmethod
    def create(
        cls, payload: LinuxIsolationQualificationPayloadV11
    ) -> LinuxIsolationQualificationV11:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV11:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V11 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV12(LinuxIsolationQualificationPayloadV11):
    schema_version: Literal[12] = 12  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV12  # type: ignore[assignment]


class LinuxIsolationQualificationV12(ContractV2):
    schema_version: Literal[12] = 12  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV12

    @classmethod
    def create(
        cls, payload: LinuxIsolationQualificationPayloadV12
    ) -> LinuxIsolationQualificationV12:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV12:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V12 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV13(LinuxIsolationQualificationPayloadV11):
    schema_version: Literal[13] = 13  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV13  # type: ignore[assignment]


class LinuxIsolationQualificationV13(ContractV2):
    schema_version: Literal[13] = 13  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV13

    @classmethod
    def create(
        cls, payload: LinuxIsolationQualificationPayloadV13
    ) -> LinuxIsolationQualificationV13:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV13:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V13 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV14(LinuxIsolationQualificationPayloadV11):
    schema_version: Literal[14] = 14  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV14  # type: ignore[assignment]


class LinuxIsolationQualificationV14(ContractV2):
    schema_version: Literal[14] = 14  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV14

    @classmethod
    def create(
        cls, payload: LinuxIsolationQualificationPayloadV14
    ) -> LinuxIsolationQualificationV14:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV14:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V14 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV15(LinuxIsolationQualificationPayloadV11):
    schema_version: Literal[15] = 15  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV15  # type: ignore[assignment]


class LinuxIsolationQualificationV15(ContractV2):
    schema_version: Literal[15] = 15  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV15

    @classmethod
    def create(
        cls, payload: LinuxIsolationQualificationPayloadV15
    ) -> LinuxIsolationQualificationV15:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV15:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V15 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV16(LinuxIsolationQualificationPayloadV11):
    schema_version: Literal[16] = 16  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV16  # type: ignore[assignment]


class LinuxIsolationQualificationV16(ContractV2):
    schema_version: Literal[16] = 16  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV16

    @classmethod
    def create(
        cls, payload: LinuxIsolationQualificationPayloadV16
    ) -> LinuxIsolationQualificationV16:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV16:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V16 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV17(LinuxIsolationQualificationPayloadV16):
    schema_version: Literal[17] = 17  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV17  # type: ignore[assignment]
    cgroup_cleanup: LinuxCgroupCleanupReceiptV1

    @model_validator(mode="after")
    def exact_cgroup_cleanup_join(self) -> LinuxIsolationQualificationPayloadV17:
        profile = self.mechanics.payload.profile
        cleanup = self.cgroup_cleanup.payload
        if (
            cleanup.implementation_commit != profile.payload.implementation_commit
            or cleanup.environment_instance_id != profile.payload.environment_instance_id
            or cleanup.linux_isolation_profile_id != profile.linux_isolation_profile_id
            or cleanup.linux_isolation_evidence_id != self.mechanics.linux_isolation_evidence_id
            or cleanup.linux_cgroup_setup_state_id != profile.payload.cgroup_setup_state_id
            or cleanup.unit_name != profile.payload.cgroup.unit_name
            or cleanup.control_group != profile.payload.cgroup.control_group
        ):
            raise ValueError("Linux V17 mechanics and cgroup cleanup authority differ")
        return self


class LinuxIsolationQualificationV17(ContractV2):
    schema_version: Literal[17] = 17  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV17

    @classmethod
    def create(
        cls, payload: LinuxIsolationQualificationPayloadV17
    ) -> LinuxIsolationQualificationV17:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV17:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V17 qualification hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV18(LinuxIsolationQualificationPayloadV17):
    """V18 binds systemd's exact removed-empty-cgroup cleanup lifecycle."""

    schema_version: Literal[18] = 18  # type: ignore[assignment]
    cgroup_cleanup: LinuxCgroupCleanupReceiptV2  # type: ignore[assignment]


class LinuxIsolationQualificationV18(ContractV2):
    schema_version: Literal[18] = 18  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV18

    @classmethod
    def create(
        cls, payload: LinuxIsolationQualificationPayloadV18
    ) -> LinuxIsolationQualificationV18:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV18:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_qualification_id != expected:
            raise ValueError("Linux isolation V18 qualification hash mismatch")
        return self


class LinuxIsolationFailurePayloadV1(Contract):
    schema_version: Literal[1] = 1
    receipt_kind: Literal["linux_native_isolation_failure_v1"] = "linux_native_isolation_failure_v1"
    linux_isolation_profile_id: Digest | None
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    phase: Literal[
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
    reason_code: Literal[
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
    errno: Annotated[int, Field(ge=1, le=4096)] | None = None
    child_stdout_retained_sha256: Digest
    child_stderr_retained_sha256: Digest
    child_stdout_truncated: bool
    child_stderr_truncated: bool
    cleanup_attempted: bool
    cleanup_succeeded: bool
    model_requests: Literal[0] = 0
    provider_sends: Literal[0] = 0
    mcp_tool_executions: Literal[0] = 0
    real_task_executions: Literal[0] = 0


class LinuxIsolationFailureV1(Contract):
    linux_isolation_failure_id: Digest
    payload: LinuxIsolationFailurePayloadV1

    @classmethod
    def create(cls, payload: LinuxIsolationFailurePayloadV1) -> LinuxIsolationFailureV1:
        return cls(
            linux_isolation_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationFailureV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_failure_id != expected:
            raise ValueError("Linux isolation failure hash mismatch")
        return self


class LinuxIsolationFailurePayloadV2(LinuxIsolationFailurePayloadV1):
    schema_version: Literal[2] = 2  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_failure_v2"] = "linux_native_isolation_failure_v2"  # type: ignore[assignment]
    child_process_started: bool
    child_returncode: int | None
    child_stdout_retained_bytes: Annotated[int, Field(ge=0, le=1024 * 1024)]
    child_stderr_retained_bytes: Annotated[int, Field(ge=0, le=1024 * 1024)]
    child_stdout_observed_bytes: Annotated[int, Field(ge=0)]
    child_stderr_observed_bytes: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def exact_process_capture(self) -> LinuxIsolationFailurePayloadV2:
        expected_reason = {
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
        }[self.phase]
        if self.reason_code != expected_reason:
            raise ValueError("Linux failure phase and reason code differ")
        if self.cleanup_succeeded and not self.cleanup_attempted:
            raise ValueError("Linux failure claims cleanup success without an attempt")
        if self.phase in {"host_inspection", "source_revalidation"} and self.child_process_started:
            raise ValueError("Linux pre-launch failure records a started child")
        child_phases = {
            "child_registration",
            "private_root",
            "capability_drop",
            "landlock",
            "broker",
            "negative_probes",
            "child_result",
        }
        if self.phase in child_phases and not self.child_process_started:
            raise ValueError("Linux child-phase failure records an unstarted child")
        if not self.child_process_started and self.child_returncode is not None:
            raise ValueError("Linux failure records a return code for an unstarted child")
        if not self.child_process_started and (
            self.child_stdout_retained_bytes
            or self.child_stderr_retained_bytes
            or self.child_stdout_observed_bytes
            or self.child_stderr_observed_bytes
        ):
            raise ValueError("Linux failure records child output for an unstarted child")
        if self.child_process_started and self.cleanup_succeeded and self.child_returncode is None:
            raise ValueError("Linux failure lacks a return code for a cleaned-up child")
        if self.child_stdout_retained_bytes > self.child_stdout_observed_bytes:
            raise ValueError("Linux failure stdout retained bytes exceed observed bytes")
        if self.child_stderr_retained_bytes > self.child_stderr_observed_bytes:
            raise ValueError("Linux failure stderr retained bytes exceed observed bytes")
        if self.child_stdout_truncated != (
            self.child_stdout_retained_bytes < self.child_stdout_observed_bytes
        ):
            raise ValueError("Linux failure stdout truncation differs from byte counts")
        if self.child_stderr_truncated != (
            self.child_stderr_retained_bytes < self.child_stderr_observed_bytes
        ):
            raise ValueError("Linux failure stderr truncation differs from byte counts")
        empty_sha256 = digest(b"")
        if self.child_stdout_retained_bytes == 0 and (
            self.child_stdout_retained_sha256 != empty_sha256
        ):
            raise ValueError("Linux failure empty stdout hash differs")
        if self.child_stderr_retained_bytes == 0 and (
            self.child_stderr_retained_sha256 != empty_sha256
        ):
            raise ValueError("Linux failure empty stderr hash differs")
        return self


class LinuxIsolationFailureV2(ContractV2):
    schema_version: Literal[2] = 2
    linux_isolation_failure_id: Digest
    payload: LinuxIsolationFailurePayloadV2

    @classmethod
    def create(cls, payload: LinuxIsolationFailurePayloadV2) -> LinuxIsolationFailureV2:
        return cls(
            linux_isolation_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationFailureV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_failure_id != expected:
            raise ValueError("Linux isolation V2 failure hash mismatch")
        return self


class LinuxIsolationFailurePayloadV3(LinuxIsolationFailurePayloadV2):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_failure_v3"] = "linux_native_isolation_failure_v3"  # type: ignore[assignment]
    child_bootstrap_failure: LinuxChildBootstrapFailureV1 | None = None

    @model_validator(mode="after")
    def exact_child_bootstrap_failure(self) -> LinuxIsolationFailurePayloadV3:
        if self.child_bootstrap_failure is not None and (
            self.phase != "child_registration" or not self.child_process_started
        ):
            raise ValueError("Linux child bootstrap failure is attached to an invalid phase")
        return self


class LinuxIsolationFailureV3(ContractV2):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    linux_isolation_failure_id: Digest
    payload: LinuxIsolationFailurePayloadV3

    @classmethod
    def create(cls, payload: LinuxIsolationFailurePayloadV3) -> LinuxIsolationFailureV3:
        return cls(
            linux_isolation_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationFailureV3:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_failure_id != expected:
            raise ValueError("Linux isolation V3 failure hash mismatch")
        return self


class LinuxIsolationFailurePayloadV4(LinuxIsolationFailurePayloadV2):
    schema_version: Literal[4] = 4  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_failure_v4"] = "linux_native_isolation_failure_v4"  # type: ignore[assignment]
    child_bootstrap_failure: LinuxChildBootstrapFailureV2 | None = None

    @model_validator(mode="after")
    def exact_child_bootstrap_failure(self) -> LinuxIsolationFailurePayloadV4:
        if self.child_bootstrap_failure is not None and (
            self.phase != "child_registration" or not self.child_process_started
        ):
            raise ValueError("Linux V4 child bootstrap failure is attached to an invalid phase")
        return self


class LinuxIsolationFailureV4(ContractV2):
    schema_version: Literal[4] = 4  # type: ignore[assignment]
    linux_isolation_failure_id: Digest
    payload: LinuxIsolationFailurePayloadV4

    @classmethod
    def create(cls, payload: LinuxIsolationFailurePayloadV4) -> LinuxIsolationFailureV4:
        return cls(
            linux_isolation_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationFailureV4:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_failure_id != expected:
            raise ValueError("Linux isolation V4 failure hash mismatch")
        return self


class LinuxIsolationFailurePayloadV5(LinuxIsolationFailurePayloadV2):
    schema_version: Literal[5] = 5  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_failure_v5"] = "linux_native_isolation_failure_v5"  # type: ignore[assignment]
    child_bootstrap_failure: LinuxChildBootstrapFailureV3 | None = None

    @model_validator(mode="after")
    def exact_child_bootstrap_failure(self) -> LinuxIsolationFailurePayloadV5:
        if self.child_bootstrap_failure is not None and (
            self.phase != "child_registration" or not self.child_process_started
        ):
            raise ValueError("Linux V5 child bootstrap failure is attached to an invalid phase")
        return self


class LinuxIsolationFailureV5(ContractV2):
    schema_version: Literal[5] = 5  # type: ignore[assignment]
    linux_isolation_failure_id: Digest
    payload: LinuxIsolationFailurePayloadV5

    @classmethod
    def create(cls, payload: LinuxIsolationFailurePayloadV5) -> LinuxIsolationFailureV5:
        return cls(
            linux_isolation_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationFailureV5:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_failure_id != expected:
            raise ValueError("Linux isolation V5 failure hash mismatch")
        return self


class LinuxIsolationFailurePayloadV6(LinuxIsolationFailurePayloadV2):
    schema_version: Literal[6] = 6  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_failure_v6"] = "linux_native_isolation_failure_v6"  # type: ignore[assignment]
    child_bootstrap_failure: LinuxChildBootstrapFailureV3 | None = None
    child_runtime_failure: LinuxChildRuntimeFailureV1 | None = None

    @model_validator(mode="after")
    def exact_child_failure(self) -> LinuxIsolationFailurePayloadV6:
        cleanup_overrides_primary = (
            self.phase == "cleanup" and self.cleanup_attempted and not self.cleanup_succeeded
        )
        if self.child_bootstrap_failure is not None:
            if (
                self.phase != "child_registration" and not cleanup_overrides_primary
            ) or not self.child_process_started:
                raise ValueError("Linux V6 bootstrap failure is attached to an invalid phase")
            if self.child_returncode != 70:
                raise ValueError("Linux V6 bootstrap failure has an unexpected return code")
        if self.child_runtime_failure is not None:
            expected_phase = {
                "private_root": "private_root",
                "rlimits": "child_result",
                "capability_drop": "capability_drop",
                "landlock": "landlock",
                "negative_probes": "negative_probes",
                "broker": "broker",
                "result_assembly": "child_result",
            }[self.child_runtime_failure.payload.stage]
            if (
                self.phase != expected_phase and not cleanup_overrides_primary
            ) or not self.child_process_started:
                raise ValueError("Linux V6 runtime failure is attached to an invalid phase")
            if self.child_returncode != 71:
                raise ValueError("Linux V6 runtime failure has an unexpected return code")
        if self.child_bootstrap_failure is not None and self.child_runtime_failure is not None:
            raise ValueError("Linux V6 failure records two child failure authorities")
        return self


class LinuxIsolationFailureV6(ContractV2):
    schema_version: Literal[6] = 6  # type: ignore[assignment]
    linux_isolation_failure_id: Digest
    payload: LinuxIsolationFailurePayloadV6

    @classmethod
    def create(cls, payload: LinuxIsolationFailurePayloadV6) -> LinuxIsolationFailureV6:
        return cls(
            linux_isolation_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationFailureV6:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_failure_id != expected:
            raise ValueError("Linux isolation V6 failure hash mismatch")
        return self


class LinuxIsolationFailurePayloadV7(LinuxIsolationFailurePayloadV2):
    schema_version: Literal[7] = 7  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_failure_v7"] = "linux_native_isolation_failure_v7"  # type: ignore[assignment]
    child_bootstrap_failure: LinuxChildBootstrapFailureV3 | None = None
    child_runtime_failure: LinuxChildRuntimeFailureV2 | None = None
    host_broker_failure: LinuxHostBrokerFailureV1 | None = None

    @model_validator(mode="after")
    def exact_diagnostics(self) -> LinuxIsolationFailurePayloadV7:
        cleanup_overrides_primary = (
            self.phase == "cleanup" and self.cleanup_attempted and not self.cleanup_succeeded
        )
        if self.child_bootstrap_failure is not None:
            if (
                self.phase != "child_registration" and not cleanup_overrides_primary
            ) or not self.child_process_started:
                raise ValueError("Linux V7 bootstrap failure is attached to an invalid phase")
            if self.child_returncode != 70:
                raise ValueError("Linux V7 bootstrap failure has an unexpected return code")
        if self.child_runtime_failure is not None:
            expected_phase = {
                "private_root": "private_root",
                "rlimits": "child_result",
                "capability_drop": "capability_drop",
                "landlock": "landlock",
                "negative_probes": "negative_probes",
                "broker": "broker",
                "result_assembly": "child_result",
            }[self.child_runtime_failure.payload.stage]
            if (
                self.phase != expected_phase and not cleanup_overrides_primary
            ) or not self.child_process_started:
                raise ValueError("Linux V7 runtime failure is attached to an invalid phase")
            if self.child_returncode != 71:
                raise ValueError("Linux V7 runtime failure has an unexpected return code")
        if self.host_broker_failure is not None and (
            (self.phase != "broker" and not cleanup_overrides_primary)
            or not self.child_process_started
        ):
            raise ValueError("Linux V7 host broker failure is attached to an invalid phase")
        if self.phase == "broker" and (
            self.child_runtime_failure is None and self.host_broker_failure is None
        ):
            raise ValueError("Linux V7 broker failure lacks typed diagnostics")
        if self.child_bootstrap_failure is not None and (
            self.child_runtime_failure is not None or self.host_broker_failure is not None
        ):
            raise ValueError("Linux V7 bootstrap failure conflicts with runtime diagnostics")
        if (
            self.host_broker_failure is not None
            and self.child_runtime_failure is not None
            and self.child_runtime_failure.payload.stage != "broker"
        ):
            raise ValueError("Linux V7 host/child broker diagnostics are inconsistent")
        for diagnostic in (self.child_runtime_failure, self.host_broker_failure):
            if diagnostic is not None and (
                diagnostic.payload.linux_isolation_profile_id != self.linux_isolation_profile_id
                or diagnostic.payload.environment_instance_id != self.environment_instance_id
            ):
                raise ValueError("Linux V7 diagnostic authority differs from the outer failure")
        return self


class LinuxIsolationFailureV7(ContractV2):
    schema_version: Literal[7] = 7  # type: ignore[assignment]
    linux_isolation_failure_id: Digest
    payload: LinuxIsolationFailurePayloadV7

    @classmethod
    def create(cls, payload: LinuxIsolationFailurePayloadV7) -> LinuxIsolationFailureV7:
        return cls(
            linux_isolation_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationFailureV7:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_failure_id != expected:
            raise ValueError("Linux isolation V7 failure hash mismatch")
        return self


class LinuxIsolationFailurePayloadV8(LinuxIsolationFailurePayloadV7):
    """V14 failure envelope carrying the fixed V3 packaged-child diagnostic."""

    schema_version: Literal[8] = 8  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_failure_v8"] = "linux_native_isolation_failure_v8"  # type: ignore[assignment]
    child_runtime_failure: LinuxChildRuntimeFailureV3 | None = None  # type: ignore[assignment]


class LinuxIsolationFailureV8(ContractV2):
    schema_version: Literal[8] = 8  # type: ignore[assignment]
    linux_isolation_failure_id: Digest
    payload: LinuxIsolationFailurePayloadV8

    @classmethod
    def create(cls, payload: LinuxIsolationFailurePayloadV8) -> LinuxIsolationFailureV8:
        return cls(
            linux_isolation_failure_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationFailureV8:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_isolation_failure_id != expected:
            raise ValueError("Linux isolation V8 failure hash mismatch")
        return self


# V19 is forward-only.  V1-V18 remain parseable historical authority.


class LinuxSystemdAnalyzeAuthorityV1(LinuxFileAuthorityV1):
    name: Literal["systemd-analyze"] = "systemd-analyze"
    locator: Literal["/usr/bin/systemd-analyze"] = LINUX_SYSTEMD_ANALYZE
    version_output_sha256: Digest

    @model_validator(mode="after")
    def exact_reviewed_tool(self) -> LinuxSystemdAnalyzeAuthorityV1:
        mode = int(self.mode, 8)
        if self.owner_uid != 0 or self.owner_gid != 0:
            raise ValueError("systemd-analyze must be root-owned")
        if mode & 0o022 or not mode & 0o100 or mode & 0o7000:
            raise ValueError("systemd-analyze mode is unsafe")
        if self.version_output_sha256 != LINUX_REVIEWED_SYSTEMD_VERSION_SHA256:
            raise ValueError("systemd-analyze version is not the reviewed V19 authority")
        return self


class LinuxSystemdManagerAuthorityV1(Contract):
    executable: LinuxFileAuthorityV1
    pid: Literal[1] = 1
    start_time_ticks: Annotated[int, Field(ge=1)]
    boot_id: Annotated[
        str,
        Field(pattern=r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"),
    ]
    version_output_sha256: Digest

    @model_validator(mode="after")
    def exact_reviewed_manager(self) -> LinuxSystemdManagerAuthorityV1:
        executable = self.executable
        mode = int(executable.mode, 8)
        if (
            executable.locator != LINUX_SYSTEMD_MANAGER
            or executable.owner_uid != 0
            or executable.owner_gid != 0
            or mode & 0o022
            or not mode & 0o100
            or mode & 0o7000
        ):
            raise ValueError("PID 1 systemd executable authority differs")
        if self.version_output_sha256 != LINUX_REVIEWED_SYSTEMD_VERSION_SHA256:
            raise ValueError("PID 1 systemd version is not the reviewed V19 authority")
        return self


class LinuxSyscallAllowlistAuthorityV1(Contract):
    """Pre-authorized selector expansion installed as explicit syscall names."""

    selectors: tuple[Literal["@system-service"], Literal["@mount"], Literal["@sandbox"]] = (
        "@system-service",
        "@mount",
        "@sandbox",
    )
    explicit_exclusions: tuple[Literal["personality"]] = ("personality",)
    configured_explicit_allowlist: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z0-9_]+$")], ...],
        Field(min_length=LINUX_SYSCALL_ALLOWLIST_COUNT),
    ]
    configured_allowlist_sha256: Digest
    selector_outputs_sha256: Digest
    systemd_analyze: LinuxSystemdAnalyzeAuthorityV1
    systemd_manager: LinuxSystemdManagerAuthorityV1
    implicit_lifecycle_syscalls: tuple[
        Literal["execve"],
        Literal["exit"],
        Literal["exit_group"],
        Literal["rt_sigreturn"],
        Literal["sigreturn"],
    ] = ("execve", "exit", "exit_group", "rt_sigreturn", "sigreturn")

    @model_validator(mode="after")
    def exact_pre_authorized_expansion(self) -> LinuxSyscallAllowlistAuthorityV1:
        names = self.configured_explicit_allowlist
        if names != tuple(sorted(set(names))):
            raise ValueError("Configured syscall allowlist is not sorted and unique")
        if len(names) != LINUX_SYSCALL_ALLOWLIST_COUNT or "personality" in names:
            raise ValueError("Configured syscall allowlist differs from reviewed V19 expansion")
        observed = syscall_allowlist_sha256(names)
        if (
            self.configured_allowlist_sha256 != observed
            or observed != LINUX_SYSCALL_ALLOWLIST_SHA256
        ):
            raise ValueError("Configured syscall allowlist hash differs")
        if not set(self.implicit_lifecycle_syscalls).issubset(names):
            raise ValueError("Systemd implicit lifecycle syscalls are not explicitly authorized")
        if self.systemd_analyze.version_output_sha256 != self.systemd_manager.version_output_sha256:
            raise ValueError("systemd analyzer and manager versions differ")
        return self


class LinuxMatchedControlAuthorityV1(Contract):
    unit_name: Annotated[
        str,
        Field(pattern=r"^devfabric-linux-isolation-control-[a-f0-9]{32}\.service$"),
    ]
    control_group: Annotated[
        str,
        Field(pattern=r"^/system\.slice/devfabric-linux-isolation-control-[a-f0-9]{32}\.service$"),
    ]
    service_uid: Annotated[int, Field(ge=1)]
    service_gid: Annotated[int, Field(ge=1)]
    no_new_privileges: Literal[True] = True
    system_call_architectures: tuple[Literal["native"]] = ("native",)
    syscall_filter_configured: Literal[False] = False
    limits: LinuxCgroupLimitsV1 = LinuxCgroupLimitsV1()

    @model_validator(mode="after")
    def exact_control_group(self) -> LinuxMatchedControlAuthorityV1:
        if self.control_group != f"/system.slice/{self.unit_name}":
            raise ValueError("Matched control unit and cgroup differ")
        return self


class LinuxSyscallFilterBoundaryAuthorityV1(Contract):
    policy: LinuxSyscallAllowlistAuthorityV1
    no_new_privileges: Literal[True] = True
    system_call_architectures: tuple[Literal["native"]] = ("native",)
    system_call_error_number: Literal["EPERM"] = "EPERM"
    matched_control: LinuxMatchedControlAuthorityV1


class LinuxCgroupSetupStatePayloadV2(LinuxCgroupSetupStatePayloadV1):
    schema_version: Literal[2] = 2  # type: ignore[assignment]
    state_kind: Literal["linux_cgroup_setup_state_v2"] = "linux_cgroup_setup_state_v2"  # type: ignore[assignment]
    syscall_filter: LinuxSyscallFilterBoundaryAuthorityV1

    @model_validator(mode="after")
    def exact_target_control_join(self) -> LinuxCgroupSetupStatePayloadV2:
        control = self.syscall_filter.matched_control
        if (
            control.service_uid != self.boundary.service_uid
            or control.service_gid != self.boundary.service_gid
            or control.limits != self.boundary.limits
            or not control.unit_name.endswith(f"{self.environment_instance_id}.service")
        ):
            raise ValueError("Matched control authority differs from target authority")
        version = self.syscall_filter.policy.systemd_manager.version_output_sha256
        if (
            self.boundary.systemd_run.version_output_sha256 != version
            or self.boundary.systemctl.version_output_sha256 != version
        ):
            raise ValueError("systemd client and manager lineages differ")
        return self


class LinuxCgroupSetupStateV2(ContractV2):
    schema_version: Literal[2] = 2
    linux_cgroup_setup_state_id: Digest
    payload: LinuxCgroupSetupStatePayloadV2

    @classmethod
    def create(cls, payload: LinuxCgroupSetupStatePayloadV2) -> LinuxCgroupSetupStateV2:
        return cls(
            linux_cgroup_setup_state_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxCgroupSetupStateV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.linux_cgroup_setup_state_id != expected:
            raise ValueError("Linux cgroup setup V2 state hash mismatch")
        return self


class LinuxRawPersonalityObservationV1(Contract):
    syscall_number: Literal[135] = 135
    argument: Literal[4294967295] = 4294967295
    result: int
    observed_errno: Annotated[int, Field(ge=0)]


class LinuxMatchedControlObservationV1(Contract):
    schema_version: Literal[1] = 1
    observation_kind: Literal["linux_syscall_matched_control_observation_v1"] = (
        "linux_syscall_matched_control_observation_v1"
    )
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    linux_cgroup_setup_state_id: Digest
    unit_name: Annotated[
        str,
        Field(pattern=r"^devfabric-linux-isolation-control-[a-f0-9]{32}\.service$"),
    ]
    control_group: Annotated[
        str,
        Field(pattern=r"^/system\.slice/devfabric-linux-isolation-control-[a-f0-9]{32}\.service$"),
    ]
    cgroup_native_identity: LinuxNativePathIdentityV1
    memory_max: Literal["2147483648"] = LINUX_CGROUP_MEMORY_MAX
    pids_max: Literal["128"] = LINUX_CGROUP_PIDS_MAX
    cpu_max: Literal["200000 100000"] = LINUX_CGROUP_CPU_MAX
    sole_cgroup_member: Literal[True] = True
    personality: LinuxRawPersonalityObservationV1
    no_new_privs: Literal[1] = 1
    seccomp_mode: Literal[2] = 2
    seccomp_filters: Annotated[int, Field(ge=1)]

    @model_validator(mode="after")
    def personality_succeeded(self) -> LinuxMatchedControlObservationV1:
        if self.personality.result < 0 or self.personality.observed_errno != 0:
            raise ValueError("Matched control personality syscall did not succeed")
        return self


class LinuxSystemdResourcePolicyObservationV1(Contract):
    service_uid: Annotated[int, Field(ge=1)]
    service_gid: Annotated[int, Field(ge=1)]
    memory_max: Literal["2147483648"] = LINUX_CGROUP_MEMORY_MAX
    tasks_max: Literal["128"] = LINUX_CGROUP_PIDS_MAX
    cpu_quota_per_sec_usec: Literal[2_000_000] = 2_000_000
    cpu_quota_period_usec: Literal[100_000] = 100_000


class LinuxSystemdUnitPolicyObservationV1(Contract):
    unit_name: Annotated[
        str, Field(pattern=r"^devfabric-linux-isolation(?:-control)?-[a-f0-9]{32}\.service$")
    ]
    no_new_privileges: Literal["yes"] = "yes"
    system_call_architectures: tuple[Literal["native"]] = ("native",)
    system_call_error_number: Literal[1] = 1
    filter_is_allowlist: Literal[True] = True
    systemd_reported_filter: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z0-9_]+$")], ...], Field(min_length=1)
    ]
    systemd_reported_filter_sha256: Digest
    raw_properties_sha256: Digest
    resources: LinuxSystemdResourcePolicyObservationV1

    @model_validator(mode="after")
    def exact_reported_filter_hash(self) -> LinuxSystemdUnitPolicyObservationV1:
        names = self.systemd_reported_filter
        if names != tuple(sorted(set(names))) or "personality" in names:
            raise ValueError("systemd reported syscall filter is invalid")
        if self.systemd_reported_filter_sha256 != digest(canonical(list(names))):
            raise ValueError("systemd reported syscall-filter hash differs")
        return self


class LinuxSystemdControlPolicyObservationV1(Contract):
    unit_name: Annotated[
        str,
        Field(pattern=r"^devfabric-linux-isolation-control-[a-f0-9]{32}\.service$"),
    ]
    no_new_privileges: Literal["yes"] = "yes"
    system_call_architectures: tuple[Literal["native"]] = ("native",)
    system_call_error_number: Annotated[str, Field(max_length=32)]
    filter_is_allowlist: Literal[False] = False
    systemd_reported_filter: tuple[()] = ()
    raw_properties_sha256: Digest
    resources: LinuxSystemdResourcePolicyObservationV1


class LinuxMatchedControlExecutionPayloadV1(Contract):
    schema_version: Literal[1] = 1
    authority_kind: Literal["linux_syscall_matched_control_execution_v1"] = (
        "linux_syscall_matched_control_execution_v1"
    )
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    linux_cgroup_setup_state_id: Digest
    python: LinuxFileAuthorityV1
    manager_script: LinuxFileAuthorityV1
    manager_script_git_blob_sha256: Digest
    state_locator: Annotated[str, Field(pattern=r"^/[^\r\n]+$")]
    state_sha256: Digest
    execution_authority_locator: Annotated[str, Field(pattern=r"^/[^\r\n]+$")]
    observation_locator: Annotated[str, Field(pattern=r"^/[^\r\n]+$")]
    argv: Annotated[tuple[Annotated[str, Field(min_length=1)], ...], Field(min_length=9)]

    @model_validator(mode="after")
    def exact_argv(self) -> LinuxMatchedControlExecutionPayloadV1:
        expected = (
            self.python.locator,
            self.manager_script.locator,
            "control-probe-v19",
            "--state",
            self.state_locator,
            "--execution-authority",
            self.execution_authority_locator,
            "--output",
            self.observation_locator,
        )
        if self.argv != expected:
            raise ValueError("Matched control execution argv differs")
        return self


class LinuxMatchedControlExecutionV1(ContractV2):
    schema_version: Literal[1] = 1  # type: ignore[assignment]
    linux_matched_control_execution_id: Digest
    payload: LinuxMatchedControlExecutionPayloadV1

    @classmethod
    def create(
        cls, payload: LinuxMatchedControlExecutionPayloadV1
    ) -> LinuxMatchedControlExecutionV1:
        return cls(
            linux_matched_control_execution_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxMatchedControlExecutionV1:
        if self.linux_matched_control_execution_id != digest(
            canonical(self.payload.model_dump(mode="json"))
        ):
            raise ValueError("Matched control execution authority hash mismatch")
        return self


class LinuxMatchedControlReceiptPayloadV1(Contract):
    schema_version: Literal[1] = 1
    receipt_kind: Literal["linux_syscall_matched_control_receipt_v1"] = (
        "linux_syscall_matched_control_receipt_v1"
    )
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    linux_cgroup_setup_state_id: Digest
    authority: LinuxMatchedControlAuthorityV1
    execution: LinuxMatchedControlExecutionV1
    observation: LinuxMatchedControlObservationV1
    unit_policy: LinuxSystemdControlPolicyObservationV1
    exact_unit_cleanup_verified: Literal[True] = True

    @model_validator(mode="after")
    def exact_control_join(self) -> LinuxMatchedControlReceiptPayloadV1:
        if (
            self.observation.implementation_commit != self.implementation_commit
            or self.observation.environment_instance_id != self.environment_instance_id
            or self.observation.linux_cgroup_setup_state_id != self.linux_cgroup_setup_state_id
            or self.observation.unit_name != self.authority.unit_name
            or self.unit_policy.unit_name != self.authority.unit_name
            or self.unit_policy.systemd_reported_filter
            or self.observation.control_group != self.authority.control_group
            or self.execution.payload.implementation_commit != self.implementation_commit
            or self.execution.payload.environment_instance_id != self.environment_instance_id
            or self.execution.payload.linux_cgroup_setup_state_id
            != self.linux_cgroup_setup_state_id
            or self.unit_policy.resources.service_uid != self.authority.service_uid
            or self.unit_policy.resources.service_gid != self.authority.service_gid
            or self.observation.memory_max != self.authority.limits.memory_max
            or self.observation.pids_max != self.authority.limits.pids_max
            or self.observation.cpu_max != self.authority.limits.cpu_max
        ):
            raise ValueError("Matched control receipt authority differs")
        return self


class LinuxMatchedControlReceiptV1(ContractV2):
    schema_version: Literal[1] = 1  # type: ignore[assignment]
    linux_syscall_matched_control_receipt_id: Digest
    payload: LinuxMatchedControlReceiptPayloadV1

    @classmethod
    def create(cls, payload: LinuxMatchedControlReceiptPayloadV1) -> LinuxMatchedControlReceiptV1:
        return cls(
            linux_syscall_matched_control_receipt_id=digest(
                canonical(payload.model_dump(mode="json"))
            ),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxMatchedControlReceiptV1:
        if self.linux_syscall_matched_control_receipt_id != digest(
            canonical(self.payload.model_dump(mode="json"))
        ):
            raise ValueError("Matched control receipt hash mismatch")
        return self


class LinuxSeccompProcessObservationV1(LinuxCgroupMemberObservationV1):
    no_new_privs: Literal[1] = 1
    seccomp_mode: Literal[2] = 2
    seccomp_filters: Annotated[int, Field(ge=1)]


class LinuxCgroupBoundaryObservationV2(LinuxCgroupBoundaryObservationV1):
    observed_members: Annotated[tuple[LinuxSeccompProcessObservationV1, ...], Field(min_length=3)]

    @model_validator(mode="after")
    def exact_filter_inheritance(self) -> LinuxCgroupBoundaryObservationV2:
        counts = {member.seccomp_filters for member in self.observed_members}
        if len(counts) != 1:
            raise ValueError("Seccomp filter count differs across the observed process tree")
        return self


class LinuxSyscallFilterObservationV1(Contract):
    personality: LinuxRawPersonalityObservationV1
    configured_allowlist_sha256: Digest

    @model_validator(mode="after")
    def personality_denied(self) -> LinuxSyscallFilterObservationV1:
        if self.personality.result != -1 or self.personality.observed_errno != 1:
            raise ValueError("Target personality syscall was not denied with EPERM")
        if self.configured_allowlist_sha256 != LINUX_SYSCALL_ALLOWLIST_SHA256:
            raise ValueError("Target syscall allowlist authority differs")
        return self


class LinuxIsolationProfilePayloadV18(LinuxIsolationProfilePayloadV17):
    schema_version: Literal[18] = 18  # type: ignore[assignment]
    profile_kind: Literal["linux_native_isolation_v18"] = "linux_native_isolation_v18"  # type: ignore[assignment]
    syscall_filter: LinuxSyscallFilterBoundaryAuthorityV1
    matched_control: LinuxMatchedControlReceiptV1

    @model_validator(mode="after")
    def exact_syscall_authority_join(self) -> LinuxIsolationProfilePayloadV18:
        control = self.matched_control.payload
        if (
            control.environment_instance_id != self.environment_instance_id
            or control.implementation_commit != self.implementation_commit
            or control.linux_cgroup_setup_state_id != self.cgroup_setup_state_id
            or control.authority != self.syscall_filter.matched_control
        ):
            raise ValueError("Linux V18 matched-control authority differs")
        return self


class LinuxIsolationProfileV18(ContractV2):
    schema_version: Literal[18] = 18  # type: ignore[assignment]
    linux_isolation_profile_id: Digest
    payload: LinuxIsolationProfilePayloadV18

    @classmethod
    def create(cls, payload: LinuxIsolationProfilePayloadV18) -> LinuxIsolationProfileV18:
        return cls(
            linux_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationProfileV18:
        if self.linux_isolation_profile_id != digest(
            canonical(self.payload.model_dump(mode="json"))
        ):
            raise ValueError("Linux isolation V18 profile hash mismatch")
        return self


class LinuxIsolationObservationV18(LinuxIsolationObservationV16):
    schema_version: Literal[18] = 18  # type: ignore[assignment]
    cgroup: LinuxCgroupBoundaryObservationV2
    syscall_filter: LinuxSyscallFilterObservationV1


class LinuxIsolationReceiptPayloadV18(LinuxIsolationReceiptPayloadV16):
    schema_version: Literal[18] = 18  # type: ignore[assignment]
    receipt_kind: Literal["linux_native_isolation_receipt_v18"] = (
        "linux_native_isolation_receipt_v18"  # type: ignore[assignment]
    )
    observation: LinuxIsolationObservationV18
    cgroup_resource_boundary_qualified: Literal[True] = True  # type: ignore[assignment]
    syscall_filter_qualified: Literal[True] = True  # type: ignore[assignment]


class LinuxIsolationReceiptV18(ContractV2):
    schema_version: Literal[18] = 18  # type: ignore[assignment]
    linux_isolation_receipt_id: Digest
    payload: LinuxIsolationReceiptPayloadV18

    @classmethod
    def create(cls, payload: LinuxIsolationReceiptPayloadV18) -> LinuxIsolationReceiptV18:
        return cls(
            linux_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationReceiptV18:
        if self.linux_isolation_receipt_id != digest(
            canonical(self.payload.model_dump(mode="json"))
        ):
            raise ValueError("Linux isolation V18 receipt hash mismatch")
        return self


class LinuxIsolationEvidencePayloadV18(LinuxIsolationEvidencePayloadV16):
    schema_version: Literal[18] = 18  # type: ignore[assignment]
    profile: LinuxIsolationProfileV18  # type: ignore[assignment]
    receipt: LinuxIsolationReceiptV18  # type: ignore[assignment]

    @model_validator(mode="after")
    def exact_v19_mechanics_join(self) -> LinuxIsolationEvidencePayloadV18:
        authority = self.profile.payload
        observed = self.receipt.payload.observation
        if (
            observed.cgroup.setup_state_id != authority.cgroup_setup_state_id
            or observed.cgroup.control_group != authority.cgroup.control_group
            or observed.syscall_filter.configured_allowlist_sha256
            != authority.syscall_filter.policy.configured_allowlist_sha256
        ):
            raise ValueError("Linux V19 mechanics authority differs")
        return self


class LinuxIsolationEvidenceV18(ContractV2):
    schema_version: Literal[18] = 18  # type: ignore[assignment]
    linux_isolation_evidence_id: Digest
    payload: LinuxIsolationEvidencePayloadV18

    @classmethod
    def create(cls, payload: LinuxIsolationEvidencePayloadV18) -> LinuxIsolationEvidenceV18:
        return cls(
            linux_isolation_evidence_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationEvidenceV18:
        if self.linux_isolation_evidence_id != digest(
            canonical(self.payload.model_dump(mode="json"))
        ):
            raise ValueError("Linux isolation V18 evidence hash mismatch")
        return self


class LinuxCgroupCleanupPayloadV3(LinuxCgroupCleanupPayloadV2):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    receipt_kind: Literal["linux_cgroup_cleanup_receipt_v3"] = "linux_cgroup_cleanup_receipt_v3"  # type: ignore[assignment]
    unit_policy: LinuxSystemdUnitPolicyObservationV1
    target_unit_absent: Literal[True] = True
    target_cgroup_absent: Literal[True] = True
    control_unit_name: Annotated[
        str,
        Field(pattern=r"^devfabric-linux-isolation-control-[a-f0-9]{32}\.service$"),
    ]
    control_control_group: Annotated[
        str,
        Field(pattern=r"^/system\.slice/devfabric-linux-isolation-control-[a-f0-9]{32}\.service$"),
    ]
    control_unit_absent: Literal[True] = True
    control_cgroup_absent: Literal[True] = True


class LinuxCgroupCleanupReceiptV3(ContractV2):
    schema_version: Literal[3] = 3  # type: ignore[assignment]
    linux_cgroup_cleanup_receipt_id: Digest
    payload: LinuxCgroupCleanupPayloadV3

    @classmethod
    def create(cls, payload: LinuxCgroupCleanupPayloadV3) -> LinuxCgroupCleanupReceiptV3:
        return cls(
            linux_cgroup_cleanup_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxCgroupCleanupReceiptV3:
        if self.linux_cgroup_cleanup_receipt_id != digest(
            canonical(self.payload.model_dump(mode="json"))
        ):
            raise ValueError("Linux cgroup cleanup V3 receipt hash mismatch")
        return self


class LinuxIsolationQualificationPayloadV19(LinuxIsolationQualificationPayloadV16):
    schema_version: Literal[19] = 19  # type: ignore[assignment]
    mechanics: LinuxIsolationEvidenceV18  # type: ignore[assignment]
    cgroup_cleanup: LinuxCgroupCleanupReceiptV3
    syscall_filter_qualified: Literal[True] = True
    cgroup_resource_boundary_qualified: Literal[True] = True
    native_executor_isolation_qualified: Literal[False] = False
    package_readiness: Literal[False] = False

    @model_validator(mode="after")
    def exact_v19_join(self) -> LinuxIsolationQualificationPayloadV19:
        profile = self.mechanics.payload.profile
        cleanup = self.cgroup_cleanup.payload
        policy = profile.payload.syscall_filter.policy
        if (
            cleanup.implementation_commit != profile.payload.implementation_commit
            or cleanup.environment_instance_id != profile.payload.environment_instance_id
            or cleanup.linux_isolation_profile_id != profile.linux_isolation_profile_id
            or cleanup.linux_isolation_evidence_id != self.mechanics.linux_isolation_evidence_id
            or cleanup.linux_cgroup_setup_state_id != profile.payload.cgroup_setup_state_id
            or cleanup.unit_name != profile.payload.cgroup.unit_name
            or cleanup.control_group != profile.payload.cgroup.control_group
            or cleanup.unit_policy.unit_name != profile.payload.cgroup.unit_name
            or cleanup.unit_policy.systemd_reported_filter != policy.configured_explicit_allowlist
            or cleanup.control_unit_name != profile.payload.syscall_filter.matched_control.unit_name
            or cleanup.control_control_group
            != profile.payload.syscall_filter.matched_control.control_group
        ):
            raise ValueError("Linux V19 mechanics, policy and cleanup authority differ")
        return self


class LinuxCgroupRollbackPayloadV2(LinuxCgroupRollbackPayloadV1):
    """Forward V19 rollback result for both exact transient authorities."""

    schema_version: Literal[2] = 2  # type: ignore[assignment]
    receipt_kind: Literal["linux_cgroup_rollback_receipt_v2"] = "linux_cgroup_rollback_receipt_v2"  # type: ignore[assignment]
    control_unit_name: Annotated[
        str,
        Field(pattern=r"^devfabric-linux-isolation-control-[a-f0-9]{32}\.service$"),
    ]
    control_control_group: Annotated[
        str,
        Field(pattern=r"^/system\.slice/devfabric-linux-isolation-control-[a-f0-9]{32}\.service$"),
    ]
    control_unit_absent: bool
    control_cgroup_absent: bool

    @model_validator(mode="after")
    def truthful_complete_success(self) -> LinuxCgroupRollbackPayloadV2:
        expected = (
            self.unit_absent
            and self.cgroup_absent
            and self.control_unit_absent
            and self.control_cgroup_absent
        )
        if self.cleanup_succeeded != expected:
            raise ValueError("Linux V19 rollback success differs from absence observations")
        return self


class LinuxCgroupRollbackReceiptV2(ContractV2):
    schema_version: Literal[2] = 2
    linux_cgroup_rollback_receipt_id: Digest
    payload: LinuxCgroupRollbackPayloadV2

    @classmethod
    def create(cls, payload: LinuxCgroupRollbackPayloadV2) -> LinuxCgroupRollbackReceiptV2:
        return cls(
            linux_cgroup_rollback_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxCgroupRollbackReceiptV2:
        if self.linux_cgroup_rollback_receipt_id != digest(
            canonical(self.payload.model_dump(mode="json"))
        ):
            raise ValueError("Linux V19 rollback receipt hash mismatch")
        return self


class LinuxIsolationQualificationV19(ContractV2):
    schema_version: Literal[19] = 19  # type: ignore[assignment]
    linux_isolation_qualification_id: Digest
    payload: LinuxIsolationQualificationPayloadV19

    @classmethod
    def create(
        cls, payload: LinuxIsolationQualificationPayloadV19
    ) -> LinuxIsolationQualificationV19:
        return cls(
            linux_isolation_qualification_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> LinuxIsolationQualificationV19:
        if self.linux_isolation_qualification_id != digest(
            canonical(self.payload.model_dump(mode="json"))
        ):
            raise ValueError("Linux isolation V19 qualification hash mismatch")
        return self
