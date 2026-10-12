"""Strict contracts for the native Linux isolation qualification baseline.

The contracts in this module describe one exact Linux host and one closed
namespace launch.  They intentionally do not turn a native bundle into an
execution-ready package: cgroup and syscall-filter qualification remain
separate required gates.
"""

from __future__ import annotations

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
LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15
LANDLOCK_ACCESS_FS_ABI3 = (1 << 15) - 1
MINIMUM_REVIEWED_LANDLOCK_ABI = 3
MAXIMUM_REVIEWED_LANDLOCK_ABI = 6


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
