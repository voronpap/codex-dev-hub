"""Fail-closed Windows AppContainer launch and qualification contracts.

This module is a native execution profile.  It does not alter the historical
Linux/OCI Stage 3G protocol.  The sandboxed process receives no network or
registry capability and starts suspended so the coordinator can place it in a
non-breakaway Job Object before any guest instruction executes.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import os
import platform
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Annotated, Literal, cast

import flatbuffers  # type: ignore[import-untyped]
from pydantic import Field, JsonValue, field_validator, model_validator

from devhub.benchmark import Digest, canonical, digest
from devhub.models import Contract

WINDOWS_SANDBOX_SPEC_VERSION = "0.1.0"
WINDOWS_SANDBOX_FILE_IDENTIFIER = b"SBOX"
WINDOWS_SANDBOX_API = "Experimental_CreateProcessInSandbox"
WINDOWS_MINIMUM_BUILD = 26100
WINDOWS_X64 = "x86_64"
NO_DIRECT_NETWORK = "appcontainer_no_capabilities"
ISOLATED_REGISTRY = "appcontainer_private_no_registry_capability"
NO_HANDLE_INHERITANCE = "inherit_handles_false"

_HEX_32 = re.compile(r"^[a-f0-9]{32}$")
_PROFILE_NAME = re.compile(r"^devfabric_[a-f0-9]{32}$")


def _windows_last_error() -> int:
    """Return the Win32 thread-local last-error value without Linux stubs."""

    getter = getattr(ctypes, "get_last_error", None)
    if not callable(getter):
        raise RuntimeError("ctypes.get_last_error is unavailable on this platform")
    return int(getter())


# Identity of the reviewed Microsoft ``BaseContainerSpecification.fbs`` wire
# layout used here.  It binds every slot rather than a mutable URL or filename.
WINDOWS_SANDBOX_SCHEMA_IDENTITY = digest(
    canonical(
        {
            "file_identifier": "SBOX",
            "root_type": "SandboxSpec",
            "schema_version": WINDOWS_SANDBOX_SPEC_VERSION,
            "slots": [
                ["version", "string", None],
                ["app_container", "bool", False],
                ["integrity_level", "uint32", 0],
                ["disallow_win32k_system_calls", "bool", False],
                ["ui_restrictions", "uint64", 0],
                ["least_privilege", "bool", False],
                ["capabilities", "string", None],
                ["fs_read_write", "vector<string>", None],
                ["fs_read_only", "vector<string>", None],
                ["network_policy", "NetworkPolicy", None],
                ["integrity", "byte", 0],
                ["fs_deny", "vector<string>", None],
            ],
        }
    )
)


class NativePathIdentityV1(Contract):
    """Stable identity for one already-created native directory locator."""

    locator: Annotated[str, Field(min_length=3, max_length=4096)]
    volume_serial_number: Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
    file_index: Annotated[str, Field(pattern=r"^[a-f0-9]{16}$")]


class WindowsJobLimitsV1(Contract):
    active_process_limit: Annotated[int, Field(ge=1, le=64)] = 16
    process_memory_bytes: Annotated[int, Field(ge=64 * 1024 * 1024)] = 2 * 1024**3
    job_memory_bytes: Annotated[int, Field(ge=64 * 1024 * 1024)] = 4 * 1024**3
    job_user_time_seconds: Annotated[int, Field(ge=1, le=3600)] = 900
    kill_on_job_close: Literal[True] = True
    breakaway_allowed: Literal[False] = False

    @model_validator(mode="after")
    def memory_order(self) -> WindowsJobLimitsV1:
        if self.process_memory_bytes > self.job_memory_bytes:
            raise ValueError("Per-process memory cannot exceed the whole-job limit")
        return self


class WindowsIsolationProfilePayloadV1(Contract):
    platform: Literal["windows"] = "windows"
    architecture: Literal["x86_64"] = "x86_64"
    minimum_windows_build: Literal[26100] = 26100
    sandbox_api: Literal["Experimental_CreateProcessInSandbox"] = (
        "Experimental_CreateProcessInSandbox"
    )
    sandbox_spec_version: Literal["0.1.0"] = "0.1.0"
    sandbox_schema_sha256: Digest = WINDOWS_SANDBOX_SCHEMA_IDENTITY
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    appcontainer_identity: Annotated[str, Field(pattern=r"^devfabric_[a-f0-9]{32}$")]
    native_bundle_id: Digest
    codex_executable_sha256: Digest
    launcher_executable_sha256: Digest
    probe_sha256: Digest
    read_only_roots: Annotated[tuple[NativePathIdentityV1, ...], Field(min_length=1, max_length=8)]
    writable_roots: Annotated[tuple[NativePathIdentityV1, ...], Field(min_length=1, max_length=4)]
    denied_roots: Annotated[tuple[NativePathIdentityV1, ...], Field(max_length=16)] = ()
    network_mode: Literal["appcontainer_no_capabilities"] = "appcontainer_no_capabilities"
    registry_mode: Literal["appcontainer_private_no_registry_capability"] = (
        "appcontainer_private_no_registry_capability"
    )
    inherited_handles: Literal["inherit_handles_false"] = "inherit_handles_false"
    capabilities: tuple[()] = ()
    disallow_win32k_system_calls: Literal[True] = True
    least_privilege: Literal[True] = True
    job_limits: WindowsJobLimitsV1 = Field(default_factory=WindowsJobLimitsV1)

    @field_validator("sandbox_schema_sha256")
    @classmethod
    def reviewed_schema_identity(cls, value: str) -> str:
        if value != WINDOWS_SANDBOX_SCHEMA_IDENTITY:
            raise ValueError("Unsupported Windows SandboxSpec schema identity")
        return value

    @model_validator(mode="after")
    def closed_paths(self) -> WindowsIsolationProfilePayloadV1:
        groups = (self.read_only_roots, self.writable_roots, self.denied_roots)
        flattened = [item.locator.casefold() for group in groups for item in group]
        if len(flattened) != len(set(flattened)):
            raise ValueError("Isolation roots must be case-insensitively unique")
        normalized = [PureWindowsPath(item.locator) for group in groups for item in group]
        for index, left in enumerate(normalized):
            for right in normalized[index + 1 :]:
                try:
                    overlap = left.is_relative_to(right) or right.is_relative_to(left)
                except ValueError:
                    overlap = False
                if overlap:
                    raise ValueError("Isolation roots cannot contain one another")
        if self.environment_instance_id not in self.appcontainer_identity:
            raise ValueError("AppContainer identity must bind the environment instance")
        return self


class WindowsIsolationProfileV1(Contract):
    windows_isolation_profile_id: Digest
    payload: WindowsIsolationProfilePayloadV1

    @classmethod
    def create(cls, payload: WindowsIsolationProfilePayloadV1) -> WindowsIsolationProfileV1:
        return cls(
            windows_isolation_profile_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsIsolationProfileV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.windows_isolation_profile_id != expected:
            raise ValueError("Windows isolation profile hash mismatch")
        return self


class WindowsIsolationReceiptPayloadV1(Contract):
    receipt_kind: Literal["windows_native_isolation"] = "windows_native_isolation"
    windows_isolation_profile_id: Digest
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    probe_sha256: Digest
    sandbox_spec_sha256: Digest
    observed_windows_build: Annotated[int, Field(ge=WINDOWS_MINIMUM_BUILD)]
    observed_architecture: Literal["x86_64"] = "x86_64"
    sandbox_api_available: Literal[True] = True
    created_suspended: Literal[True] = True
    job_assigned_before_resume: Literal[True] = True
    inherited_handles_blocked: bool
    child_tree_terminated: bool
    breakaway_blocked: bool
    allowed_root_read_write: bool
    hidden_root_read_denied: bool
    hidden_root_write_denied: bool
    reparse_substitution_rejected: bool
    host_registry_unchanged: bool
    direct_loopback_denied: bool
    direct_lan_denied: bool
    direct_dns_denied: bool
    direct_public_denied: bool
    appcontainer_profile_deleted: bool
    model_requests: Literal[0] = 0
    provider_sends: Literal[0] = 0
    mcp_tool_executions: Literal[0] = 0
    real_task_executions: Literal[0] = 0
    no_direct_network_baseline_qualified: Literal[True] = True
    native_executor_isolation_qualified: Literal[False] = False
    package_readiness: Literal[False] = False

    @model_validator(mode="after")
    def all_security_observations_pass(self) -> WindowsIsolationReceiptPayloadV1:
        observations = (
            self.inherited_handles_blocked,
            self.child_tree_terminated,
            self.breakaway_blocked,
            self.allowed_root_read_write,
            self.hidden_root_read_denied,
            self.hidden_root_write_denied,
            self.reparse_substitution_rejected,
            self.host_registry_unchanged,
            self.direct_loopback_denied,
            self.direct_lan_denied,
            self.direct_dns_denied,
            self.direct_public_denied,
            self.appcontainer_profile_deleted,
        )
        if not all(observations):
            raise ValueError("Windows isolation qualification observation failed")
        return self


class WindowsIsolationReceiptV1(Contract):
    windows_isolation_receipt_id: Digest
    payload: WindowsIsolationReceiptPayloadV1

    @classmethod
    def create(cls, payload: WindowsIsolationReceiptPayloadV1) -> WindowsIsolationReceiptV1:
        return cls(
            windows_isolation_receipt_id=digest(canonical(payload.model_dump(mode="json"))),
            payload=payload,
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsIsolationReceiptV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.windows_isolation_receipt_id != expected:
            raise ValueError("Windows isolation receipt hash mismatch")
        return self


class WindowsAccessDeniedObservationV1(Contract):
    denied: Literal[True]
    error_code: int

    @field_validator("error_code")
    @classmethod
    def reviewed_access_denial(cls, value: int) -> int:
        if value not in {5, 13}:
            raise ValueError("Filesystem denial must be an access-denied error")
        return value


class WindowsNetworkDeniedObservationV1(Contract):
    denied: Literal[True]
    error_code: int

    @field_validator("error_code")
    @classmethod
    def reviewed_network_denial(cls, value: int) -> int:
        if value not in {5, 13, 10013}:
            raise ValueError("Network denial must be an access-denied error")
        return value


class WindowsIsolationChildResultV1(Contract):
    allowed_root_read_write: Literal[True]
    inherited_handles_blocked: Literal[True]
    inherited_handle_error_code: Literal[6]
    hidden_read: WindowsAccessDeniedObservationV1
    hidden_write: WindowsAccessDeniedObservationV1
    registry_write_succeeded: bool
    registry_error_code: int | None
    loopback: WindowsNetworkDeniedObservationV1
    lan: WindowsNetworkDeniedObservationV1
    public: WindowsNetworkDeniedObservationV1
    dns: WindowsNetworkDeniedObservationV1
    grandchild_pid: Annotated[int, Field(gt=0)]
    breakaway_blocked: Literal[True]
    breakaway_error_code: Literal[5]
    breakaway_pid: None = None

    @model_validator(mode="after")
    def registry_result_is_coherent(self) -> WindowsIsolationChildResultV1:
        if self.registry_write_succeeded:
            if self.registry_error_code is not None:
                raise ValueError("Successful private registry write cannot report an error")
        elif self.registry_error_code not in {5, 13}:
            raise ValueError("Registry denial must be an access-denied error")
        return self


class WindowsIsolationEvidenceV1(Contract):
    windows_isolation_evidence_id: Digest
    profile: WindowsIsolationProfileV1
    sandbox_spec_base64: str
    sandbox_spec_sha256: Digest
    receipt: WindowsIsolationReceiptV1

    @classmethod
    def create(
        cls,
        profile: WindowsIsolationProfileV1,
        sandbox_spec: bytes,
        receipt: WindowsIsolationReceiptV1,
    ) -> WindowsIsolationEvidenceV1:
        encoded = base64.b64encode(sandbox_spec).decode("ascii")
        sandbox_hash = digest(sandbox_spec)
        payload: dict[str, JsonValue] = {
            "profile": profile.model_dump(mode="json"),
            "sandbox_spec_base64": encoded,
            "sandbox_spec_sha256": sandbox_hash,
            "receipt": receipt.model_dump(mode="json"),
        }
        return cls(
            windows_isolation_evidence_id=digest(canonical(payload)),
            profile=profile,
            sandbox_spec_base64=encoded,
            sandbox_spec_sha256=sandbox_hash,
            receipt=receipt,
        )

    @model_validator(mode="after")
    def strict_joins(self) -> WindowsIsolationEvidenceV1:
        try:
            spec = base64.b64decode(self.sandbox_spec_base64, validate=True)
        except ValueError as error:
            raise ValueError("SandboxSpec is not canonical base64") from error
        if base64.b64encode(spec).decode("ascii") != self.sandbox_spec_base64:
            raise ValueError("SandboxSpec is not canonical base64")
        expected_spec = windows_sandbox_spec(self.profile)
        if spec != expected_spec or digest(spec) != self.sandbox_spec_sha256:
            raise ValueError("Retained SandboxSpec does not match the profile")
        receipt = self.receipt.payload
        if (
            receipt.windows_isolation_profile_id != self.profile.windows_isolation_profile_id
            or receipt.environment_instance_id != self.profile.payload.environment_instance_id
            or receipt.probe_sha256 != self.profile.payload.probe_sha256
            or receipt.sandbox_spec_sha256 != self.sandbox_spec_sha256
        ):
            raise ValueError("Windows isolation receipt does not bind the retained profile")
        payload: dict[str, JsonValue] = {
            "profile": self.profile.model_dump(mode="json"),
            "sandbox_spec_base64": self.sandbox_spec_base64,
            "sandbox_spec_sha256": self.sandbox_spec_sha256,
            "receipt": self.receipt.model_dump(mode="json"),
        }
        if digest(canonical(payload)) != self.windows_isolation_evidence_id:
            raise ValueError("Windows isolation evidence hash mismatch")
        return self


def _string_vector(builder: flatbuffers.Builder, values: tuple[str, ...]) -> int:
    offsets = [builder.CreateString(item) for item in values]
    builder.StartVector(4, len(offsets), 4)
    for item in reversed(offsets):
        builder.PrependUOffsetTRelative(item)
    return cast(int, builder.EndVector())


def windows_sandbox_spec(profile: WindowsIsolationProfileV1) -> bytes:
    """Encode the reviewed Microsoft ``SandboxSpec`` v0.1.0 field layout."""

    payload = profile.payload
    builder = flatbuffers.Builder(1024)
    version = builder.CreateString(WINDOWS_SANDBOX_SPEC_VERSION)
    read_write = _string_vector(builder, tuple(item.locator for item in payload.writable_roots))
    read_only = _string_vector(builder, tuple(item.locator for item in payload.read_only_roots))
    denied = _string_vector(builder, tuple(item.locator for item in payload.denied_roots))
    # BaseContainerSpecification.fbs has 12 slots.  Slots 2, 6, 9 and 10 stay at
    # their reviewed defaults: deprecated integrity RID, no capabilities, no
    # network policy and AppContainer system-default (low) integrity.
    builder.StartObject(12)
    builder.PrependUOffsetTRelativeSlot(0, version, 0)
    builder.PrependBoolSlot(1, True, False)
    builder.PrependBoolSlot(3, payload.disallow_win32k_system_calls, False)
    builder.PrependUint64Slot(4, 0x00FF, 0)
    builder.PrependBoolSlot(5, payload.least_privilege, False)
    builder.PrependUOffsetTRelativeSlot(7, read_write, 0)
    builder.PrependUOffsetTRelativeSlot(8, read_only, 0)
    if payload.denied_roots:
        builder.PrependUOffsetTRelativeSlot(11, denied, 0)
    root = builder.EndObject()
    builder.Finish(root, file_identifier=WINDOWS_SANDBOX_FILE_IDENTIFIER)
    return bytes(builder.Output())


def _windows_dll(name: str) -> ctypes.CDLL:
    if os.name != "nt":
        raise OSError("Windows native isolation is unavailable on this platform")
    loader = getattr(ctypes, "WinDLL", None)
    if loader is None:
        raise OSError("Windows DLL loader is unavailable")
    return cast(ctypes.CDLL, loader(name, use_last_error=True, winmode=0x00000800))


def _windows_environment_block(
    environment: dict[str, str], *, require_local_app_data: bool = True
) -> str:
    """Validate and encode the complete non-inherited sandbox environment."""

    normalized: dict[str, tuple[str, str]] = {}
    for name, value in environment.items():
        folded = name.casefold()
        if not name or "=" in name or "\0" in name or "\0" in value:
            raise ValueError("Isolated environment contains an invalid name or NUL")
        if folded in normalized:
            raise ValueError("Isolated environment names must be case-insensitively unique")
        normalized[folded] = (name, value)
    if "path" in normalized:
        raise ValueError("Isolated environment cannot inherit PATH")
    required_names = ("systemroot", "localappdata") if require_local_app_data else ("systemroot",)
    for required in required_names:
        item = normalized.get(required)
        if item is None or not item[1]:
            raise ValueError(f"Isolated environment requires non-empty {required.upper()}")
    ordered = sorted(normalized.values(), key=lambda item: (item[0].casefold(), item[0]))
    return "\0".join(f"{name}={value}" for name, value in ordered) + "\0\0"


def _require_local_fixed_volume(path: Path) -> None:
    raw = str(path)
    pure = PureWindowsPath(raw)
    if raw.startswith("\\\\") or re.fullmatch(r"[A-Za-z]:", pure.drive) is None:
        raise ValueError("Isolation paths must use an ordinary drive-qualified local volume")
    kernel = _windows_dll("kernel32.dll")
    drive_type = kernel.GetDriveTypeW
    drive_type.argtypes = [ctypes.c_wchar_p]
    drive_type.restype = ctypes.c_uint32
    if drive_type(pure.anchor) != 3:
        raise ValueError("Isolation paths must use a local fixed volume")


def _reject_reparse_chain(path: Path, *, require_directory: bool = True) -> Path:
    if os.name != "nt":
        raise OSError("Windows path identity is unavailable on this platform")
    absolute = Path(os.path.abspath(path))
    valid = absolute.is_dir() if require_directory else absolute.is_file()
    if not absolute.is_absolute() or not valid:
        kind = "directory" if require_directory else "file"
        raise ValueError(f"Isolation path must be an existing absolute {kind}")
    _require_local_fixed_volume(absolute)
    kernel = _windows_dll("kernel32.dll")
    attributes = kernel.GetFileAttributesW
    attributes.argtypes = [ctypes.c_wchar_p]
    attributes.restype = ctypes.c_uint32
    invalid = 0xFFFFFFFF
    reparse = 0x400
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        observed = attributes(str(current))
        if observed == invalid:
            raise OSError(_windows_last_error(), "GetFileAttributesW failed")
        if observed & reparse:
            raise ValueError("Isolation roots cannot traverse reparse points")
    return absolute


def windows_path_identity(path: Path) -> NativePathIdentityV1:
    """Bind a directory locator to its Windows volume/file identity."""

    absolute = _reject_reparse_chain(path)

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", ctypes.c_uint32),
            ("creation_low", ctypes.c_uint32),
            ("creation_high", ctypes.c_uint32),
            ("access_low", ctypes.c_uint32),
            ("access_high", ctypes.c_uint32),
            ("write_low", ctypes.c_uint32),
            ("write_high", ctypes.c_uint32),
            ("volume_serial", ctypes.c_uint32),
            ("file_size_high", ctypes.c_uint32),
            ("file_size_low", ctypes.c_uint32),
            ("links", ctypes.c_uint32),
            ("file_index_high", ctypes.c_uint32),
            ("file_index_low", ctypes.c_uint32),
        ]

    kernel = _windows_dll("kernel32.dll")
    create = kernel.CreateFileW
    create.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    create.restype = ctypes.c_void_p
    handle = create(
        str(absolute),
        0x80,
        0x1 | 0x2 | 0x4,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle in (None, invalid_handle):
        raise OSError(_windows_last_error(), "CreateFileW failed for isolation root")
    try:
        information = ByHandleFileInformation()
        get_information = kernel.GetFileInformationByHandle
        get_information.argtypes = [ctypes.c_void_p, ctypes.POINTER(ByHandleFileInformation)]
        get_information.restype = ctypes.c_int
        if not get_information(handle, ctypes.byref(information)):
            raise OSError(_windows_last_error(), "GetFileInformationByHandle failed")
        file_index = (information.file_index_high << 32) | information.file_index_low
        return NativePathIdentityV1(
            locator=str(absolute),
            volume_serial_number=information.volume_serial,
            file_index=f"{file_index:016x}",
        )
    finally:
        kernel.CloseHandle(handle)


def _file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def observed_windows_platform() -> tuple[int, Literal["x86_64"]]:
    if os.name != "nt" or platform.machine().upper() not in {"AMD64", "X86_64"}:
        raise OSError("Windows x64 native isolation is required")
    build = platform.version().split(".")[-1]
    if not build.isdecimal() or int(build) < WINDOWS_MINIMUM_BUILD:
        raise OSError("Required Windows sandbox API build is unavailable")
    return int(build), "x86_64"


@dataclass
class WindowsSandboxProcess:
    process_handle: int
    thread_handle: int
    job_handle: int
    process_id: int
    appcontainer_identity: str
    launch_order: tuple[str, ...]
    appcontainer_sid: str | None = None
    local_app_data: Path | None = None
    appcontainer_profile_owned: bool = True
    _profile_deleted: bool = False
    _terminal_cleanup_errors: tuple[Exception, ...] = ()

    def poll_exit_code(self) -> int | None:
        """Return the exact unsigned exit code when the retained process handle signals."""

        kernel = _windows_dll("kernel32.dll")
        wait_for = kernel.WaitForSingleObject
        wait_for.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        wait_for.restype = ctypes.c_uint32
        wait = wait_for(self.process_handle, 0)
        if wait == 0x102:
            return None
        if wait != 0:
            raise OSError(_windows_last_error(), "WaitForSingleObject failed")
        code = ctypes.c_uint32()
        get_exit = kernel.GetExitCodeProcess
        get_exit.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        get_exit.restype = ctypes.c_int
        if not get_exit(self.process_handle, ctypes.byref(code)):
            raise OSError(_windows_last_error(), "GetExitCodeProcess failed")
        return int(code.value)

    def wait(self, timeout_seconds: float) -> int:
        kernel = _windows_dll("kernel32.dll")
        wait_for = kernel.WaitForSingleObject
        wait_for.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        wait_for.restype = ctypes.c_uint32
        wait = wait_for(self.process_handle, max(0, int(timeout_seconds * 1000)))
        if wait == 0x102:
            raise TimeoutError("Isolated process did not exit before its deadline")
        if wait != 0:
            raise OSError(_windows_last_error(), "WaitForSingleObject failed")
        code = self.poll_exit_code()
        if code is None:
            raise RuntimeError("Signaled isolated process has no terminal exit code")
        return code

    def terminate_tree(self, exit_code: int = 1) -> None:
        if not self.job_handle:
            return
        kernel = _windows_dll("kernel32.dll")
        terminate = kernel.TerminateJobObject
        terminate.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        terminate.restype = ctypes.c_int
        if not terminate(self.job_handle, exit_code):
            error = _windows_last_error()
            if error not in (0, 6):
                raise OSError(error, "TerminateJobObject failed")

    def close(self) -> bool:
        if (
            not any((self.thread_handle, self.process_handle, self.job_handle))
            and self._profile_deleted
        ):
            if self._terminal_cleanup_errors:
                raise ExceptionGroup(
                    "Windows sandbox cleanup previously failed",
                    list(self._terminal_cleanup_errors),
                )
            return True
        try:
            self.terminate_tree()
        except Exception as error:
            self._terminal_cleanup_errors = (error,)
            raise ExceptionGroup("Windows sandbox cleanup failed", [error]) from error
        kernel = _windows_dll("kernel32.dll")
        close_handle = kernel.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        errors: list[Exception] = []
        for field in ("thread_handle", "process_handle", "job_handle"):
            handle = getattr(self, field)
            if handle and close_handle(handle):
                setattr(self, field, 0)
            elif handle:
                errors.append(OSError(_windows_last_error(), f"CloseHandle failed for {field}"))
        if errors:
            self._terminal_cleanup_errors = tuple(errors)
            raise ExceptionGroup("Windows sandbox cleanup failed", errors)
        if self.appcontainer_profile_owned and not self._profile_deleted:
            try:
                self._profile_deleted = _delete_appcontainer_profile(self.appcontainer_identity)
                if not self._profile_deleted:
                    errors.append(RuntimeError("AppContainer profile deletion was not confirmed"))
            except Exception as error:
                errors.append(error)
        if errors:
            raise ExceptionGroup("Windows sandbox cleanup failed", errors)
        self._terminal_cleanup_errors = ()
        return True

    def __enter__(self) -> WindowsSandboxProcess:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _set_job_limits(job: int, limits: WindowsJobLimitsV1) -> None:
    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("per_process_user_time", ctypes.c_longlong),
            ("per_job_user_time", ctypes.c_longlong),
            ("limit_flags", ctypes.c_uint32),
            ("minimum_working_set", ctypes.c_size_t),
            ("maximum_working_set", ctypes.c_size_t),
            ("active_process_limit", ctypes.c_uint32),
            ("affinity", ctypes.c_size_t),
            ("priority_class", ctypes.c_uint32),
            ("scheduling_class", ctypes.c_uint32),
        ]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            (name, ctypes.c_uint64)
            for name in (
                "read_operations",
                "write_operations",
                "other_operations",
                "read_bytes",
                "write_bytes",
                "other_bytes",
            )
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("basic", BasicLimitInformation),
            ("io", IoCounters),
            ("process_memory_limit", ctypes.c_size_t),
            ("job_memory_limit", ctypes.c_size_t),
            ("peak_process_memory", ctypes.c_size_t),
            ("peak_job_memory", ctypes.c_size_t),
        ]

    information = ExtendedLimitInformation()
    information.basic.limit_flags = 0x2000 | 0x8 | 0x100 | 0x200 | 0x4 | 0x400
    information.basic.active_process_limit = limits.active_process_limit
    information.basic.per_job_user_time = limits.job_user_time_seconds * 10_000_000
    information.process_memory_limit = limits.process_memory_bytes
    information.job_memory_limit = limits.job_memory_bytes
    kernel = _windows_dll("kernel32.dll")
    setter = kernel.SetInformationJobObject
    setter.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    setter.restype = ctypes.c_int
    if not setter(job, 9, ctypes.byref(information), ctypes.sizeof(information)):
        raise OSError(_windows_last_error(), "SetInformationJobObject failed")


def _verify_profile_paths(profile: WindowsIsolationProfileV1) -> None:
    for expected in (
        *profile.payload.read_only_roots,
        *profile.payload.writable_roots,
        *profile.payload.denied_roots,
    ):
        if windows_path_identity(Path(expected.locator)) != expected:
            raise ValueError("Isolation root identity changed")


class WindowsIsolationLaunchError(RuntimeError):
    """Typed fail-closed launch failure without success-evidence publication."""

    def __init__(self, phase: str, error_code: int, message: str) -> None:
        super().__init__(f"{phase} failed ({error_code}): {message}")
        self.phase = phase
        self.error_code = error_code


@dataclass(frozen=True)
class OwnedAppContainerProfile:
    identity: str
    sid: str
    local_app_data: Path


def _hresult_error_code(result: int) -> int:
    unsigned = result & 0xFFFFFFFF
    if unsigned & 0xFFFF0000 == 0x80070000:
        return unsigned & 0xFFFF
    return unsigned


def _create_owned_appcontainer_profile(identity: str) -> OwnedAppContainerProfile:
    """Create one new profile and return only paths derived from its exact SID."""

    userenv = _windows_dll("userenv.dll")
    advapi = _windows_dll("advapi32.dll")
    kernel = _windows_dll("kernel32.dll")
    ole32 = _windows_dll("ole32.dll")
    create = userenv.CreateAppContainerProfile
    create.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    create.restype = ctypes.c_long
    convert = advapi.ConvertSidToStringSidW
    convert.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    convert.restype = ctypes.c_int
    local_free = kernel.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    free_sid = advapi.FreeSid
    free_sid.argtypes = [ctypes.c_void_p]
    free_sid.restype = ctypes.c_void_p
    get_folder = userenv.GetAppContainerFolderPath
    get_folder.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
    get_folder.restype = ctypes.c_long
    free_folder = ole32.CoTaskMemFree
    free_folder.argtypes = [ctypes.c_void_p]
    free_folder.restype = None
    sid = ctypes.c_void_p()
    string_sid = ctypes.c_void_p()
    result = (
        int(
            create(
                identity,
                "DevFabric isolated runtime",
                "Ephemeral DevFabric qualification profile",
                None,
                0,
                ctypes.byref(sid),
            )
        )
        & 0xFFFFFFFF
    )
    if result:
        code = _hresult_error_code(result)
        message = (
            "AppContainer identity already exists and is not owned by this invocation"
            if code == 183
            else "CreateAppContainerProfile returned an HRESULT failure"
        )
        raise WindowsIsolationLaunchError("appcontainer_profile_create", code, message)
    if not sid.value:
        primary = WindowsIsolationLaunchError(
            "appcontainer_profile_create", 0, "CreateAppContainerProfile returned no SID"
        )
        cleanup_error: Exception | None = None
        try:
            if not _delete_appcontainer_profile(identity):
                cleanup_error = RuntimeError(
                    "Owned AppContainer profile deletion was not confirmed"
                )
        except Exception as error:
            cleanup_error = error
        if cleanup_error is not None:
            raise ExceptionGroup(
                "AppContainer profile creation and cleanup failed", [primary, cleanup_error]
            ) from primary
        raise primary

    try:
        if not convert(sid, ctypes.byref(string_sid)) or not string_sid.value:
            raise WindowsIsolationLaunchError(
                "appcontainer_sid_string", _windows_last_error(), "SID conversion failed"
            )
        sid_text = ctypes.wstring_at(string_sid.value)
        folder = ctypes.c_void_p()
        folder_result = int(get_folder(sid_text, ctypes.byref(folder))) & 0xFFFFFFFF
        if folder_result or not folder.value:
            raise WindowsIsolationLaunchError(
                "appcontainer_folder_path",
                _hresult_error_code(folder_result),
                "GetAppContainerFolderPath failed",
            )
        try:
            local_app_data = _reject_reparse_chain(Path(ctypes.wstring_at(folder.value)))
        finally:
            free_folder(folder)
        return OwnedAppContainerProfile(identity, sid_text, local_app_data)
    except BaseException as primary:
        cleanup_error = None
        try:
            if not _delete_appcontainer_profile(identity):
                cleanup_error = RuntimeError(
                    "Owned AppContainer profile deletion was not confirmed"
                )
        except Exception as error:
            cleanup_error = error
        if cleanup_error is not None:
            raise BaseExceptionGroup(
                "AppContainer profile preparation and cleanup failed", [primary, cleanup_error]
            ) from primary
        raise
    finally:
        if string_sid.value:
            local_free(string_sid)
        free_sid(sid)


def _delete_appcontainer_profile(identity: str) -> bool:
    userenv = _windows_dll("userenv.dll")
    delete = userenv.DeleteAppContainerProfile
    delete.argtypes = [ctypes.c_wchar_p]
    delete.restype = ctypes.c_long
    result = int(delete(identity)) & 0xFFFFFFFF
    return result in (0, 0x80070002)


def _reject_broad_roots(profile: WindowsIsolationProfileV1) -> None:
    protected = {
        Path(value).absolute()
        for value in (
            os.environ.get("SYSTEMROOT"),
            os.environ.get("PROGRAMFILES"),
            os.environ.get("PROGRAMFILES(X86)"),
            os.environ.get("PROGRAMDATA"),
            Path.home(),
            Path.home().parent,
        )
        if value
    }
    for item in (*profile.payload.read_only_roots, *profile.payload.writable_roots):
        root = Path(item.locator).absolute()
        if root == Path(root.anchor) or root in protected:
            raise ValueError("Broad system/user roots cannot be granted to the sandbox")


def _cleanup_failed_launch(
    kernel: ctypes.CDLL,
    *,
    process_handle: int,
    thread_handle: int,
    job_handle: int,
    appcontainer_identity: str,
    appcontainer_profile_owned: bool,
) -> list[Exception]:
    errors: list[Exception] = []
    terminate_process = kernel.TerminateProcess
    terminate_process.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    terminate_process.restype = ctypes.c_int
    terminate_job = kernel.TerminateJobObject
    terminate_job.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    terminate_job.restype = ctypes.c_int
    close_handle = kernel.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    if process_handle and not terminate_process(process_handle, 1):
        errors.append(OSError(_windows_last_error(), "TerminateProcess cleanup failed"))
    if job_handle and not terminate_job(job_handle, 1):
        errors.append(OSError(_windows_last_error(), "TerminateJobObject cleanup failed"))
    for name, handle in (
        ("thread", thread_handle),
        ("process", process_handle),
        ("job", job_handle),
    ):
        if handle and not close_handle(handle):
            errors.append(OSError(_windows_last_error(), f"CloseHandle cleanup failed: {name}"))
    if appcontainer_profile_owned and not errors:
        try:
            if not _delete_appcontainer_profile(appcontainer_identity):
                errors.append(RuntimeError("AppContainer profile cleanup was not confirmed"))
        except Exception as error:
            errors.append(error)
    elif appcontainer_profile_owned:
        errors.append(
            RuntimeError("AppContainer profile retained because process cleanup did not complete")
        )
    return errors


def launch_windows_isolated(
    profile: WindowsIsolationProfileV1,
    executable: Path,
    arguments: tuple[str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> WindowsSandboxProcess:
    """Create one suspended AppContainer process and bind its complete child tree."""

    if any(name.casefold() == "localappdata" for name in environment):
        raise ValueError("Isolated LOCALAPPDATA is host-owned and cannot be supplied")
    _windows_environment_block(environment, require_local_app_data=False)
    observed_windows_platform()
    _reject_broad_roots(profile)
    _verify_profile_paths(profile)
    executable = Path(os.path.abspath(executable))
    cwd = Path(os.path.abspath(cwd))
    _reject_reparse_chain(executable, require_directory=False)
    _reject_reparse_chain(cwd)
    read_only = tuple(Path(item.locator) for item in profile.payload.read_only_roots)
    writable = tuple(Path(item.locator) for item in profile.payload.writable_roots)
    if not executable.is_file() or not any(executable.is_relative_to(root) for root in read_only):
        raise ValueError("Isolated executable must belong to an exact read-only root")
    if _file_sha256(executable) != profile.payload.launcher_executable_sha256:
        raise ValueError("Isolated launcher executable hash mismatch")
    if not cwd.is_dir() or not any(cwd.is_relative_to(root) for root in writable):
        raise ValueError("Isolated cwd must belong to an exact writable root")

    class StartupInfo(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_uint32),
            ("reserved", ctypes.c_wchar_p),
            ("desktop", ctypes.c_wchar_p),
            ("title", ctypes.c_wchar_p),
            ("x", ctypes.c_uint32),
            ("y", ctypes.c_uint32),
            ("x_size", ctypes.c_uint32),
            ("y_size", ctypes.c_uint32),
            ("x_chars", ctypes.c_uint32),
            ("y_chars", ctypes.c_uint32),
            ("fill", ctypes.c_uint32),
            ("flags", ctypes.c_uint32),
            ("show", ctypes.c_uint16),
            ("reserved2_size", ctypes.c_uint16),
            ("reserved2", ctypes.c_void_p),
            ("stdin", ctypes.c_void_p),
            ("stdout", ctypes.c_void_p),
            ("stderr", ctypes.c_void_p),
        ]

    class ProcessInformation(ctypes.Structure):
        _fields_ = [
            ("process", ctypes.c_void_p),
            ("thread", ctypes.c_void_p),
            ("process_id", ctypes.c_uint32),
            ("thread_id", ctypes.c_uint32),
        ]

    kernel = _windows_dll("kernel32.dll")
    create_job = kernel.CreateJobObjectW
    create_job.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    create_job.restype = ctypes.c_void_p
    job = 0
    process_information = ProcessInformation()
    owned_profile = _create_owned_appcontainer_profile(profile.payload.appcontainer_identity)
    try:
        isolated_environment = {
            **environment,
            "LOCALAPPDATA": str(owned_profile.local_app_data),
        }
        env_text = _windows_environment_block(isolated_environment)
        job = int(create_job(None, None) or 0)
        if not job:
            raise WindowsIsolationLaunchError(
                "job_create", _windows_last_error(), "CreateJobObjectW failed"
            )
        _set_job_limits(job, profile.payload.job_limits)
        process_model = _windows_dll("processmodel.dll")
        create = getattr(process_model, WINDOWS_SANDBOX_API, None)
        if create is None:
            raise OSError("Required Windows sandbox API export is unavailable")
        create.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.POINTER(StartupInfo),
            ctypes.c_wchar_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ProcessInformation),
        ]
        create.restype = ctypes.c_int
        command = ctypes.create_unicode_buffer(
            subprocess.list2cmdline([str(executable), *arguments])
        )
        env_buffer = ctypes.create_unicode_buffer(env_text)
        spec = windows_sandbox_spec(profile)
        spec_buffer = ctypes.create_string_buffer(spec)
        startup = StartupInfo()
        startup.cb = ctypes.sizeof(startup)
        flags = 0x4 | 0x400 | 0x08000000
        if not create(
            str(executable),
            command,
            None,
            None,
            False,
            flags,
            env_buffer,
            str(cwd),
            ctypes.byref(startup),
            profile.payload.appcontainer_identity,
            spec_buffer,
            len(spec),
            ctypes.byref(process_information),
        ):
            raise WindowsIsolationLaunchError(
                "sandbox_process_create",
                _windows_last_error(),
                "Experimental_CreateProcessInSandbox failed",
            )
        assign = kernel.AssignProcessToJobObject
        assign.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        assign.restype = ctypes.c_int
        resume = kernel.ResumeThread
        resume.argtypes = [ctypes.c_void_p]
        resume.restype = ctypes.c_uint32
        if not assign(job, process_information.process):
            raise OSError(_windows_last_error(), "AssignProcessToJobObject failed")
        if resume(process_information.thread) == 0xFFFFFFFF:
            raise OSError(_windows_last_error(), "ResumeThread failed")
        return WindowsSandboxProcess(
            process_handle=int(process_information.process or 0),
            thread_handle=int(process_information.thread or 0),
            job_handle=job,
            process_id=int(process_information.process_id),
            appcontainer_identity=owned_profile.identity,
            launch_order=("created_suspended", "job_assigned", "thread_resumed"),
            appcontainer_sid=owned_profile.sid,
            local_app_data=owned_profile.local_app_data,
            appcontainer_profile_owned=True,
        )
    except Exception as launch_error:
        cleanup_errors = _cleanup_failed_launch(
            kernel,
            process_handle=int(process_information.process or 0),
            thread_handle=int(process_information.thread or 0),
            job_handle=job,
            appcontainer_identity=owned_profile.identity,
            appcontainer_profile_owned=True,
        )
        if cleanup_errors:
            raise ExceptionGroup(
                "Windows sandbox launch and cleanup failed",
                [launch_error, *cleanup_errors],
            ) from launch_error
        raise


def validate_environment_instance(value: str) -> str:
    if _HEX_32.fullmatch(value) is None:
        raise ValueError("Environment instance ID must be lowercase 128-bit hex")
    return value


def appcontainer_identity(environment_instance_id: str) -> str:
    validate_environment_instance(environment_instance_id)
    value = f"devfabric_{environment_instance_id}"
    if _PROFILE_NAME.fullmatch(value) is None:
        raise AssertionError("Invalid derived AppContainer identity")
    return value
