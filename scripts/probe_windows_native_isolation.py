"""Qualify the Windows no-direct-network sandbox without running a task or model."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import winreg
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, Literal, NoReturn, cast

from pydantic import Field, JsonValue, model_validator

from devhub.benchmark import Digest, canonical, digest
from devhub.experiment_launch import durable_publish
from devhub.models import Contract, ContractV2
from devhub.native_bundle import NativeBundleV1, verify_native_bundle
from devhub.windows_isolation import (
    WindowsIsolationChildResultV1,
    WindowsIsolationEvidenceV3,
    WindowsIsolationProfilePayloadV2,
    WindowsIsolationProfileV2,
    WindowsIsolationReceiptPayloadV3,
    WindowsIsolationReceiptV3,
    _reject_reparse_chain,
    appcontainer_identity,
    launch_windows_isolated,
    observed_windows_platform,
    windows_path_identity,
    windows_sandbox_spec,
)

ACCESS_DENIED_ERRORS = {5, 13, 10013}
MAX_CHILD_FAILURE_BYTES = 4096
MAX_BOOTSTRAP_STATUS_BYTES = 4096


class WindowsIsolationChildFailureV1(Contract):
    schema_version: Literal[1] = 1
    phase: Literal["child_probe"] = "child_probe"
    exception_class: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]
    winerror: int | None = None
    errno: int | None = None


class WindowsIsolationChildFailureV2(ContractV2):
    phase: Literal["bootstrap_import", "bootstrap_invoke", "child_probe"] = "child_probe"
    exception_class: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")]
    winerror: int | None = None
    errno: int | None = None


class WindowsIsolationBootstrapStartedPayloadV1(Contract):
    schema_version: Literal[1] = 1
    phase: Literal["bootstrap_started"] = "bootstrap_started"
    child_bootstrap_sha256: Digest
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    windows_isolation_profile_id: Digest
    probe_sha256: Digest


class WindowsIsolationBootstrapStartedV1(Contract):
    bootstrap_started_id: Digest
    payload: WindowsIsolationBootstrapStartedPayloadV1

    @model_validator(mode="after")
    def verified_id(self) -> WindowsIsolationBootstrapStartedV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.bootstrap_started_id != expected:
            raise ValueError("Windows isolation bootstrap-started hash mismatch")
        return self


class WindowsIsolationFailureDiagnosticPayloadV1(Contract):
    schema_version: Literal[1] = 1
    failure_kind: Literal["child_before_evidence"] = "child_before_evidence"
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    windows_isolation_profile_id: Digest
    probe_sha256: Digest
    process_exit_code: Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
    child_failure_status: Literal["absent", "validated", "invalid"]
    child_failure: WindowsIsolationChildFailureV1 | None = None
    success_evidence_published: Literal[False] = False

    @model_validator(mode="after")
    def strict_child_failure_status(self) -> WindowsIsolationFailureDiagnosticPayloadV1:
        if (self.child_failure is not None) != (self.child_failure_status == "validated"):
            raise ValueError("Child failure status does not match the validated diagnostic")
        return self


class WindowsIsolationFailureDiagnosticV1(Contract):
    diagnostic_id: Digest
    payload: WindowsIsolationFailureDiagnosticPayloadV1

    @classmethod
    def create(
        cls, payload: WindowsIsolationFailureDiagnosticPayloadV1
    ) -> WindowsIsolationFailureDiagnosticV1:
        return cls(
            diagnostic_id=digest(canonical(payload.model_dump(mode="json"))), payload=payload
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsIsolationFailureDiagnosticV1:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.diagnostic_id != expected:
            raise ValueError("Windows isolation failure diagnostic hash mismatch")
        return self


class WindowsIsolationFailureDiagnosticPayloadV2(ContractV2):
    failure_kind: Literal["child_before_evidence"] = "child_before_evidence"
    environment_instance_id: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    windows_isolation_profile_id: Digest
    probe_sha256: Digest
    child_bootstrap_sha256: Digest
    process_exit_code: Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
    bootstrap_started_status: Literal["absent", "validated", "invalid"]
    bootstrap_started: WindowsIsolationBootstrapStartedV1 | None = None
    child_failure_status: Literal["absent", "validated", "invalid"]
    child_failure: WindowsIsolationChildFailureV2 | None = None
    success_evidence_published: Literal[False] = False

    @model_validator(mode="after")
    def strict_status_and_bindings(self) -> WindowsIsolationFailureDiagnosticPayloadV2:
        if (self.bootstrap_started is not None) != (self.bootstrap_started_status == "validated"):
            raise ValueError("Bootstrap-started status does not match the validated frame")
        if (self.child_failure is not None) != (self.child_failure_status == "validated"):
            raise ValueError("Child failure status does not match the validated diagnostic")
        if self.bootstrap_started is not None:
            started = self.bootstrap_started.payload
            if (
                started.child_bootstrap_sha256 != self.child_bootstrap_sha256
                or started.environment_instance_id != self.environment_instance_id
                or started.windows_isolation_profile_id != self.windows_isolation_profile_id
                or started.probe_sha256 != self.probe_sha256
            ):
                raise ValueError("Bootstrap-started frame does not bind the failed child")
        return self


class WindowsIsolationFailureDiagnosticV2(ContractV2):
    diagnostic_id: Digest
    payload: WindowsIsolationFailureDiagnosticPayloadV2

    @classmethod
    def create(
        cls, payload: WindowsIsolationFailureDiagnosticPayloadV2
    ) -> WindowsIsolationFailureDiagnosticV2:
        return cls(
            diagnostic_id=digest(canonical(payload.model_dump(mode="json"))), payload=payload
        )

    @model_validator(mode="after")
    def verified_id(self) -> WindowsIsolationFailureDiagnosticV2:
        expected = digest(canonical(self.payload.model_dump(mode="json")))
        if self.diagnostic_id != expected:
            raise ValueError("Windows isolation failure diagnostic hash mismatch")
        return self


class WindowsIsolationChildExitError(RuntimeError):
    phase = "child_before_evidence"

    def __init__(self, diagnostic: WindowsIsolationFailureDiagnosticV2) -> None:
        self.diagnostic = diagnostic
        self.exit_code = diagnostic.payload.process_exit_code
        super().__init__(
            "Windows isolation child exited before evidence "
            f"(exit_code={self.exit_code}, hex=0x{self.exit_code:08X}, "
            f"bootstrap_started={diagnostic.payload.bootstrap_started_status}, "
            f"child_failure={diagnostic.payload.child_failure_status})"
        )


def _error_code(error: BaseException) -> int | None:
    for name in ("winerror", "errno"):
        value = getattr(error, name, None)
        if isinstance(value, int):
            return value
    return None


def _socket_denied(address: tuple[str, int], *, tcp: bool) -> dict[str, object]:
    family = socket.AF_INET
    kind = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
    try:
        with socket.socket(family, kind) as client:
            client.settimeout(1)
            client.connect(address)
        return {"denied": False, "error_code": None}
    except OSError as error:
        code = _error_code(error)
        return {"denied": code in ACCESS_DENIED_ERRORS, "error_code": code}


def _dns_denied() -> dict[str, object]:
    try:
        socket.getaddrinfo("devfabric-isolation.invalid", 443, type=socket.SOCK_STREAM)
        return {"denied": False, "error_code": None}
    except OSError as error:
        code = _error_code(error)
        return {"denied": code in ACCESS_DENIED_ERRORS, "error_code": code}


def _path_denied(path: Path, *, write: bool) -> dict[str, object]:
    try:
        if write:
            path.write_bytes(b"forbidden")
        else:
            path.read_bytes()
        return {"denied": False, "error_code": None}
    except OSError as error:
        return {"denied": True, "error_code": _error_code(error)}


def _child(request_path: Path, result_path: Path) -> int:
    request = json.loads(request_path.read_bytes())
    allowed = Path(request["allowed_root"])
    hidden = Path(request["hidden_canary"])
    marker = allowed / "sandbox-write.txt"
    marker.write_text("isolated", encoding="ascii")
    allowed_ok = marker.read_text(encoding="ascii") == "isolated"

    inherited_handle = int(request["forbidden_handle"])
    flags = ctypes.c_uint32()
    get_handle_information = ctypes.windll.kernel32.GetHandleInformation
    get_handle_information.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    get_handle_information.restype = ctypes.c_int
    ctypes.set_last_error(0)
    inherited_visible = bool(get_handle_information(inherited_handle, ctypes.byref(flags)))
    inherited_error = None if inherited_visible else ctypes.get_last_error()

    registry_path = request["registry_path"]
    registry_write_succeeded = False
    registry_error = None
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_WRITE)
        try:
            winreg.SetValueEx(key, "probe", 0, winreg.REG_SZ, "sandbox")
            registry_write_succeeded = True
        finally:
            winreg.CloseKey(key)
    except OSError as error:
        registry_error = _error_code(error)

    normal = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", "import time; time.sleep(60)"],
        close_fds=True,
    )
    (allowed / "grandchild.pid").write_text(str(normal.pid), encoding="ascii")
    breakaway_blocked = False
    breakaway_error = None
    breakaway_pid = None
    try:
        escaped = subprocess.Popen(
            [sys.executable, "-I", "-B", "-c", "import time; time.sleep(60)"],
            close_fds=True,
            creationflags=subprocess.CREATE_BREAKAWAY_FROM_JOB,
        )
        breakaway_pid = escaped.pid
        escaped.terminate()
        escaped.wait(timeout=5)
    except OSError as error:
        breakaway_blocked = True
        breakaway_error = _error_code(error)

    result = {
        "allowed_root_read_write": allowed_ok,
        "inherited_handles_blocked": not inherited_visible,
        "inherited_handle_error_code": inherited_error,
        "hidden_read": _path_denied(hidden, write=False),
        "hidden_write": _path_denied(hidden.with_name("created.txt"), write=True),
        "registry_write_succeeded": registry_write_succeeded,
        "registry_error_code": registry_error,
        "loopback": _socket_denied(("127.0.0.1", int(request["loopback_port"])), tcp=True),
        "lan": _socket_denied(("192.0.2.1", 9), tcp=False),
        "public": _socket_denied(("203.0.113.1", 9), tcp=False),
        "dns": _dns_denied(),
        "grandchild_pid": normal.pid,
        "breakaway_blocked": breakaway_blocked,
        "breakaway_error_code": breakaway_error,
        "breakaway_pid": breakaway_pid,
    }
    temporary = result_path.with_suffix(".tmp")
    temporary.write_bytes(canonical(cast(JsonValue, result)))
    os.replace(temporary, result_path)
    time.sleep(60)
    return 0


def _child_guarded(request_path: Path, result_path: Path, failure_path: Path) -> int:
    try:
        return _child(request_path, result_path)
    except BaseException as error:
        failure = WindowsIsolationChildFailureV2(
            exception_class=type(error).__name__,
            winerror=getattr(error, "winerror", None),
            errno=getattr(error, "errno", None),
        )
        encoded = canonical(failure.model_dump(mode="json"))
        if len(encoded) > MAX_CHILD_FAILURE_BYTES:
            return 1
        temporary = failure_path.with_name(failure_path.name + ".tmp")
        temporary.write_bytes(encoded)
        os.replace(temporary, failure_path)
        return 1


def _read_child_failure(
    failure_path: Path,
) -> tuple[Literal["absent", "validated", "invalid"], WindowsIsolationChildFailureV2 | None]:
    if not failure_path.is_file():
        return "absent", None
    try:
        _reject_reparse_chain(failure_path, require_directory=False)
        with failure_path.open("rb") as stream:
            encoded = stream.read(MAX_CHILD_FAILURE_BYTES + 1)
        if len(encoded) > MAX_CHILD_FAILURE_BYTES:
            return "invalid", None
        return "validated", WindowsIsolationChildFailureV2.model_validate_json(encoded)
    except (OSError, ValueError):
        return "invalid", None


def _read_bootstrap_started(
    status_path: Path,
) -> tuple[Literal["absent", "validated", "invalid"], WindowsIsolationBootstrapStartedV1 | None]:
    if not status_path.is_file():
        return "absent", None
    try:
        _reject_reparse_chain(status_path, require_directory=False)
        with status_path.open("rb") as stream:
            encoded = stream.read(MAX_BOOTSTRAP_STATUS_BYTES + 1)
        if len(encoded) > MAX_BOOTSTRAP_STATUS_BYTES:
            return "invalid", None
        return "validated", WindowsIsolationBootstrapStartedV1.model_validate_json(encoded)
    except (OSError, ValueError):
        return "invalid", None


def _read_bound_bootstrap_started(
    status_path: Path,
    profile: WindowsIsolationProfileV2,
    environment_instance_id: str,
) -> tuple[Literal["absent", "validated", "invalid"], WindowsIsolationBootstrapStartedV1 | None]:
    status, started = _read_bootstrap_started(status_path)
    if status != "validated" or started is None:
        return status, None
    payload = started.payload
    if (
        payload.child_bootstrap_sha256 != profile.payload.child_bootstrap_sha256
        or payload.environment_instance_id != environment_instance_id
        or payload.windows_isolation_profile_id != profile.windows_isolation_profile_id
        or payload.probe_sha256 != profile.payload.probe_sha256
    ):
        return "invalid", None
    return "validated", started


def _require_bootstrap_started(
    status_path: Path,
    profile: WindowsIsolationProfileV2,
    environment_instance_id: str,
) -> WindowsIsolationBootstrapStartedV1:
    status, started = _read_bound_bootstrap_started(status_path, profile, environment_instance_id)
    if status != "validated" or started is None:
        raise RuntimeError(f"Windows isolation bootstrap-started frame is {status}")
    return started


def _raise_if_child_exited(
    process: Any,
    child_result: Path,
    child_failure: Path,
    bootstrap_status: Path,
    profile: WindowsIsolationProfileV2,
    environment_instance_id: str,
) -> None:
    if child_result.is_file():
        return
    exit_code = process.poll_exit_code()
    if exit_code is None:
        return
    bootstrap_started_status, validated_bootstrap_started = _read_bound_bootstrap_started(
        bootstrap_status, profile, environment_instance_id
    )
    child_failure_status, validated_child_failure = _read_child_failure(child_failure)
    diagnostic = WindowsIsolationFailureDiagnosticV2.create(
        WindowsIsolationFailureDiagnosticPayloadV2(
            environment_instance_id=environment_instance_id,
            windows_isolation_profile_id=profile.windows_isolation_profile_id,
            probe_sha256=profile.payload.probe_sha256,
            child_bootstrap_sha256=profile.payload.child_bootstrap_sha256,
            process_exit_code=exit_code,
            bootstrap_started_status=bootstrap_started_status,
            bootstrap_started=validated_bootstrap_started,
            child_failure_status=child_failure_status,
            child_failure=validated_child_failure,
        )
    )
    raise WindowsIsolationChildExitError(diagnostic)


def _raise_after_cleanup(
    primary_error: BaseException,
    cleanup_errors: list[Exception],
    failure_diagnostic: WindowsIsolationFailureDiagnosticV2 | None,
    failure_output: Path,
) -> NoReturn:
    if cleanup_errors:
        raise BaseExceptionGroup(
            "Windows isolation probe and cleanup failed",
            [primary_error, *cleanup_errors],
        ) from primary_error
    if failure_diagnostic is not None:
        failure_output.parent.mkdir(parents=True, exist_ok=True)
        durable_publish(
            failure_output,
            canonical(failure_diagnostic.model_dump(mode="json")),
        )
    raise primary_error


def _pid_active(pid: int) -> bool:
    open_process = ctypes.windll.kernel32.OpenProcess
    open_process.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    open_process.restype = ctypes.c_void_p
    handle = open_process(0x1000, False, pid)
    if not handle:
        return not _open_process_failure_proves_absent(ctypes.get_last_error())
    try:
        code = ctypes.c_uint32()
        get_exit = ctypes.windll.kernel32.GetExitCodeProcess
        get_exit.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        get_exit.restype = ctypes.c_int
        if not get_exit(handle, ctypes.byref(code)):
            raise OSError(ctypes.get_last_error(), "GetExitCodeProcess failed")
        return code.value == 259
    finally:
        close_handle = ctypes.windll.kernel32.CloseHandle
        close_handle.argtypes = [ctypes.c_void_p]
        close_handle.restype = ctypes.c_int
        close_handle(handle)


def _open_process_failure_proves_absent(error: int) -> bool:
    if error == 87:
        return True
    raise OSError(error, "OpenProcess could not prove the process terminated")


def _wait_gone(pid: int, timeout: float = 10) -> bool:
    deadline = time.monotonic() + timeout
    while _pid_active(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not _pid_active(pid)


def _close_handle(handle: int) -> None:
    close_handle = ctypes.windll.kernel32.CloseHandle
    close_handle.argtypes = [ctypes.c_void_p]
    close_handle.restype = ctypes.c_int
    if not close_handle(handle):
        raise OSError(ctypes.get_last_error(), "CloseHandle failed")


def _registry_exists(path: str) -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return False


def _delete_registry(path: str) -> None:
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    except FileNotFoundError:
        pass


def _cleanup_probe_resources(
    process: Any | None,
    event: int | None,
    listener: socket.socket | None,
    registry_path: str,
    scratch: Path,
    execution_bundle: Path | None = None,
) -> list[Exception]:
    errors: list[Exception] = []
    operations: list[tuple[str, Callable[[], object]]] = [
        ("sandbox process", lambda: process.close() if process is not None else None),
        ("event handle", lambda: _close_handle(event) if event is not None else None),
        ("listener", lambda: listener.close() if listener is not None else None),
        (
            "registry canary",
            lambda: _delete_registry(registry_path) if _registry_exists(registry_path) else None,
        ),
        ("scratch directory", lambda: shutil.rmtree(scratch) if scratch.exists() else None),
        (
            "disposable execution bundle",
            lambda: shutil.rmtree(execution_bundle)
            if execution_bundle is not None and execution_bundle.exists()
            else None,
        ),
    ]
    for name, operation in operations:
        try:
            operation()
        except Exception as error:
            error.add_note(f"cleanup operation: {name}")
            errors.append(error)
    return errors


def _security_descriptor(path: Path) -> bytes:
    security_information = 0x00000001 | 0x00000002 | 0x00000004
    loader = getattr(ctypes, "WinDLL", None)
    if not callable(loader):
        raise RuntimeError("Windows DLL loader is unavailable")
    advapi = loader("advapi32.dll", use_last_error=True, winmode=0x00000800)
    get_security = advapi.GetFileSecurityW
    get_security.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    get_security.restype = ctypes.c_int
    required = ctypes.c_uint32()
    if get_security(str(path), security_information, None, 0, ctypes.byref(required)):
        raise RuntimeError("GetFileSecurityW unexpectedly accepted an empty buffer")
    error = ctypes.get_last_error()
    if error != 122 or required.value == 0:
        raise OSError(error, "GetFileSecurityW size query failed")
    descriptor = ctypes.create_string_buffer(required.value)
    if not get_security(
        str(path),
        security_information,
        descriptor,
        required.value,
        ctypes.byref(required),
    ):
        raise OSError(ctypes.get_last_error(), "GetFileSecurityW failed")
    return descriptor.raw[: required.value]


def _security_descriptor_inventory_sha256(root: Path) -> str:
    """Hash owner/group/DACL bytes for the exact source bundle tree."""

    entries = [root, *sorted(root.rglob("*"), key=lambda item: item.as_posix())]
    accumulator = hashlib.sha256()
    for item in entries:
        relative = "." if item == root else item.relative_to(root).as_posix()
        descriptor = _security_descriptor(item)
        accumulator.update(relative.encode("utf-8"))
        accumulator.update(b"\0")
        accumulator.update(len(descriptor).to_bytes(8, "big"))
        accumulator.update(descriptor)
    return accumulator.hexdigest()


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _validated_probe_paths(
    bundle_root: Path,
    bundle_manifest: Path,
    scratch: Path,
    execution_bundle: Path,
    output: Path,
    failure_output: Path,
) -> tuple[Path, Path, Path, Path, Path, Path]:
    source_root = _reject_reparse_chain(bundle_root)
    source_manifest = _reject_reparse_chain(bundle_manifest, require_directory=False)
    mutable = tuple(
        Path(os.path.abspath(path)) for path in (scratch, execution_bundle, output, failure_output)
    )
    for parent in {path.parent for path in mutable}:
        _reject_reparse_chain(parent)
    for path in mutable:
        if _paths_overlap(path, source_root) or _paths_overlap(path, source_manifest):
            raise ValueError("Probe mutable paths cannot overlap bundle authority")
    for index, left in enumerate(mutable):
        if any(_paths_overlap(left, right) for right in mutable[index + 1 :]):
            raise ValueError("Probe mutable paths cannot overlap each other")
    return (
        source_root,
        source_manifest,
        mutable[0],
        mutable[1],
        mutable[2],
        mutable[3],
    )


def _reparse_rejected(root: Path, target: Path) -> bool:
    link = root / "reparse-link"
    command = [os.environ["COMSPEC"], "/d", "/c", "mklink", "/J", str(link), str(target)]
    created = subprocess.run(command, capture_output=True, check=False)
    if created.returncode != 0:
        raise RuntimeError("Junction creation unavailable; reparse qualification cannot proceed")
    try:
        try:
            windows_path_identity(link)
        except ValueError:
            return True
        return False
    finally:
        subprocess.run(
            [os.environ["COMSPEC"], "/d", "/c", "rmdir", str(link)],
            capture_output=True,
            check=False,
        )


def _inheritable_event() -> int:
    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", ctypes.c_uint32),
            ("security_descriptor", ctypes.c_void_p),
            ("inherit_handle", ctypes.c_int),
        ]

    attributes = SecurityAttributes(ctypes.sizeof(SecurityAttributes), None, True)
    create_event = ctypes.windll.kernel32.CreateEventW
    create_event.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_wchar_p]
    create_event.restype = ctypes.c_void_p
    handle = create_event(ctypes.byref(attributes), True, False, None)
    if not handle:
        raise OSError(ctypes.get_last_error(), "CreateEventW failed")
    return int(handle)


def qualify(
    bundle_root: Path,
    bundle_manifest: Path,
    scratch: Path,
    output: Path,
    environment_instance_id: str,
    expected_implementation_commit: str,
) -> WindowsIsolationEvidenceV3:
    scratch = Path(os.path.abspath(scratch))
    output = Path(os.path.abspath(output))
    failure_output = output.with_name(output.name + ".failure.json")
    execution_bundle = scratch.with_name(scratch.name + ".execution-bundle")
    if scratch.exists() or execution_bundle.exists() or output.exists() or failure_output.exists():
        raise FileExistsError("Scratch, disposable bundle and output paths must not already exist")
    (
        bundle_root,
        bundle_manifest,
        scratch,
        execution_bundle,
        output,
        failure_output,
    ) = _validated_probe_paths(
        bundle_root,
        bundle_manifest,
        scratch,
        execution_bundle,
        output,
        failure_output,
    )
    bundle = NativeBundleV1.model_validate_json(bundle_manifest.read_bytes())
    verify_native_bundle(
        bundle,
        bundle_root,
        expected_platform="windows",
        expected_architecture="x86_64",
    )
    if len(expected_implementation_commit) != 40 or any(
        character not in "0123456789abcdef" for character in expected_implementation_commit
    ):
        raise ValueError(
            "Expected implementation commit must be 40 lowercase hexadecimal characters"
        )
    if bundle.payload.implementation_commit != expected_implementation_commit:
        raise ValueError("Native bundle implementation commit differs from expected authority")
    source_security_descriptor_sha256 = _security_descriptor_inventory_sha256(bundle_root)
    registry_path = rf"Software\DevFabric\IsolationProbe\{environment_instance_id}"
    listener: socket.socket | None = None
    event: int | None = None
    process: Any | None = None
    evidence: WindowsIsolationEvidenceV3 | None = None
    primary_error: BaseException | None = None
    failure_diagnostic: WindowsIsolationFailureDiagnosticV2 | None = None
    try:
        shutil.copytree(bundle_root, execution_bundle)
        verify_native_bundle(
            bundle,
            execution_bundle,
            expected_platform="windows",
            expected_architecture="x86_64",
        )
        _reject_reparse_chain(execution_bundle)
        observed_build, observed_architecture = observed_windows_platform()
        scratch.mkdir(parents=True)
        allowed = scratch / "allowed"
        hidden = scratch / "hidden"
        allowed.mkdir()
        hidden.mkdir()
        hidden_canary = hidden / "canary.txt"
        hidden_canary.write_text("private", encoding="ascii")
        bootstrap_source = Path(__file__).with_name("windows_isolation_child_bootstrap.py")
        bootstrap_bytes = bootstrap_source.read_bytes()
        child_bootstrap = allowed / "child-bootstrap.py"
        child_bootstrap.write_bytes(bootstrap_bytes)
        probe_bytes = Path(__file__).read_bytes()
        child_script = allowed / "probe-child.py"
        child_script.write_bytes(probe_bytes)
        child_result = allowed / "child-result.json"
        child_failure = allowed / "child-failure.json"
        bootstrap_status = allowed / "bootstrap-started.json"
        request_path = allowed / "request.json"
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.2)
        event = _inheritable_event()
        _delete_registry(registry_path)
        reparse_rejected = _reparse_rejected(scratch, hidden)
        profile = WindowsIsolationProfileV2.create(
            WindowsIsolationProfilePayloadV2(
                environment_instance_id=environment_instance_id,
                appcontainer_identity=appcontainer_identity(environment_instance_id),
                native_bundle_id=bundle.bundle_id,
                codex_executable_sha256=bundle.payload.codex.executable_sha256,
                launcher_executable_sha256=bundle.payload.python.executable_sha256,
                probe_sha256=digest(probe_bytes),
                child_bootstrap_sha256=digest(bootstrap_bytes),
                read_only_roots=(windows_path_identity(execution_bundle),),
                writable_roots=(windows_path_identity(allowed),),
                denied_roots=(windows_path_identity(hidden),),
            )
        )
        request_path.write_bytes(
            canonical(
                {
                    "allowed_root": str(allowed),
                    "hidden_canary": str(hidden_canary),
                    "forbidden_handle": event,
                    "registry_path": registry_path,
                    "loopback_port": listener.getsockname()[1],
                }
            )
        )
        python = execution_bundle / bundle.payload.python.executable_path
        environment = {
            "SYSTEMROOT": os.environ["SYSTEMROOT"],
            "TEMP": str(allowed),
            "TMP": str(allowed),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }

        def verify_execution_bundle(root: Path) -> str:
            verify_native_bundle(
                bundle,
                root,
                expected_platform="windows",
                expected_architecture="x86_64",
            )
            return bundle.bundle_id

        process = launch_windows_isolated(
            profile,
            python,
            (
                "-I",
                "-B",
                str(child_bootstrap),
                str(child_script),
                str(request_path),
                str(child_result),
                str(child_failure),
                str(bootstrap_status),
                profile.payload.child_bootstrap_sha256,
                environment_instance_id,
                profile.windows_isolation_profile_id,
                profile.payload.probe_sha256,
            ),
            cwd=allowed,
            environment=environment,
            verify_runtime_bundle=verify_execution_bundle,
        )
        if process.runtime_access_grant is None:
            raise RuntimeError("Windows sandbox launch did not retain its runtime access grant")
        deadline = time.monotonic() + 30
        while not child_result.is_file() and time.monotonic() < deadline:
            try:
                _raise_if_child_exited(
                    process,
                    child_result,
                    child_failure,
                    bootstrap_status,
                    profile,
                    environment_instance_id,
                )
            except WindowsIsolationChildExitError as error:
                failure_diagnostic = error.diagnostic
                raise
            time.sleep(0.05)
        if not child_result.is_file():
            raise TimeoutError("Isolation probe did not produce evidence")
        bootstrap_started = _require_bootstrap_started(
            bootstrap_status, profile, environment_instance_id
        )
        child = WindowsIsolationChildResultV1.model_validate_json(child_result.read_bytes())
        try:
            listener.accept()
            loopback_reached = True
        except TimeoutError:
            loopback_reached = False
        process.terminate_tree()
        child_tree_terminated = _wait_gone(child.grandchild_pid) and _wait_gone(process.process_id)
        profile_deleted = process.close()
        host_registry_unchanged = not _registry_exists(registry_path)
        spec = windows_sandbox_spec(profile)
        payload = WindowsIsolationReceiptPayloadV3(
            windows_isolation_profile_id=profile.windows_isolation_profile_id,
            environment_instance_id=environment_instance_id,
            probe_sha256=profile.payload.probe_sha256,
            child_bootstrap_sha256=profile.payload.child_bootstrap_sha256,
            bootstrap_started_id=bootstrap_started.bootstrap_started_id,
            bootstrap_started_validated=True,
            runtime_access_grant=process.runtime_access_grant,
            sandbox_spec_sha256=digest(spec),
            observed_windows_build=observed_build,
            observed_architecture=observed_architecture,
            inherited_handles_blocked=child.inherited_handles_blocked,
            child_tree_terminated=child_tree_terminated,
            breakaway_blocked=child.breakaway_blocked,
            allowed_root_read_write=child.allowed_root_read_write,
            hidden_root_read_denied=child.hidden_read.denied,
            hidden_root_write_denied=child.hidden_write.denied,
            reparse_substitution_rejected=reparse_rejected,
            host_registry_unchanged=host_registry_unchanged,
            direct_loopback_denied=child.loopback.denied and not loopback_reached,
            direct_lan_denied=child.lan.denied,
            direct_dns_denied=child.dns.denied,
            direct_public_denied=child.public.denied,
            appcontainer_profile_deleted=profile_deleted,
        )
        receipt = WindowsIsolationReceiptV3.create(payload)
        evidence = WindowsIsolationEvidenceV3.create(profile, spec, receipt)
    except BaseException as error:
        primary_error = error
    cleanup_errors = _cleanup_probe_resources(
        process,
        event,
        listener,
        registry_path,
        scratch,
        execution_bundle,
    )
    try:
        verify_native_bundle(
            bundle,
            bundle_root,
            expected_platform="windows",
            expected_architecture="x86_64",
        )
    except Exception as error:
        error.add_note("post-probe source bundle byte verification")
        cleanup_errors.append(error)
    try:
        observed_source_security_descriptor_sha256 = _security_descriptor_inventory_sha256(
            bundle_root
        )
        if observed_source_security_descriptor_sha256 != source_security_descriptor_sha256:
            raise RuntimeError("Source bundle security descriptor changed during qualification")
    except Exception as error:
        error.add_note("post-probe source bundle security descriptor verification")
        cleanup_errors.append(error)
    if primary_error is not None:
        _raise_after_cleanup(primary_error, cleanup_errors, failure_diagnostic, failure_output)
    if cleanup_errors:
        raise ExceptionGroup("Windows isolation probe cleanup failed", cleanup_errors)
    if evidence is None:
        raise AssertionError("Windows isolation evidence was not constructed")
    output.parent.mkdir(parents=True, exist_ok=True)
    durable_publish(output, canonical(evidence.model_dump(mode="json")))
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("child_request", nargs="?", type=Path)
    parser.add_argument("child_result", nargs="?", type=Path)
    parser.add_argument("child_failure", nargs="?", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--bundle-manifest", type=Path)
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--environment-instance-id")
    parser.add_argument("--expected-implementation-commit")
    args = parser.parse_args()
    if args.child:
        if args.child_request is None or args.child_result is None or args.child_failure is None:
            parser.error("child mode requires request, result and failure paths")
        raise SystemExit(_child_guarded(args.child_request, args.child_result, args.child_failure))
    required: dict[str, Any] = {
        "bundle_root": args.bundle,
        "bundle_manifest": args.bundle_manifest,
        "scratch": args.scratch,
        "output": args.output,
        "environment_instance_id": args.environment_instance_id,
        "expected_implementation_commit": args.expected_implementation_commit,
    }
    if any(value is None for value in required.values()):
        parser.error("host mode requires bundle, manifest, scratch, output and environment ID")
    receipt = qualify(**required)
    print(json.dumps(receipt.model_dump(mode="json"), sort_keys=True))


if __name__ == "__main__":
    main()
