"""Qualify the Windows no-direct-network sandbox without running a task or model."""

from __future__ import annotations

import argparse
import ctypes
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
from typing import Any, cast

from pydantic import JsonValue

from devhub.benchmark import canonical, digest
from devhub.experiment_launch import durable_publish
from devhub.native_bundle import NativeBundleV1, verify_native_bundle
from devhub.windows_isolation import (
    WindowsIsolationChildResultV1,
    WindowsIsolationEvidenceV1,
    WindowsIsolationProfilePayloadV1,
    WindowsIsolationProfileV1,
    WindowsIsolationReceiptPayloadV1,
    WindowsIsolationReceiptV1,
    appcontainer_identity,
    launch_windows_isolated,
    observed_windows_platform,
    windows_path_identity,
    windows_sandbox_spec,
)

ACCESS_DENIED_ERRORS = {5, 13, 10013}


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
    ]
    for name, operation in operations:
        try:
            operation()
        except Exception as error:
            error.add_note(f"cleanup operation: {name}")
            errors.append(error)
    return errors


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
) -> WindowsIsolationEvidenceV1:
    observed_build, observed_architecture = observed_windows_platform()
    if scratch.exists() or output.exists():
        raise FileExistsError("Scratch and output must not already exist")
    bundle = NativeBundleV1.model_validate_json(bundle_manifest.read_bytes())
    verify_native_bundle(
        bundle,
        bundle_root,
        expected_platform="windows",
        expected_architecture="x86_64",
    )
    registry_path = rf"Software\DevFabric\IsolationProbe\{environment_instance_id}"
    listener: socket.socket | None = None
    event: int | None = None
    process: Any | None = None
    evidence: WindowsIsolationEvidenceV1 | None = None
    primary_error: BaseException | None = None
    try:
        scratch.mkdir(parents=True)
        allowed = scratch / "allowed"
        hidden = scratch / "hidden"
        allowed.mkdir()
        hidden.mkdir()
        hidden_canary = hidden / "canary.txt"
        hidden_canary.write_text("private", encoding="ascii")
        child_script = allowed / "probe-child.py"
        child_script.write_bytes(Path(__file__).read_bytes())
        child_result = allowed / "child-result.json"
        request_path = allowed / "request.json"
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.2)
        event = _inheritable_event()
        _delete_registry(registry_path)
        reparse_rejected = _reparse_rejected(scratch, hidden)
        profile = WindowsIsolationProfileV1.create(
            WindowsIsolationProfilePayloadV1(
                environment_instance_id=environment_instance_id,
                appcontainer_identity=appcontainer_identity(environment_instance_id),
                native_bundle_id=bundle.bundle_id,
                codex_executable_sha256=bundle.payload.codex.executable_sha256,
                launcher_executable_sha256=bundle.payload.python.executable_sha256,
                probe_sha256=digest(Path(__file__).read_bytes()),
                read_only_roots=(windows_path_identity(bundle_root),),
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
        python = bundle_root / bundle.payload.python.executable_path
        environment = {
            "SYSTEMROOT": os.environ["SYSTEMROOT"],
            "TEMP": str(allowed),
            "TMP": str(allowed),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
        process = launch_windows_isolated(
            profile,
            python,
            ("-I", "-B", str(child_script), "--child", str(request_path), str(child_result)),
            cwd=allowed,
            environment=environment,
        )
        deadline = time.monotonic() + 30
        while not child_result.is_file() and time.monotonic() < deadline:
            if not _pid_active(process.process_id):
                raise RuntimeError("Isolation probe exited before producing evidence")
            time.sleep(0.05)
        if not child_result.is_file():
            raise TimeoutError("Isolation probe did not produce evidence")
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
        payload = WindowsIsolationReceiptPayloadV1(
            windows_isolation_profile_id=profile.windows_isolation_profile_id,
            environment_instance_id=environment_instance_id,
            probe_sha256=profile.payload.probe_sha256,
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
        receipt = WindowsIsolationReceiptV1.create(payload)
        evidence = WindowsIsolationEvidenceV1.create(profile, spec, receipt)
    except BaseException as error:
        primary_error = error
    cleanup_errors = _cleanup_probe_resources(process, event, listener, registry_path, scratch)
    if primary_error is not None:
        if cleanup_errors:
            raise BaseExceptionGroup(
                "Windows isolation probe and cleanup failed",
                [primary_error, *cleanup_errors],
            ) from primary_error
        raise primary_error
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
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--bundle-manifest", type=Path)
    parser.add_argument("--scratch", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--environment-instance-id")
    args = parser.parse_args()
    if args.child:
        if args.child_request is None or args.child_result is None:
            parser.error("child mode requires request and result paths")
        raise SystemExit(_child(args.child_request, args.child_result))
    required: dict[str, Any] = {
        "bundle": args.bundle,
        "bundle_manifest": args.bundle_manifest,
        "scratch": args.scratch,
        "output": args.output,
        "environment_instance_id": args.environment_instance_id,
    }
    if any(value is None for value in required.values()):
        parser.error("host mode requires bundle, manifest, scratch, output and environment ID")
    receipt = qualify(**required)
    print(json.dumps(receipt.model_dump(mode="json"), sort_keys=True))


if __name__ == "__main__":
    main()
