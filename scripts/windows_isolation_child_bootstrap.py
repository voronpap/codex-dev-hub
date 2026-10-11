"""Stdlib-only bootstrap for the Windows native isolation child probe.

The bootstrap proves that the AppContainer child reached an allowed writable
root before importing the heavier probe and records only bounded error classes
and numeric OS codes.  Its exact bytes are bound into the isolation profile.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import runpy
import sys
from pathlib import Path

EXIT_ARGUMENTS_INVALID = 189
EXIT_SELF_HASH_MISMATCH = 190
EXIT_PROBE_HASH_MISMATCH = 191
EXIT_STATUS_WRITE_DENIED = 192
EXIT_IMPORT_FAILED = 193
EXIT_IMPORT_FAILURE_WRITE_DENIED = 194
EXIT_IMPORT_FAILURE_TOO_LARGE = 195
EXIT_INVOKE_FAILED = 196
EXIT_INVOKE_FAILURE_WRITE_DENIED = 197
EXIT_INVOKE_FAILURE_TOO_LARGE = 198
EXIT_IMPORT_CTYPES = 199
EXIT_IMPORT_SOCKET = 200
EXIT_IMPORT_PYDANTIC_CORE = 201
EXIT_IMPORT_DEVHUB = 202
EXIT_IMPORT_UNKNOWN = 203
EXIT_MATRIX_SOCKET = 204
EXIT_MATRIX_OVERLAPPED = 205
EXIT_MATRIX_SELECT = 206
EXIT_MATRIX_SSL = 207
MAX_FAILURE_BYTES = 4096
NATIVE_LOADER_FILES = (
    ("python/_ctypes.pyd", "_ctypes.pyd"),
    ("python/libffi-8.dll", "libffi-8.dll"),
)
NATIVE_IMPORT_MATRIX = (
    ("_socket", "python/_socket.pyd", "_socket.pyd", EXIT_MATRIX_SOCKET),
    ("_overlapped", "python/_overlapped.pyd", "_overlapped.pyd", EXIT_MATRIX_OVERLAPPED),
    ("select", "python/select.pyd", "select.pyd", EXIT_MATRIX_SELECT),
    ("_ssl", "python/_ssl.pyd", "_ssl.pyd", EXIT_MATRIX_SSL),
)
LOADER_DETAILS = {
    "access is denied": ("access_denied", 5),
    "the specified module could not be found": ("dependency_not_found", 126),
    "the specified procedure could not be found": ("procedure_not_found", 127),
    "%1 is not a valid win32 application": ("bad_image", 193),
    "a dynamic link library (dll) initialization routine failed": (
        "initialization_failed",
        1114,
    ),
}


class _FailureFrameTooLarge(Exception):
    pass


def _classified_import_exit(error: BaseException) -> int:
    """Classify allowlisted import boundaries without retaining error text or paths."""

    if not isinstance(error, ImportError):
        return EXIT_IMPORT_FAILED
    name = error.name
    if name == "_ctypes":
        return EXIT_IMPORT_CTYPES
    if name == "_socket":
        return EXIT_IMPORT_SOCKET
    if name == "pydantic_core" or (isinstance(name, str) and name.startswith("pydantic_core.")):
        return EXIT_IMPORT_PYDANTIC_CORE
    if name == "devhub" or (isinstance(name, str) and name.startswith("devhub.")):
        return EXIT_IMPORT_DEVHUB
    return EXIT_IMPORT_UNKNOWN


def _import_boundary(error: BaseException) -> str:
    if not isinstance(error, ImportError):
        return "unknown"
    name = error.name
    if name == "_ctypes":
        return "ctypes"
    if name == "_socket":
        return "socket"
    if name == "pydantic_core" or (isinstance(name, str) and name.startswith("pydantic_core.")):
        return "pydantic_core"
    if name == "devhub" or (isinstance(name, str) and name.startswith("devhub.")):
        return "devhub"
    return "unknown"


def _loader_diagnostic(error: BaseException) -> tuple[str, int | None]:
    """Parse only reviewed CPython loader forms without retaining raw text or paths."""

    if not isinstance(error, ImportError):
        return "unknown", None
    message = str(error).strip()
    prefixes = ["DLL load failed: "]
    if isinstance(error.name, str) and error.name.isidentifier():
        prefixes.append(f"DLL load failed while importing {error.name}: ")
    detail: str | None = None
    for prefix in prefixes:
        if message.startswith(prefix):
            detail = message.removeprefix(prefix).strip()
            break
    if detail is None:
        return "unknown", None
    normalized = detail.removesuffix(".").casefold()
    for reviewed, (reason, code) in LOADER_DETAILS.items():
        plain = reviewed.casefold()
        with_code = f"[winerror {code}] {reviewed}".casefold()
        if normalized in {plain, with_code}:
            return reason, code
    return "unknown", None


def _loader_reason(error: BaseException) -> str:
    return _loader_diagnostic(error)[0]


def _native_loader_observations() -> list[dict[str, object]]:
    runtime_root = Path(sys.executable).resolve().parent
    observations: list[dict[str, object]] = []
    for relative_path, filename in NATIVE_LOADER_FILES:
        target = runtime_root / filename
        try:
            observed_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
            status = "readable"
        except FileNotFoundError:
            observed_sha256 = None
            status = "missing"
        except PermissionError:
            observed_sha256 = None
            status = "access_denied"
        except OSError:
            observed_sha256 = None
            status = "other_error"
        observations.append(
            {
                "observed_sha256": observed_sha256,
                "relative_path": relative_path,
                "status": status,
            }
        )
    return observations


def _native_file_observation(relative_path: str, filename: str) -> dict[str, object]:
    target = Path(sys.executable).resolve().parent / filename
    try:
        observed_sha256 = hashlib.sha256(target.read_bytes()).hexdigest()
        status = "readable"
    except FileNotFoundError:
        observed_sha256 = None
        status = "missing"
    except PermissionError:
        observed_sha256 = None
        status = "access_denied"
    except OSError:
        observed_sha256 = None
        status = "other_error"
    return {
        "observed_sha256": observed_sha256,
        "relative_path": relative_path,
        "status": status,
    }


def _run_native_import_matrix() -> tuple[list[dict[str, object]], BaseException | None, int | None]:
    observations: list[dict[str, object]] = [
        {
            "module": module,
            "file": _native_file_observation(relative_path, filename),
            "import_status": "not_attempted",
        }
        for module, relative_path, filename, _ in NATIVE_IMPORT_MATRIX
    ]
    for index, (module, _, _, exit_code) in enumerate(NATIVE_IMPORT_MATRIX):
        try:
            importlib.import_module(module)
        except BaseException as error:
            observations[index]["import_status"] = "failed"
            return observations, error, exit_code
        observations[index]["import_status"] = "imported"
    return observations, None, None


def _canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _atomic_write(path: Path, payload: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("bootstrap write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def _numeric_code(error: BaseException, name: str) -> int | None:
    value = getattr(error, name, None)
    return value if isinstance(value, int) else None


def _write_failure(
    path: Path,
    phase: str,
    error: BaseException,
    native_import_matrix: list[dict[str, object]],
    failed_matrix_module: str | None = None,
) -> None:
    exception_class = type(error).__name__
    if (
        len(exception_class) > 128
        or not exception_class.isascii()
        or not exception_class.isidentifier()
    ):
        raise _FailureFrameTooLarge
    loader_failure = phase in {"bootstrap_native_matrix", "bootstrap_import"}
    loader_reason, loader_code = _loader_diagnostic(error) if loader_failure else (None, None)
    encoded = _canonical(
        {
            "errno": _numeric_code(error, "errno"),
            "exception_class": exception_class,
            "failed_matrix_module": failed_matrix_module,
            "import_boundary": _import_boundary(error) if phase == "bootstrap_import" else None,
            "loader_code": loader_code,
            "loader_reason": loader_reason,
            "native_import_matrix": native_import_matrix,
            "native_loader_observations": (
                _native_loader_observations() if phase == "bootstrap_import" else []
            ),
            "phase": phase,
            "schema_version": 4,
            "winerror": _numeric_code(error, "winerror"),
        }
    )
    if len(encoded) > MAX_FAILURE_BYTES:
        raise _FailureFrameTooLarge
    _atomic_write(path, encoded)


def _started_frame(
    bootstrap_sha256: str,
    environment_instance_id: str,
    profile_id: str,
    probe_sha256: str,
) -> bytes:
    payload = {
        "child_bootstrap_sha256": bootstrap_sha256,
        "environment_instance_id": environment_instance_id,
        "phase": "bootstrap_started",
        "probe_sha256": probe_sha256,
        "schema_version": 1,
        "windows_isolation_profile_id": profile_id,
    }
    return _canonical(
        {
            "bootstrap_started_id": hashlib.sha256(_canonical(payload)).hexdigest(),
            "payload": payload,
        }
    )


def main() -> int:
    if len(sys.argv) != 10:
        return EXIT_ARGUMENTS_INVALID
    (
        _,
        child_script_raw,
        request_raw,
        result_raw,
        failure_raw,
        status_raw,
        expected_bootstrap_sha256,
        environment_instance_id,
        profile_id,
        probe_sha256,
    ) = sys.argv
    child_script = Path(child_script_raw)
    request_path = Path(request_raw)
    result_path = Path(result_raw)
    failure_path = Path(failure_raw)
    status_path = Path(status_raw)
    try:
        observed_bootstrap_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        return EXIT_SELF_HASH_MISMATCH
    if observed_bootstrap_sha256 != expected_bootstrap_sha256:
        return EXIT_SELF_HASH_MISMATCH
    try:
        observed_probe_sha256 = hashlib.sha256(child_script.read_bytes()).hexdigest()
    except OSError:
        return EXIT_PROBE_HASH_MISMATCH
    if observed_probe_sha256 != probe_sha256:
        return EXIT_PROBE_HASH_MISMATCH
    try:
        _atomic_write(
            status_path,
            _started_frame(
                expected_bootstrap_sha256,
                environment_instance_id,
                profile_id,
                probe_sha256,
            ),
        )
    except BaseException:
        return EXIT_STATUS_WRITE_DENIED

    native_import_matrix, matrix_error, matrix_exit = _run_native_import_matrix()
    if (matrix_error is None) != (matrix_exit is None):
        return EXIT_IMPORT_FAILED
    if matrix_error is not None:
        if matrix_exit is None:
            return EXIT_IMPORT_FAILED
        failed = next(
            item["module"] for item in native_import_matrix if item["import_status"] == "failed"
        )
        try:
            _write_failure(
                failure_path,
                "bootstrap_native_matrix",
                matrix_error,
                native_import_matrix,
                str(failed),
            )
        except _FailureFrameTooLarge:
            return EXIT_IMPORT_FAILURE_TOO_LARGE
        except BaseException:
            return EXIT_IMPORT_FAILURE_WRITE_DENIED
        return matrix_exit

    sys.argv = [
        str(child_script),
        "--child",
        str(request_path),
        str(result_path),
        str(failure_path),
    ]
    try:
        namespace = runpy.run_path(str(child_script), run_name="devfabric_windows_isolation_child")
        guarded = namespace.get("_child_guarded")
        if not callable(guarded):
            raise RuntimeError("reviewed child entry point is unavailable")
    except BaseException as error:
        try:
            _write_failure(failure_path, "bootstrap_import", error, native_import_matrix)
        except _FailureFrameTooLarge:
            return EXIT_IMPORT_FAILURE_TOO_LARGE
        except BaseException:
            return EXIT_IMPORT_FAILURE_WRITE_DENIED
        return _classified_import_exit(error)

    try:
        return int(guarded(request_path, result_path, failure_path))
    except BaseException as error:
        try:
            _write_failure(failure_path, "bootstrap_invoke", error, native_import_matrix)
        except _FailureFrameTooLarge:
            return EXIT_INVOKE_FAILURE_TOO_LARGE
        except BaseException:
            return EXIT_INVOKE_FAILURE_WRITE_DENIED
        return EXIT_INVOKE_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
