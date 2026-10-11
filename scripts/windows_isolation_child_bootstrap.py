"""Stdlib-only bootstrap for the Windows native isolation child probe.

The bootstrap proves that the AppContainer child reached an allowed writable
root before importing the heavier probe and records only bounded error classes
and numeric OS codes.  Its exact bytes are bound into the isolation profile.
"""

from __future__ import annotations

import hashlib
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
MAX_FAILURE_BYTES = 4096
NATIVE_LOADER_FILES = (
    ("python/_ctypes.pyd", "_ctypes.pyd"),
    ("python/libffi-8.dll", "libffi-8.dll"),
)


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


def _loader_reason(error: BaseException) -> str:
    """Map loader text to a bounded category without retaining the text or paths."""

    if not isinstance(error, ImportError):
        return "unknown"
    message = str(error).casefold()
    if "access is denied" in message or "permission denied" in message or "winerror 5" in message:
        return "access_denied"
    if "specified module could not be found" in message or "no such file" in message:
        return "dependency_not_found"
    if "not a valid win32 application" in message or "bad image" in message:
        return "bad_image"
    if "specified procedure could not be found" in message:
        return "procedure_not_found"
    return "unknown"


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


def _write_failure(path: Path, phase: str, error: BaseException) -> None:
    exception_class = type(error).__name__
    if (
        len(exception_class) > 128
        or not exception_class.isascii()
        or not exception_class.isidentifier()
    ):
        raise _FailureFrameTooLarge
    bootstrap_import = phase == "bootstrap_import"
    encoded = _canonical(
        {
            "errno": _numeric_code(error, "errno"),
            "exception_class": exception_class,
            "import_boundary": _import_boundary(error) if bootstrap_import else None,
            "loader_reason": _loader_reason(error) if bootstrap_import else None,
            "native_loader_observations": (
                _native_loader_observations() if bootstrap_import else []
            ),
            "phase": phase,
            "schema_version": 3,
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
            _write_failure(failure_path, "bootstrap_import", error)
        except _FailureFrameTooLarge:
            return EXIT_IMPORT_FAILURE_TOO_LARGE
        except BaseException:
            return EXIT_IMPORT_FAILURE_WRITE_DENIED
        return _classified_import_exit(error)

    try:
        return int(guarded(request_path, result_path, failure_path))
    except BaseException as error:
        try:
            _write_failure(failure_path, "bootstrap_invoke", error)
        except _FailureFrameTooLarge:
            return EXIT_INVOKE_FAILURE_TOO_LARGE
        except BaseException:
            return EXIT_INVOKE_FAILURE_WRITE_DENIED
        return EXIT_INVOKE_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
