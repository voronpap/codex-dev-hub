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
MAX_FAILURE_BYTES = 4096


class _FailureFrameTooLarge(Exception):
    pass


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
    encoded = _canonical(
        {
            "errno": _numeric_code(error, "errno"),
            "exception_class": exception_class,
            "phase": phase,
            "schema_version": 2,
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
        return EXIT_IMPORT_FAILED

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
