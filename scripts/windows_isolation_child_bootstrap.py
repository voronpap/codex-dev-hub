"""Stdlib-only bootstrap for the Windows native isolation child probe.

The bootstrap proves that the AppContainer child reached an allowed writable
root before importing the heavier probe and records only bounded error classes
and numeric OS codes.  Its exact bytes are bound into the isolation profile.
"""

from __future__ import annotations

import _sha2  # type: ignore[import-not-found]  # CPython built-in; verified by the bundle gate.
import importlib
import json
import ntpath
import os
import posixpath
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
EXIT_DLL_DIRECTORY_BINDING = 208
EXIT_MATRIX_HASHLIB_V5 = 209
EXIT_MATRIX_SSL_V5 = 210
EXIT_NATIVE_LOADER_ACTIVATION = 211
EXIT_MATRIX_CTYPES_V6 = 212
MAX_FAILURE_BYTES = 4096
NATIVE_LOADER_MODULE = ("python/_devfabric_native_loader.pyd", "_devfabric_native_loader.pyd")
NATIVE_LOADER_DEPENDENCIES = ("libffi-8.dll", "libcrypto-3.dll", "libssl-3.dll")
NATIVE_LOADER_FAILURE_STAGES = (
    "module_interpreter_sibling_identity",
    "directory_open_validation",
    "dependency_preopen",
    "dependency_load",
    "loaded_path_query",
    "loaded_file_reopen",
    "file_identity_compare",
)
NATIVE_LOADER_DEPENDENCY_STAGES = frozenset(NATIVE_LOADER_FAILURE_STAGES[2:])
NATIVE_LOADER_BOOTSTRAP_STAGES = (
    "preloaded_module_guard",
    "launcher_authority_validation",
    "module_path_resolve",
    "module_sibling_validation",
    "module_hash_read",
    "module_hash_validation",
    "module_import",
    "module_origin_validation",
    "helper_activation",
    "activation_result_validation",
)
NATIVE_IMPORT_MATRIX = (
    ("_ctypes", "python/_ctypes.pyd", "_ctypes.pyd", EXIT_MATRIX_CTYPES_V6),
    ("_socket", "python/_socket.pyd", "_socket.pyd", EXIT_MATRIX_SOCKET),
    ("_overlapped", "python/_overlapped.pyd", "_overlapped.pyd", EXIT_MATRIX_OVERLAPPED),
    ("select", "python/select.pyd", "select.pyd", EXIT_MATRIX_SELECT),
    ("_hashlib", "python/_hashlib.pyd", "_hashlib.pyd", EXIT_MATRIX_HASHLIB_V5),
    ("_ssl", "python/_ssl.pyd", "_ssl.pyd", EXIT_MATRIX_SSL_V5),
)
NATIVE_CRYPTO_FILES = (
    ("python/_hashlib.pyd", "_hashlib.pyd"),
    ("python/_ssl.pyd", "_ssl.pyd"),
    ("python/libcrypto-3.dll", "libcrypto-3.dll"),
    ("python/libssl-3.dll", "libssl-3.dll"),
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


def _normalized_launcher_locator(value: str) -> str:
    """Validate a host-bound launcher locator without filesystem traversal."""

    if not value or "\x00" in value:
        raise ValueError("Launcher locator is empty or contains a NUL")
    if os.name == "nt":
        if "/" in value or value.startswith(("\\\\", "\\\\?\\", "\\\\.\\")):
            raise ValueError("Launcher locator must use a local drive-qualified path")
        drive, tail = ntpath.splitdrive(value)
        if (
            len(drive) != 2
            or drive[1] != ":"
            or drive[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            or not tail.startswith("\\")
        ):
            raise ValueError("Launcher locator must use a local drive-qualified path")
        parts = tail.split("\\")[1:]
        if not parts or any(
            part in {"", ".", ".."} or ":" in part or part.rstrip(" .") != part for part in parts
        ):
            raise ValueError("Launcher locator contains a non-canonical path segment")
        normalized = ntpath.normpath(value)
        if ntpath.basename(normalized).casefold() != "python.exe":
            raise ValueError("Launcher locator must name python.exe")
        return ntpath.normcase(normalized)

    # Platform-independent tests import this Windows bootstrap. Keep an
    # equivalent lexical contract without treating a POSIX path as Windows
    # authority in production.
    if not value.startswith("/") or "\\" in value:
        raise ValueError("Test launcher locator must be an absolute POSIX path")
    parts = value.split("/")[1:]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Launcher locator contains a non-canonical path segment")
    normalized = posixpath.normpath(value)
    if not posixpath.basename(normalized):
        raise ValueError("Test launcher locator must name an executable")
    return normalized


def _reviewed_runtime_root(expected_launcher_locator: str) -> Path:
    expected = _normalized_launcher_locator(expected_launcher_locator)
    observed = _normalized_launcher_locator(sys.executable)
    if observed != expected:
        raise RuntimeError("Runtime launcher differs from host-bound authority")
    parent = (
        ntpath.dirname(expected_launcher_locator)
        if os.name == "nt"
        else posixpath.dirname(expected_launcher_locator)
    )
    return Path(parent)


def _launcher_locator_sha256(value: str) -> str:
    return str(_sha2.sha256(_normalized_launcher_locator(value).encode("utf-8")).hexdigest())


def _normalized_runtime_member(value: str, filename: str) -> str:
    if not value or "\x00" in value:
        raise ValueError("Runtime member locator is empty or contains a NUL")
    if os.name == "nt":
        if "/" in value or value.startswith(("\\\\", "\\\\?\\", "\\\\.\\")):
            raise ValueError("Runtime member must use a local drive-qualified path")
        drive, tail = ntpath.splitdrive(value)
        parts = tail.split("\\")[1:] if tail.startswith("\\") else []
        if (
            len(drive) != 2
            or drive[1] != ":"
            or drive[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            or not parts
            or any(
                part in {"", ".", ".."} or ":" in part or part.rstrip(" .") != part
                for part in parts
            )
        ):
            raise ValueError("Runtime member locator is not canonical")
        normalized = ntpath.normcase(ntpath.normpath(value))
        if ntpath.basename(normalized) != filename.casefold():
            raise ValueError("Runtime member filename differs from reviewed authority")
        return normalized

    if not value.startswith("/") or "\\" in value:
        raise ValueError("Test runtime member must be an absolute POSIX path")
    parts = value.split("/")[1:]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Runtime member locator is not canonical")
    normalized = posixpath.normpath(value)
    if posixpath.basename(normalized) != filename:
        raise ValueError("Runtime member filename differs from reviewed authority")
    return normalized


def _reviewed_runtime_member(runtime_root: Path, raw: str, filename: str) -> Path:
    expected = (
        ntpath.normcase(ntpath.join(str(runtime_root), filename))
        if os.name == "nt"
        else posixpath.join(str(runtime_root), filename)
    )
    if _normalized_runtime_member(raw, filename) != expected:
        raise RuntimeError("Runtime member differs from reviewed interpreter sibling")
    return Path(raw)


def _native_file_observation(
    runtime_root: Path, relative_path: str, filename: str
) -> dict[str, object]:
    target = runtime_root / filename
    try:
        observed_sha256 = _sha2.sha256(target.read_bytes()).hexdigest()
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
        "schema_version": 3,
        "status": status,
    }


def _native_crypto_observation(
    runtime_root: Path, relative_path: str, filename: str
) -> dict[str, object]:
    observation = _native_file_observation(runtime_root, relative_path, filename)
    observation["schema_version"] = 1
    return observation


def _run_native_import_matrix(
    runtime_root: Path,
) -> tuple[list[dict[str, object]], BaseException | None, int | None]:
    observations: list[dict[str, object]] = [
        {
            "module": module,
            "file": _native_file_observation(runtime_root, relative_path, filename),
            "import_status": "not_attempted",
            "schema_version": 3,
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


def _activate_native_loader(
    expected_sha256: str,
    expected_launcher_locator: str,
) -> tuple[dict[str, object], BaseException | None, str | None, dict[str, object] | None]:
    """Activate only the reviewed interpreter-sibling native loader."""

    relative_path, filename = NATIVE_LOADER_MODULE
    observation: dict[str, object] = {
        "activated_dependencies": [],
        "error_code": None,
        "module_path": relative_path,
        "module_sha256": None,
        "schema_version": 2,
        "status": "failed",
    }
    bootstrap_stage = "preloaded_module_guard"
    try:
        if any(module in sys.modules for module, *_ in NATIVE_IMPORT_MATRIX):
            raise RuntimeError("Reviewed native module loaded before native-loader activation")
        bootstrap_stage = "launcher_authority_validation"
        runtime_root = _reviewed_runtime_root(expected_launcher_locator)
        bootstrap_stage = "module_path_resolve"
        module_path = _reviewed_runtime_member(runtime_root, str(runtime_root / filename), filename)
        bootstrap_stage = "module_sibling_validation"
        if module_path.parent != runtime_root or module_path.name != filename:
            raise RuntimeError("Native-loader module is not the interpreter sibling")
        bootstrap_stage = "module_hash_read"
        observed_sha256 = _sha2.sha256(module_path.read_bytes()).hexdigest()
        bootstrap_stage = "module_hash_validation"
        if observed_sha256 != expected_sha256:
            raise RuntimeError("Native-loader module hash differs from reviewed authority")
        bootstrap_stage = "module_import"
        loader = importlib.import_module("_devfabric_native_loader")
        bootstrap_stage = "module_origin_validation"
        origin_raw = getattr(loader, "__file__", None)
        if not isinstance(origin_raw, str):
            raise RuntimeError("Imported native-loader origin is unavailable")
        origin = _reviewed_runtime_member(runtime_root, origin_raw, filename)
        if origin != module_path:
            raise RuntimeError("Imported native-loader origin differs from reviewed sibling")
        bootstrap_stage = "helper_activation"
        activated = loader.activate()
        bootstrap_stage = "activation_result_validation"
        if activated != NATIVE_LOADER_DEPENDENCIES:
            raise RuntimeError("Native-loader activation result differs from reviewed order")
    except BaseException as error:
        observation["error_code"] = _numeric_code(error, "winerror") or _numeric_code(
            error, "errno"
        )
        return observation, error, bootstrap_stage, _native_loader_failure(error)
    observation.update(
        {
            "activated_dependencies": list(NATIVE_LOADER_DEPENDENCIES),
            "module_sha256": observed_sha256,
            "status": "active",
        }
    )
    return observation, None, None, None


def _native_loader_failure(error: BaseException) -> dict[str, object] | None:
    """Retain only helper-emitted bounded stage/dependency/code attributes."""

    stage = getattr(error, "devfabric_failure_stage", None)
    dependency = getattr(error, "devfabric_failure_dependency", None)
    winerror = _numeric_code(error, "winerror")
    if stage not in NATIVE_LOADER_FAILURE_STAGES or winerror is None:
        return None
    dependency_stage = stage in NATIVE_LOADER_DEPENDENCY_STAGES
    if dependency_stage:
        if dependency not in NATIVE_LOADER_DEPENDENCIES:
            return None
    elif dependency is not None:
        return None
    return {
        "dependency": dependency,
        "schema_version": 1,
        "stage": stage,
        "winerror": winerror,
    }


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
    native_loader_activation: dict[str, object],
    failed_matrix_module: str | None = None,
    native_loader_bootstrap_stage: str | None = None,
    native_loader_failure: dict[str, object] | None = None,
    runtime_root: Path | None = None,
    expected_launcher_locator_sha256: str | None = None,
    observed_launcher_locator_sha256: str | None = None,
) -> None:
    exception_class = type(error).__name__
    if (
        len(exception_class) > 128
        or not exception_class.isascii()
        or not exception_class.isidentifier()
    ):
        raise _FailureFrameTooLarge
    loader_failure = phase in {
        "bootstrap_native_loader",
        "bootstrap_native_matrix",
        "bootstrap_import",
    }
    loader_reason, loader_code = _loader_diagnostic(error) if loader_failure else (None, None)
    encoded = _canonical(
        {
            "errno": _numeric_code(error, "errno"),
            "native_loader_activation": native_loader_activation,
            "native_loader_bootstrap_stage": native_loader_bootstrap_stage,
            "native_loader_failure": native_loader_failure,
            "exception_class": exception_class,
            "failed_matrix_module": failed_matrix_module,
            "import_boundary": _import_boundary(error) if phase == "bootstrap_import" else None,
            "loader_code": loader_code,
            "loader_reason": loader_reason,
            "expected_launcher_locator_sha256": expected_launcher_locator_sha256,
            "observed_launcher_locator_sha256": observed_launcher_locator_sha256,
            "native_import_matrix": native_import_matrix,
            "native_crypto_observations": (
                [
                    _native_crypto_observation(runtime_root, relative_path, filename)
                    for relative_path, filename in NATIVE_CRYPTO_FILES
                ]
                if runtime_root is not None
                else [
                    {
                        "observed_sha256": None,
                        "relative_path": relative_path,
                        "schema_version": 1,
                        "status": "other_error",
                    }
                    for relative_path, _ in NATIVE_CRYPTO_FILES
                ]
            ),
            "phase": phase,
            "schema_version": 9,
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
            "bootstrap_started_id": _sha2.sha256(_canonical(payload)).hexdigest(),
            "payload": payload,
        }
    )


def main() -> int:
    if len(sys.argv) != 13:
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
        expected_native_loader_sha256,
        expected_launcher_locator,
        expected_launcher_locator_sha256,
    ) = sys.argv
    child_script = Path(child_script_raw)
    request_path = Path(request_raw)
    result_path = Path(result_raw)
    failure_path = Path(failure_raw)
    status_path = Path(status_raw)
    try:
        observed_bootstrap_sha256 = _sha2.sha256(Path(__file__).read_bytes()).hexdigest()
    except OSError:
        return EXIT_SELF_HASH_MISMATCH
    if observed_bootstrap_sha256 != expected_bootstrap_sha256:
        return EXIT_SELF_HASH_MISMATCH
    try:
        observed_probe_sha256 = _sha2.sha256(child_script.read_bytes()).hexdigest()
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

    runtime_root: Path | None = None
    observed_launcher_locator_sha256: str | None = None
    launcher_error: BaseException | None = None
    try:
        if _launcher_locator_sha256(expected_launcher_locator) != expected_launcher_locator_sha256:
            raise RuntimeError("Launcher locator argument differs from sealed authority")
        observed_launcher_locator_sha256 = _launcher_locator_sha256(sys.executable)
        runtime_root = _reviewed_runtime_root(expected_launcher_locator)
    except BaseException as error:
        launcher_error = error
    if launcher_error is None:
        (
            native_loader_activation,
            activation_error,
            native_loader_bootstrap_stage,
            native_loader_failure,
        ) = _activate_native_loader(expected_native_loader_sha256, expected_launcher_locator)
    else:
        native_loader_activation = {
            "activated_dependencies": [],
            "error_code": _numeric_code(launcher_error, "winerror")
            or _numeric_code(launcher_error, "errno"),
            "module_path": "python/_devfabric_native_loader.pyd",
            "module_sha256": None,
            "schema_version": 2,
            "status": "failed",
        }
        activation_error = launcher_error
        native_loader_bootstrap_stage = "launcher_authority_validation"
        native_loader_failure = None
    if activation_error is not None:
        native_import_matrix: list[dict[str, object]] = [
            {
                "module": module,
                "file": (
                    _native_file_observation(runtime_root, relative_path, filename)
                    if runtime_root is not None
                    else {
                        "observed_sha256": None,
                        "relative_path": relative_path,
                        "schema_version": 3,
                        "status": "other_error",
                    }
                ),
                "import_status": "not_attempted",
                "schema_version": 3,
            }
            for module, relative_path, filename, _ in NATIVE_IMPORT_MATRIX
        ]
        try:
            _write_failure(
                failure_path,
                "bootstrap_native_loader",
                activation_error,
                native_import_matrix,
                native_loader_activation,
                native_loader_bootstrap_stage=native_loader_bootstrap_stage,
                native_loader_failure=native_loader_failure,
                runtime_root=runtime_root,
                expected_launcher_locator_sha256=expected_launcher_locator_sha256,
                observed_launcher_locator_sha256=observed_launcher_locator_sha256,
            )
        except _FailureFrameTooLarge:
            return EXIT_IMPORT_FAILURE_TOO_LARGE
        except BaseException:
            return EXIT_IMPORT_FAILURE_WRITE_DENIED
        return EXIT_NATIVE_LOADER_ACTIVATION

    if runtime_root is None:
        return EXIT_NATIVE_LOADER_ACTIVATION
    native_import_matrix, matrix_error, matrix_exit = _run_native_import_matrix(runtime_root)
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
                native_loader_activation,
                str(failed),
                runtime_root=runtime_root,
                expected_launcher_locator_sha256=expected_launcher_locator_sha256,
                observed_launcher_locator_sha256=observed_launcher_locator_sha256,
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
        guarded = namespace.get("_child_guarded_v7")
        if not callable(guarded):
            raise RuntimeError("reviewed child entry point is unavailable")
    except BaseException as error:
        try:
            _write_failure(
                failure_path,
                "bootstrap_import",
                error,
                native_import_matrix,
                native_loader_activation,
                runtime_root=runtime_root,
                expected_launcher_locator_sha256=expected_launcher_locator_sha256,
                observed_launcher_locator_sha256=observed_launcher_locator_sha256,
            )
        except _FailureFrameTooLarge:
            return EXIT_IMPORT_FAILURE_TOO_LARGE
        except BaseException:
            return EXIT_IMPORT_FAILURE_WRITE_DENIED
        return _classified_import_exit(error)

    try:
        return int(
            guarded(
                request_path,
                result_path,
                failure_path,
                native_loader_activation,
                native_import_matrix,
                observed_launcher_locator_sha256,
            )
        )
    except BaseException as error:
        try:
            _write_failure(
                failure_path,
                "bootstrap_invoke",
                error,
                native_import_matrix,
                native_loader_activation,
                runtime_root=runtime_root,
                expected_launcher_locator_sha256=expected_launcher_locator_sha256,
                observed_launcher_locator_sha256=observed_launcher_locator_sha256,
            )
        except _FailureFrameTooLarge:
            return EXIT_INVOKE_FAILURE_TOO_LARGE
        except BaseException:
            return EXIT_INVOKE_FAILURE_WRITE_DENIED
        return EXIT_INVOKE_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
