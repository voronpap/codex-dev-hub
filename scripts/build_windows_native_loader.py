"""Build the fixed Windows native-loader extension and seal its exact identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import cast

from pydantic import JsonValue

from devhub.benchmark import canonical, digest, write_new
from devhub.native_bundle import (
    NativeLoaderBuildPayloadV2,
    NativeLoaderBuildV2,
    NativeLoaderDependencyName,
    NativeLoaderDependencyV1,
    NativeLoaderFailureV1,
    NativeLoaderPostBuildProofV2,
    NativeLoaderWorkflowV1,
    file_sha256,
    git_blob_bytes,
    git_blob_sha256,
)

MODULE = "_devfabric_native_loader"
SOURCE = "native/windows_loader/devfabric_native_loader.c"
BINARY = f"{MODULE}.pyd"
DEPENDENCIES = ("libffi-8.dll", "libcrypto-3.dll", "libssl-3.dll")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _output(argv: list[str]) -> str:
    return subprocess.check_output(argv, text=True, stderr=subprocess.STDOUT).strip()


def _tool_version(argv: list[str]) -> str:
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = result.stdout.strip()
    if not output:
        raise ValueError("Native-loader tool version output is empty")
    return output.splitlines()[0]


def _clean_commit(repo: Path, expected_commit: str) -> str:
    if not COMMIT.fullmatch(expected_commit):
        raise ValueError("Expected implementation commit is invalid")
    head = _output(["git", "-C", str(repo), "rev-parse", "HEAD"])
    if head != expected_commit:
        raise ValueError("Native-loader build HEAD differs from expected commit")
    if _output(["git", "-C", str(repo), "status", "--porcelain"]):
        raise ValueError("Native-loader build requires an exact clean commit")
    return head


def _header_inventory(include: Path) -> tuple[str, int]:
    records: list[dict[str, object]] = []
    for path in sorted(include.rglob("*.h")):
        if path.is_symlink() or not path.is_file():
            raise ValueError("CPython header inventory contains a non-plain file")
        records.append(
            {
                "path": path.relative_to(include).as_posix(),
                "size": path.stat().st_size,
                "sha256": file_sha256(path),
            }
        )
    if not records:
        raise ValueError("CPython header inventory is empty")
    return digest(canonical(cast(JsonValue, records))), len(records)


def _pe_machine(path: Path) -> str:
    raw = path.read_bytes()
    if len(raw) < 64 or raw[:2] != b"MZ":
        raise ValueError("Native-loader output is not a PE image")
    offset = struct.unpack_from("<I", raw, 0x3C)[0]
    if offset + 6 > len(raw) or raw[offset : offset + 4] != b"PE\0\0":
        raise ValueError("Native-loader output has an invalid PE header")
    machine = struct.unpack_from("<H", raw, offset + 4)[0]
    if machine != 0x8664:
        raise ValueError("Native-loader output is not Windows AMD64")
    return "0x8664"


def _materialize_source_snapshot(repo: Path, commit: str, stage: Path) -> tuple[Path, str]:
    raw = git_blob_bytes(repo, commit, SOURCE)
    target = stage / "devfabric_native_loader.c"
    target.write_bytes(raw)
    blob_sha256 = hashlib.sha256(raw).hexdigest()
    if file_sha256(target) != blob_sha256:
        raise ValueError("Native-loader source snapshot differs from its Git blob")
    return target, blob_sha256


def _run_isolated(runtime: Path, code: str, *, hostile_path: Path | None = None) -> str:
    environment = {
        "SYSTEMROOT": os.environ["SYSTEMROOT"],
        "TEMP": str(runtime),
        "TMP": str(runtime),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PATH": str(hostile_path) if hostile_path is not None else "",
    }
    result = subprocess.run(
        [str(runtime / "python.exe"), "-I", "-B", "-c", code],
        text=True,
        capture_output=True,
        env=environment,
        cwd=runtime,
        timeout=60,
    )
    if result.returncode != 0:
        raise ValueError(f"Native-loader isolated proof failed with exit {result.returncode}")
    return result.stdout.strip()


def _copy_runtime(source: Path, target: Path, binary: Path) -> None:
    shutil.copytree(source, target)
    shutil.copy2(binary, target / BINARY)


def _positive_proof_code() -> str:
    """Return the proof whose first successful activation is concurrent."""

    return (
        "import importlib,json,pathlib,sys;"
        "assert '_ctypes' not in sys.modules and '_hashlib' not in sys.modules "
        "and '_ssl' not in sys.modules;"
        "loader=importlib.import_module('_devfabric_native_loader');"
        "origin=pathlib.Path(loader.__file__).resolve();"
        "assert origin.parent==pathlib.Path(sys.executable).resolve().parent;"
        "rejected=False;"
        "\ntry: loader.activate('ambient')\nexcept TypeError: rejected=True\n"
        "assert rejected;"
        "import concurrent.futures,threading;"
        "barrier=threading.Barrier(8);"
        "\ndef first_activate(_index):\n"
        " barrier.wait()\n"
        " return loader.activate()\n"
        "\nwith concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:\n"
        " results=list(pool.map(first_activate,range(8)))\n"
        "assert all(item==('libffi-8.dll','libcrypto-3.dll','libssl-3.dll') for item in results);"
        "assert all(loader.activate()==('libffi-8.dll','libcrypto-3.dll','libssl-3.dll') "
        "for _index in range(64));"
        "modules=['_ctypes','_socket','_overlapped','select','_hashlib','_ssl'];"
        "[importlib.import_module(name) for name in modules];"
        "print(json.dumps({'modules':modules,'sibling':True},sort_keys=True))"
    )


def _post_build_proof(
    runtime_root: Path, binary: Path, scratch: Path
) -> NativeLoaderPostBuildProofV2:
    positive = scratch / "relocated-positive"
    _copy_runtime(runtime_root, positive, binary)
    hostile = scratch / "hostile-path"
    hostile.mkdir()
    for name in DEPENDENCIES:
        (hostile / name).write_bytes(b"MZ-hostile")
    positive_code = _positive_proof_code()
    compile(positive_code, "<native-loader-positive-proof>", "exec")
    observed = json.loads(_run_isolated(positive, positive_code, hostile_path=hostile))
    if observed != {
        "modules": ["_ctypes", "_socket", "_overlapped", "select", "_hashlib", "_ssl"],
        "sibling": True,
    }:
        raise ValueError("Native-loader positive proof output differs from the reviewed contract")

    missing = scratch / "missing-dependency"
    _copy_runtime(runtime_root, missing, binary)
    (missing / "libffi-8.dll").unlink()
    rejection_code = (
        "import _devfabric_native_loader as loader,json;observed=None;"
        "\ntry: loader.activate()\n"
        "except OSError as error:\n"
        " observed={'stage':getattr(error,'devfabric_failure_stage',None),"
        "'dependency':getattr(error,'devfabric_failure_dependency',None),"
        "'winerror':getattr(error,'winerror',None)}\n"
        "assert observed is not None;print(json.dumps(observed,sort_keys=True))"
    )
    compile(rejection_code, "<native-loader-rejection-proof>", "exec")
    missing_failure = NativeLoaderFailureV1.model_validate_json(
        _run_isolated(missing, rejection_code)
    )

    invalid = scratch / "invalid-dependency"
    _copy_runtime(runtime_root, invalid, binary)
    (invalid / "libffi-8.dll").write_bytes(b"MZ-invalid")
    invalid_failure = NativeLoaderFailureV1.model_validate_json(
        _run_isolated(invalid, rejection_code)
    )

    wrong_directory = scratch / "wrong-module-directory"
    shutil.copytree(runtime_root, wrong_directory)
    module_dir = wrong_directory / "extension"
    module_dir.mkdir()
    shutil.copy2(binary, module_dir / BINARY)
    wrong_code = (
        "import importlib.util,json,pathlib;"
        "path=pathlib.Path('extension/_devfabric_native_loader.pyd').resolve();"
        "spec=importlib.util.spec_from_file_location('_devfabric_native_loader',path);"
        "assert spec and spec.loader;loader=importlib.util.module_from_spec(spec);"
        "spec.loader.exec_module(loader);"
        "observed=None;"
        "\ntry: loader.activate()\n"
        "except OSError as error:\n"
        " observed={'stage':getattr(error,'devfabric_failure_stage',None),"
        "'dependency':getattr(error,'devfabric_failure_dependency',None),"
        "'winerror':getattr(error,'winerror',None)}\n"
        "assert observed is not None;print(json.dumps(observed,sort_keys=True))"
    )
    compile(wrong_code, "<native-loader-wrong-directory-proof>", "exec")
    wrong_directory_failure = NativeLoaderFailureV1.model_validate_json(
        _run_isolated(wrong_directory, wrong_code)
    )

    partial = scratch / "partial-load"
    _copy_runtime(runtime_root, partial, binary)
    backup = partial / "libssl-3.dll.reviewed"
    shutil.copy2(partial / "libssl-3.dll", backup)
    (partial / "libssl-3.dll").write_bytes(b"MZ-invalid")
    partial_code = (
        "import _devfabric_native_loader as loader,json,shutil;observed=None;"
        "\ntry: loader.activate()\n"
        "except OSError as error:\n"
        " observed={'stage':getattr(error,'devfabric_failure_stage',None),"
        "'dependency':getattr(error,'devfabric_failure_dependency',None),"
        "'winerror':getattr(error,'winerror',None)}\n"
        "assert observed is not None;shutil.copyfile('libssl-3.dll.reviewed','libssl-3.dll');"
        "assert loader.activate()==('libffi-8.dll','libcrypto-3.dll','libssl-3.dll');"
        "print(json.dumps(observed,sort_keys=True))"
    )
    compile(partial_code, "<native-loader-partial-cleanup-proof>", "exec")
    partial_failure = NativeLoaderFailureV1.model_validate_json(
        _run_isolated(partial, partial_code)
    )
    return NativeLoaderPostBuildProofV2(
        final_binary_sha256=file_sha256(binary),
        missing_dependency_failure=missing_failure,
        invalid_dependency_failure=invalid_failure,
        wrong_module_directory_failure=wrong_directory_failure,
        partial_load_failure=partial_failure,
    )


def build(
    repo: Path,
    output: Path,
    runtime_root: Path,
    expected_commit: str,
    workflow_run_id: int,
    workflow_run_attempt: int,
) -> NativeLoaderBuildV2:
    repo = repo.resolve(strict=True)
    runtime_root = runtime_root.resolve(strict=True)
    commit = _clean_commit(repo, expected_commit)
    if output.exists():
        raise ValueError("Native-loader output must be new")
    if os.name != "nt" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise ValueError("Native-loader build requires Windows AMD64")
    if platform.python_version() != "3.12.10" or sys.implementation.cache_tag != "cpython-312":
        raise ValueError("Native-loader build requires exact CPython 3.12.10")
    compiler = shutil.which("cl.exe")
    linker = shutil.which("link.exe")
    if compiler is None or linker is None:
        raise ValueError("Pinned MSVC developer environment is unavailable")
    compiler_path = Path(compiler).resolve(strict=True)
    linker_path = Path(linker).resolve(strict=True)
    include = Path(sysconfig.get_path("include")).resolve(strict=True)
    libs = Path(sys.base_prefix, "libs").resolve(strict=True)
    import_library = (libs / "python312.lib").resolve(strict=True)
    headers_sha256, header_count = _header_inventory(include)
    runtime_python = (runtime_root / "python.exe").resolve(strict=True)
    dependencies = tuple(
        NativeLoaderDependencyV1(
            filename=cast(NativeLoaderDependencyName, name),
            sha256=file_sha256((runtime_root / name).resolve(strict=True)),
        )
        for name in DEPENDENCIES
    )
    compile_flags = ("/nologo", "/LD", "/O2", "/GS", "/guard:cf", "/sdl", "/W3", "/WX")
    link_flags = ("/DYNAMICBASE", "/NXCOMPAT")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="devfabric-native-loader-", dir=output.parent) as raw:
        stage = Path(raw)
        binary = stage / BINARY
        source, source_sha256 = _materialize_source_snapshot(repo, commit, stage)
        command = [
            str(compiler_path),
            *compile_flags,
            f"/I{include}",
            str(source),
            "/link",
            f"/OUT:{binary}",
            f"/LIBPATH:{libs}",
            "python312.lib",
            "kernel32.lib",
            *link_flags,
        ]
        subprocess.run(command, check=True, cwd=stage)
        if not binary.is_file():
            raise ValueError("Native-loader build did not produce its exact extension")
        pe_machine = _pe_machine(binary)
        post_build_proof = _post_build_proof(runtime_root, binary, stage / "proof")
        payload = NativeLoaderBuildPayloadV2(
            implementation_commit=commit,
            source_sha256=source_sha256,
            binary_sha256=file_sha256(binary),
            python_executable_sha256=file_sha256(Path(sys.executable).resolve(strict=True)),
            runtime_python_executable_sha256=file_sha256(runtime_python),
            python_import_library_sha256=file_sha256(import_library),
            python_headers_sha256=headers_sha256,
            python_header_count=header_count,
            compiler_path_sha256=file_sha256(compiler_path),
            compiler_version=_tool_version([str(compiler_path), "/Bv"]),
            linker_path_sha256=file_sha256(linker_path),
            linker_version=_tool_version([str(linker_path)]),
            pe_machine=pe_machine,
            compile_flags=compile_flags,
            link_flags=link_flags,
            dependencies=dependencies,
            workflow=NativeLoaderWorkflowV1(
                workflow_sha256=git_blob_sha256(
                    repo, commit, ".github/workflows/windows-native-loader.yml"
                ),
                run_id=workflow_run_id,
                run_attempt=workflow_run_attempt,
            ),
            post_build_proof=post_build_proof,
        )
        receipt = NativeLoaderBuildV2.create(payload)
        receipt_path = stage / "native-loader-build.json"
        write_new(receipt_path, canonical(cast(JsonValue, receipt.model_dump(mode="json"))))
        output.mkdir()
        os.replace(binary, output / BINARY)
        os.replace(receipt_path, output / receipt_path.name)
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--runtime-root", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--workflow-run-id", required=True, type=int)
    parser.add_argument("--workflow-run-attempt", required=True, type=int)
    args = parser.parse_args()
    receipt = build(
        Path(__file__).resolve().parents[1],
        args.output.resolve(),
        args.runtime_root,
        args.expected_commit,
        args.workflow_run_id,
        args.workflow_run_attempt,
    )
    print(json.dumps(receipt.model_dump(mode="json"), sort_keys=True))


if __name__ == "__main__":
    main()
