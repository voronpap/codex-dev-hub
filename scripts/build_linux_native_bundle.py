"""Build one immutable native Linux directory from exact reviewed authorities."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path
from typing import Literal, cast

from pydantic import JsonValue

from devhub.benchmark import canonical, write_new
from devhub.linux_bundle import (
    LinuxCodexAuthorityV6,
    LinuxLauncherV2,
    LinuxNativeArchivePayloadV9,
    LinuxNativeArchiveV9,
    LinuxNativeBundlePayloadV9,
    LinuxNativeBundleV9,
    LinuxPythonAuthorityV1,
    LinuxRuntimeClosureV1,
    LinuxRuntimeLibraryV1,
    inspect_linux_dynamic_elf,
    inventory_linux_bundle,
    is_linux_dynamic_elf,
    observe_linux_runtime,
    verify_linux_native_bundle,
    verify_linux_native_release,
)
from devhub.linux_native import LinuxNativeCodexBuildV12
from devhub.native_bundle import (
    file_sha256,
    review_dependency_wheels,
    sanitize_installed_wheel_tree,
)
from devhub.native_proof import LinuxNativeBuildArtifactJoinV1, NativeBuildArtifactInventoryV2

PIP_BUILD_VERSION = "26.2.1"
ARCHIVE_NAME = "devfabric-linux-native.tar.gz"
MANIFEST_NAME = "linux-native-bundle.json"
ARCHIVE_RECEIPT_NAME = "linux-native-archive.json"
CODEX_ARTIFACT_MAX_BYTES = 1536 * 1024 * 1024
CODE_MODE_HOST_ARTIFACT_MAX_BYTES = 512 * 1024 * 1024
CLI_LAUNCHER = """#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
loader="$root/runtime/loader/ld-linux-x86-64.so.2"
libraries="$root/runtime/lib"
exec "$loader" --inhibit-cache --library-path "$libraries" \
  "$root/python/bin/python3.12" -I -B -m devhub.cli "$@"
"""
DELEGATE_LAUNCHER = """#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
loader="$root/runtime/loader/ld-linux-x86-64.so.2"
libraries="$root/runtime/lib"
exec "$loader" --inhibit-cache --library-path "$libraries" \
  "$root/python/bin/python3.12" -I -B -m devhub.delegate_server "$@"
"""

_LDD_RESOLVED = re.compile(r"^\s*([^\s]+) => (/[^\s]+) \(0x[0-9A-Fa-f]+\)\s*$")
_LDD_ABSOLUTE = re.compile(r"^\s*(/[^\s]+) \(0x[0-9A-Fa-f]+\)\s*$")
_LDD_VDSO = re.compile(r"^\s*linux-vdso\.so\.1 \(0x[0-9A-Fa-f]+\)\s*$")
_EXPECTED_INTERPRETER = "/lib64/ld-linux-x86-64.so.2"


def _run(argv: list[str], *, cwd: Path | None = None, timeout: int = 1800) -> None:
    subprocess.run(argv, cwd=cwd, check=True, timeout=timeout)


def _output(argv: list[str], *, cwd: Path | None = None) -> str:
    return subprocess.check_output(argv, cwd=cwd, text=True, timeout=60).strip()


def _elf_files(root: Path) -> tuple[Path, ...]:
    values: list[Path] = []
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            if is_linux_dynamic_elf(path):
                values.append(path)
    return tuple(sorted(values, key=lambda value: value.relative_to(root).as_posix()))


def _ldd_resolutions(path: Path) -> dict[str, Path]:
    completed = subprocess.run(
        ["ldd", str(path)],
        capture_output=True,
        check=False,
        timeout=60,
        env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    stdout = completed.stdout.decode("utf-8", errors="strict")
    stderr = completed.stderr.decode("utf-8", errors="strict")
    if completed.returncode != 0 or stderr or "not found" in stdout:
        raise ValueError(f"Linux runtime dependency resolution failed: {path.name}")
    resolved: dict[str, Path] = {}
    for line in stdout.splitlines():
        match = _LDD_RESOLVED.match(line)
        if match is None:
            continue
        name, locator = match.groups()
        candidate = Path(locator).resolve(strict=True)
        if not candidate.is_file():
            raise ValueError(f"Linux runtime dependency is not a file: {name}")
        previous = resolved.get(name)
        if previous is not None and previous != candidate:
            raise ValueError(f"Linux runtime dependency resolution is ambiguous: {name}")
        resolved[name] = candidate
    return resolved


def _copy_runtime_closure(bundle_root: Path) -> None:
    """Copy the exact loader and recursive DT_NEEDED closure as plain files."""

    initial = _elf_files(bundle_root)
    if not initial:
        raise ValueError("Linux bundle contains no ELF objects")
    requirements = tuple(
        inspect_linux_dynamic_elf(path, path.relative_to(bundle_root).as_posix())
        for path in initial
    )
    direct_names = {name for item in requirements for name in item.needed}
    resolved: dict[str, Path] = {}
    for path in initial:
        for name, candidate in _ldd_resolutions(path).items():
            previous = resolved.get(name)
            if previous is not None and (
                previous != candidate or file_sha256(previous) != file_sha256(candidate)
            ):
                raise ValueError(f"Linux runtime dependency authority differs: {name}")
            resolved[name] = candidate
    loader_name = Path(_EXPECTED_INTERPRETER).name
    missing = direct_names - {loader_name} - set(resolved)
    if missing:
        raise ValueError(f"Linux runtime dependency is unresolved: {sorted(missing)[0]}")
    required_names = set(resolved) - {loader_name}
    runtime = bundle_root / "runtime"
    loader_directory = runtime / "loader"
    library_directory = runtime / "lib"
    loader_directory.mkdir(parents=True)
    library_directory.mkdir()
    loader_source = Path(_EXPECTED_INTERPRETER).resolve(strict=True)
    if not loader_source.is_file():
        raise ValueError("Reviewed Linux dynamic loader is unavailable")
    loader_destination = loader_directory / "ld-linux-x86-64.so.2"
    shutil.copyfile(loader_source, loader_destination)
    loader_destination.chmod(0o755)
    for name in sorted(required_names):
        destination = library_directory / name
        shutil.copyfile(resolved[name], destination)


def _seal_runtime_closure(bundle_root: Path) -> LinuxRuntimeClosureV1:
    requirements = tuple(
        inspect_linux_dynamic_elf(path, path.relative_to(bundle_root).as_posix())
        for path in _elf_files(bundle_root)
    )
    loader = bundle_root / "runtime/loader/ld-linux-x86-64.so.2"
    libraries = tuple(
        LinuxRuntimeLibraryV1(
            soname=path.name,
            path=path.relative_to(bundle_root).as_posix(),
            size=path.stat().st_size,
            sha256=file_sha256(path),
        )
        for path in sorted((bundle_root / "runtime/lib").iterdir(), key=lambda value: value.name)
    )
    return LinuxRuntimeClosureV1(
        loader_sha256=file_sha256(loader),
        loader_size=loader.stat().st_size,
        libraries=libraries,
        elf_requirements=requirements,
    )


def _verify_loader_resolution(bundle_root: Path, closure: LinuxRuntimeClosureV1) -> None:
    """Prove executable dependencies resolve only to the immutable closure."""

    loader = bundle_root / closure.loader_path
    library_directory = bundle_root / closure.library_directory
    loader_name = Path(closure.loader_path).name
    for requirement in closure.elf_requirements:
        relative = requirement.path
        if relative == closure.loader_path:
            continue
        completed = subprocess.run(
            [
                str(loader),
                *closure.loader_arguments,
                str(library_directory),
                "--list",
                str(bundle_root / relative),
            ],
            capture_output=True,
            check=False,
            timeout=60,
            env={"LANG": "C", "LC_ALL": "C"},
        )
        stdout = completed.stdout.decode("utf-8", errors="strict")
        stderr = completed.stderr.decode("utf-8", errors="strict")
        if completed.returncode != 0 or stderr:
            raise ValueError(f"Bundled loader resolution failed: {relative}")
        observed: dict[str, Path] = {}
        for line in stdout.splitlines():
            match = _LDD_RESOLVED.match(line)
            if match is not None:
                name, locator = match.groups()
                path = (
                    loader.resolve(strict=True)
                    if name == loader_name and locator == closure.embedded_interpreter
                    else Path(locator).resolve(strict=True)
                )
            else:
                absolute = _LDD_ABSOLUTE.match(line)
                if absolute is not None:
                    locator = absolute.group(1)
                    if locator == closure.embedded_interpreter:
                        name = loader_name
                        path = loader.resolve(strict=True)
                    else:
                        path = Path(locator).resolve(strict=True)
                        name = path.name
                elif not line.strip() or _LDD_VDSO.match(line):
                    continue
                else:
                    raise ValueError(f"Bundled loader output is unrecognized: {relative}")
            previous = observed.get(name)
            if previous is not None and previous != path:
                raise ValueError(f"Bundled loader resolved a dependency ambiguously: {name}")
            observed[name] = path
        direct = set(requirement.needed)
        if not direct.issubset(observed):
            raise ValueError(f"Bundled loader omitted a direct dependency: {relative}")
        for name, path in observed.items():
            expected = (
                loader.resolve(strict=True)
                if name == loader_name
                else (library_directory / name).resolve(strict=True)
            )
            if path != expected:
                raise ValueError(f"Bundled loader used an ambient dependency: {name}")


def reviewed_commit(repo: Path, expected_commit: str) -> str:
    if len(expected_commit) != 40 or any(
        value not in "0123456789abcdef" for value in expected_commit
    ):
        raise ValueError("Expected implementation commit must be lowercase hex")
    if _output(["git", "status", "--porcelain=v1"], cwd=repo):
        raise ValueError("Linux bundle requires a clean repository")
    actual = _output(["git", "rev-parse", "HEAD"], cwd=repo)
    if actual != expected_commit:
        raise ValueError("Repository HEAD differs from expected implementation commit")
    return actual


def _verified_builder(repo: Path) -> tuple[Path, Path]:
    if sys.platform != "linux" or os.uname().machine != "x86_64":
        raise ValueError("Linux bundle must be assembled on Linux x86_64")
    if sys.version_info[:3] != (3, 12, 10):
        raise ValueError("Linux bundle requires exact CPython 3.12.10")
    project = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
    groups = project.get("dependency-groups")
    if not isinstance(groups, dict) or groups.get("linux-bundle-build") != [
        f"pip=={PIP_BUILD_VERSION}"
    ]:
        raise ValueError("Linux bundle pip authority differs from dependency-group policy")
    base_executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
    if (
        _output([str(base_executable), "-I", "-m", "pip", "--version"]).split()[1]
        != PIP_BUILD_VERSION
    ):
        raise ValueError("Linux bundle pip version differs from reviewed policy")
    uv_value = shutil.which("uv")
    if uv_value is None:
        raise ValueError("Reviewed uv executable is required")
    return base_executable, Path(uv_value).resolve(strict=True)


def _validate_source_prefix(prefix: Path) -> None:
    prefix = prefix.resolve(strict=True)
    for path in prefix.rglob("*"):
        if not path.is_symlink():
            continue
        try:
            target = path.resolve(strict=True)
        except OSError as exc:
            raise ValueError("CPython runtime contains a dangling symlink") from exc
        if not target.is_relative_to(prefix):
            raise ValueError("CPython runtime symlink escapes the copied prefix")


def _plain_artifact_layout(root: Path) -> None:
    root = Path(os.path.abspath(root))
    if root.is_symlink() or not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("Linux Codex artifact root must be a plain directory")
    expected_files = {
        "binary/codex",
        "binary/codex-code-mode-host",
        "code-mode-host-eof.json",
        "linux-build-result.json",
        "linux-native-codex-build.json",
        "linux-process-proof.json",
        "native-build-artifact-inventory.json",
    }
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    for path in root.rglob("*"):
        result = path.lstat()
        if path.is_symlink():
            raise ValueError("Linux Codex artifact contains a symlink")
        relative = path.relative_to(root).as_posix()
        if stat.S_ISDIR(result.st_mode):
            observed_directories.add(relative)
        elif stat.S_ISREG(result.st_mode):
            observed_files.add(relative)
        else:
            raise ValueError("Linux Codex artifact contains a non-file entry")
    if observed_directories != {"binary"} or observed_files != expected_files:
        raise ValueError("Linux Codex artifact layout differs from reviewed authority")
    for relative, limit in (
        ("linux-native-codex-build.json", 256 * 1024),
        ("native-build-artifact-inventory.json", 1024 * 1024),
        ("linux-build-result.json", 1024 * 1024),
        ("linux-process-proof.json", 1024 * 1024),
        ("code-mode-host-eof.json", 1024 * 1024),
        ("binary/codex", CODEX_ARTIFACT_MAX_BYTES),
        ("binary/codex-code-mode-host", CODE_MODE_HOST_ARTIFACT_MAX_BYTES),
    ):
        if (root / relative).stat().st_size > limit:
            raise ValueError(f"Linux Codex artifact file exceeds its bound: {relative}")


def _normalize_bundle_modes(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        result = path.lstat()
        if path.is_symlink():
            raise ValueError("Linux bundle contains a symlink before publication")
        if stat.S_ISDIR(result.st_mode):
            path.chmod(0o755)
        elif stat.S_ISREG(result.st_mode):
            path.chmod(0o755 if result.st_mode & 0o111 else 0o644)
        else:
            raise ValueError("Linux bundle contains a non-file before publication")
    root.chmod(0o755)


def _copy_python_prefix(prefix: Path, destination: Path) -> Path:
    _validate_source_prefix(prefix)
    shutil.copytree(prefix, destination, symlinks=False)
    site_packages = destination / "lib/python3.12/site-packages"
    if site_packages.exists():
        shutil.rmtree(site_packages)
    site_packages.mkdir(parents=True)
    ensurepip = destination / "lib/python3.12/ensurepip"
    if ensurepip.exists():
        shutil.rmtree(ensurepip)
    for path in sorted(destination.rglob("__pycache__"), reverse=True):
        if path.is_dir():
            shutil.rmtree(path)
    for path in destination.rglob("*.pyc"):
        path.unlink()
    interpreter = destination / "bin/python3.12"
    result = interpreter.lstat()
    if interpreter.is_symlink() or not stat.S_ISREG(result.st_mode):
        raise ValueError("Copied Linux interpreter is not a plain regular file")
    return interpreter


def _build_wheel(repo: Path, commit: str, scratch: Path, uv: Path) -> tuple[Path, Path, str]:
    archive = scratch / "source.tar"
    _run(["git", "archive", "--format=tar", "-o", str(archive), commit], cwd=repo)
    source = scratch / "source"
    source.mkdir()
    with tarfile.open(archive) as stream:
        stream.extractall(source, filter="data")
    wheels = scratch / "devhub-wheel"
    wheels.mkdir()
    _run([str(uv), "build", "--wheel", "--out-dir", str(wheels)], cwd=source)
    built = tuple(wheels.glob("*.whl"))
    if len(built) != 1:
        raise ValueError("DevFabric build did not produce exactly one wheel")
    return built[0], source, file_sha256(archive)


def _verify_retained_authority(
    artifact: Path,
    inventory: NativeBuildArtifactInventoryV2,
    pair: LinuxNativeBuildArtifactJoinV1,
) -> None:
    files = {item.relative_path: item for item in inventory.payload.files}
    expected = {
        "linux-build-result.json": inventory.payload.build_result_sha256,
        "linux-process-proof.json": pair.process_proof_sha256,
        "code-mode-host-eof.json": pair.code_mode_host_eof_receipt_sha256,
        "linux-native-codex-build.json": pair.build_receipt_sha256,
        "binary/codex": pair.codex_sha256,
        "binary/codex-code-mode-host": pair.code_mode_host_sha256,
    }
    for relative, expected_sha256 in expected.items():
        entry = files.get(relative)
        path = artifact / relative
        if (
            entry is None
            or entry.sha256 != expected_sha256
            or entry.size != path.stat().st_size
            or file_sha256(path) != expected_sha256
        ):
            raise ValueError(f"Linux retained authority differs: {relative}")


def _review_codex_artifact(
    artifact: Path, expected_codex_commit: str, run_id: int, run_attempt: int
) -> LinuxNativeCodexBuildV12:
    artifact = Path(os.path.abspath(artifact))
    _plain_artifact_layout(artifact)
    receipt_path = artifact / "linux-native-codex-build.json"
    inventory_path = artifact / "native-build-artifact-inventory.json"
    receipt = LinuxNativeCodexBuildV12.model_validate_json(receipt_path.read_bytes())
    inventory = NativeBuildArtifactInventoryV2.model_validate_json(inventory_path.read_bytes())
    payload = receipt.payload
    pair = inventory.payload.linux_pair
    if (
        payload.provenance.implementation_commit != expected_codex_commit
        or payload.provenance.workflow_run_id != run_id
        or payload.provenance.workflow_run_attempt != run_attempt
        or payload.provenance.build_id != "linux-build-012"
        or inventory.payload.platform != "linux"
        or inventory.payload.build_id != "linux-build-012"
        or inventory.payload.status != "PASS"
        or pair is None
        or pair.build_receipt_sha256 != file_sha256(receipt_path)
        or pair.linux_native_codex_build_id != receipt.linux_native_codex_build_id
    ):
        raise ValueError("Linux Codex artifact provenance differs from reviewed authority")
    _verify_retained_authority(artifact, inventory, pair)
    binaries = {item.role: item for item in payload.binaries}
    binary_roles: tuple[tuple[Literal["codex", "codex-code-mode-host"], Path], ...] = (
        ("codex", artifact / "binary/codex"),
        ("codex-code-mode-host", artifact / "binary/codex-code-mode-host"),
    )
    for role, expected_path in binary_roles:
        expected = binaries[role]
        if (
            expected_path.stat().st_size != expected.size
            or file_sha256(expected_path) != expected.sha256
        ):
            raise ValueError(f"Linux {role} bytes differ from build receipt")
    return receipt


def _assemble(
    repo: Path,
    release: Path,
    expected_commit: str,
    codex_artifact: Path,
    expected_codex_commit: str,
    run_id: int,
    run_attempt: int,
    builder_python: Path,
    uv: Path,
) -> LinuxNativeBundleV9:
    bundle_root = release / "bundle"
    manifest_path = release / "linux-native-bundle.json"
    bundle_root.mkdir(parents=True)
    authority = bundle_root / "authority"
    wheelhouse = authority / "wheels"
    wheelhouse.mkdir(parents=True)
    receipt = _review_codex_artifact(codex_artifact, expected_codex_commit, run_id, run_attempt)
    with tempfile.TemporaryDirectory(prefix="devfabric-linux-bundle-") as temporary:
        scratch = Path(temporary)
        devhub_wheel_source, source, source_archive_sha256 = _build_wheel(
            repo, expected_commit, scratch, uv
        )
        requirements = scratch / "runtime-requirements.txt"
        _run(
            [
                str(uv),
                "export",
                "--locked",
                "--no-dev",
                "--no-emit-project",
                "--no-header",
                "--no-annotate",
                "--output-file",
                str(requirements),
            ],
            cwd=source,
        )
        _run(
            [
                str(builder_python),
                "-I",
                "-m",
                "pip",
                "download",
                "--only-binary=:all:",
                "--require-hashes",
                "--dest",
                str(wheelhouse),
                "-r",
                str(requirements),
            ]
        )
        dependencies = review_dependency_wheels(wheelhouse, source / "uv.lock")
        shutil.copy2(source / "uv.lock", authority / "uv.lock")
        devhub_wheel = authority / devhub_wheel_source.name
        shutil.copy2(devhub_wheel_source, devhub_wheel)
        python_root = bundle_root / "python"
        interpreter = _copy_python_prefix(Path(sys.base_prefix), python_root)
        site_packages = python_root / "lib/python3.12/site-packages"
        install_wheels = (*tuple(sorted(wheelhouse.glob("*.whl"))), devhub_wheel)
        _run(
            [
                str(builder_python),
                "-I",
                "-m",
                "pip",
                "install",
                "--target",
                str(site_packages),
                "--no-index",
                "--no-compile",
                "--find-links",
                str(wheelhouse),
                "--require-hashes",
                "-r",
                str(requirements),
            ]
        )
        _run(
            [
                str(builder_python),
                "-I",
                "-m",
                "pip",
                "install",
                "--target",
                str(site_packages),
                "--no-index",
                "--no-compile",
                "--no-deps",
                str(devhub_wheel),
            ]
        )
        sanitize_installed_wheel_tree(site_packages, install_wheels)
        codex_dir = bundle_root / "codex"
        codex_dir.mkdir()
        shutil.copy2(codex_artifact / "binary/codex", codex_dir / "codex")
        shutil.copy2(
            codex_artifact / "binary/codex-code-mode-host",
            codex_dir / "codex-code-mode-host",
        )
        receipt_path = authority / "linux-native-codex-build.json"
        inventory_path = authority / "native-build-artifact-inventory.json"
        shutil.copy2(codex_artifact / receipt_path.name, receipt_path)
        shutil.copy2(codex_artifact / inventory_path.name, inventory_path)
        _copy_runtime_closure(bundle_root)
        launchers = bundle_root / "bin"
        launchers.mkdir()
        cli_launcher = launchers / "devfabric"
        delegate_launcher = launchers / "devhub-delegate-server"
        cli_launcher.write_text(CLI_LAUNCHER, encoding="utf-8", newline="\n")
        delegate_launcher.write_text(DELEGATE_LAUNCHER, encoding="utf-8", newline="\n")
        cli_launcher.chmod(0o755)
        delegate_launcher.chmod(0o755)
        _normalize_bundle_modes(bundle_root)
        closure = _seal_runtime_closure(bundle_root)
        _verify_loader_resolution(bundle_root, closure)
        runtime = observe_linux_runtime(
            interpreter,
            devhub_wheel,
            authority / "uv.lock",
            expected_commit,
            closure,
        )
    build = receipt.payload
    binaries = {item.role: item for item in build.binaries}
    codex = LinuxCodexAuthorityV6(
        accepted_run_id=run_id,
        accepted_run_attempt=run_attempt,
        devfabric_implementation_commit=expected_codex_commit,
        build_receipt_sha256=file_sha256(authority / "linux-native-codex-build.json"),
        inventory_sha256=file_sha256(authority / "native-build-artifact-inventory.json"),
        linux_native_codex_build_id=receipt.linux_native_codex_build_id,
        executable_sha256=binaries["codex"].sha256,
        code_mode_host_sha256=binaries["codex-code-mode-host"].sha256,
        process_proof_sha256=build.process_proof.process_proof_sha256,
        code_mode_host_eof_receipt_sha256=(build.process_proof.code_mode_host_eof_receipt_sha256),
    )
    python = LinuxPythonAuthorityV1(
        executable_sha256=file_sha256(bundle_root / "python/bin/python3.12"),
        devhub_wheel_path=f"authority/{devhub_wheel.name}",
        devhub_wheel_sha256=file_sha256(devhub_wheel),
        devhub_source_archive_sha256=source_archive_sha256,
        dependency_lock_sha256=file_sha256(authority / "uv.lock"),
        dependency_wheels=dependencies,
        runtime=runtime,
    )
    bundle = LinuxNativeBundleV9.create(
        LinuxNativeBundlePayloadV9(
            implementation_commit=expected_commit,
            retained_codex_implementation_commit=expected_codex_commit,
            python=python,
            codex=codex,
            launcher=LinuxLauncherV2(
                cli_sha256=file_sha256(bundle_root / "bin/devfabric"),
                delegate_sha256=file_sha256(bundle_root / "bin/devhub-delegate-server"),
            ),
            runtime_closure=closure,
            files=inventory_linux_bundle(bundle_root),
        )
    )
    verify_linux_native_bundle(bundle, bundle_root)
    write_new(
        manifest_path,
        canonical(cast(JsonValue, bundle.model_dump(mode="json"))),
    )
    return bundle


def _write_archive(release: Path, bundle: LinuxNativeBundleV9) -> LinuxNativeArchiveV9:
    archive_path = release / ARCHIVE_NAME
    with tarfile.open(archive_path, mode="w:gz", format=tarfile.PAX_FORMAT) as stream:
        stream.add(release / "bundle", arcname="bundle", recursive=True)
    archive = LinuxNativeArchiveV9.create(
        LinuxNativeArchivePayloadV9(
            bundle_id=bundle.linux_native_bundle_id,
            size=archive_path.stat().st_size,
            sha256=file_sha256(archive_path),
        )
    )
    write_new(
        release / ARCHIVE_RECEIPT_NAME,
        canonical(cast(JsonValue, archive.model_dump(mode="json"))),
    )
    return archive


def build(
    repo: Path,
    output: Path,
    expected_commit: str,
    codex_artifact: Path,
    expected_codex_commit: str,
    accepted_run_id: int,
    accepted_run_attempt: int,
) -> LinuxNativeBundleV9:
    repo = repo.resolve(strict=True)
    commit = reviewed_commit(repo, expected_commit)
    builder_python, uv = _verified_builder(repo)
    if output.exists():
        raise ValueError("Linux native release root must be new")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".devfabric-linux-publication-", dir=output.parent
    ) as tmp:
        staging = Path(tmp) / "staging"
        staging.mkdir()
        bundle = _assemble(
            repo,
            staging,
            commit,
            Path(os.path.abspath(codex_artifact)),
            expected_codex_commit,
            accepted_run_id,
            accepted_run_attempt,
            builder_python,
            uv,
        )
        archive = _write_archive(staging, bundle)
        if (
            archive.payload.bundle_id != bundle.linux_native_bundle_id
            or archive.payload.sha256 != file_sha256(staging / ARCHIVE_NAME)
        ):
            raise ValueError("Linux native archive authority differs before publication")
        shutil.rmtree(staging / "bundle")
        verify_linux_native_release(staging, Path(tmp) / "relocated")
        os.replace(staging, output)
    return bundle


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--codex-artifact", required=True, type=Path)
    parser.add_argument("--expected-codex-commit", required=True)
    parser.add_argument("--accepted-run-id", required=True, type=int)
    parser.add_argument("--accepted-run-attempt", required=True, type=int)
    args = parser.parse_args()
    bundle = build(
        Path(__file__).resolve().parents[1],
        args.output,
        args.expected_commit,
        args.codex_artifact,
        args.expected_codex_commit,
        args.accepted_run_id,
        args.accepted_run_attempt,
    )
    print(json.dumps(bundle.model_dump(mode="json"), sort_keys=True))


if __name__ == "__main__":
    main()
