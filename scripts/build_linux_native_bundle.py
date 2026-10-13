"""Build one immutable native Linux directory from exact reviewed authorities."""

from __future__ import annotations

import argparse
import json
import os
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
    LinuxLauncherV1,
    LinuxNativeArchivePayloadV7,
    LinuxNativeArchiveV7,
    LinuxNativeBundlePayloadV7,
    LinuxNativeBundleV7,
    LinuxPythonAuthorityV1,
    inventory_linux_bundle,
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
exec "$root/python/bin/python3.12" -I -B -m devhub.cli "$@"
"""
DELEGATE_LAUNCHER = """#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
exec "$root/python/bin/python3.12" -I -B -m devhub.delegate_server "$@"
"""


def _run(argv: list[str], *, cwd: Path | None = None, timeout: int = 1800) -> None:
    subprocess.run(argv, cwd=cwd, check=True, timeout=timeout)


def _output(argv: list[str], *, cwd: Path | None = None) -> str:
    return subprocess.check_output(argv, cwd=cwd, text=True, timeout=60).strip()


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
) -> LinuxNativeBundleV7:
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
        launchers = bundle_root / "bin"
        launchers.mkdir()
        cli_launcher = launchers / "devfabric"
        delegate_launcher = launchers / "devhub-delegate-server"
        cli_launcher.write_text(CLI_LAUNCHER, encoding="utf-8", newline="\n")
        delegate_launcher.write_text(DELEGATE_LAUNCHER, encoding="utf-8", newline="\n")
        cli_launcher.chmod(0o755)
        delegate_launcher.chmod(0o755)
        _normalize_bundle_modes(bundle_root)
        runtime = observe_linux_runtime(
            interpreter, devhub_wheel, authority / "uv.lock", expected_commit
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
    bundle = LinuxNativeBundleV7.create(
        LinuxNativeBundlePayloadV7(
            implementation_commit=expected_commit,
            retained_codex_implementation_commit=expected_codex_commit,
            python=python,
            codex=codex,
            launcher=LinuxLauncherV1(
                cli_sha256=file_sha256(bundle_root / "bin/devfabric"),
                delegate_sha256=file_sha256(bundle_root / "bin/devhub-delegate-server"),
            ),
            files=inventory_linux_bundle(bundle_root),
        )
    )
    verify_linux_native_bundle(bundle, bundle_root)
    write_new(
        manifest_path,
        canonical(cast(JsonValue, bundle.model_dump(mode="json"))),
    )
    return bundle


def _write_archive(release: Path, bundle: LinuxNativeBundleV7) -> LinuxNativeArchiveV7:
    archive_path = release / ARCHIVE_NAME
    with tarfile.open(archive_path, mode="w:gz", format=tarfile.PAX_FORMAT) as stream:
        stream.add(release / "bundle", arcname="bundle", recursive=True)
    archive = LinuxNativeArchiveV7.create(
        LinuxNativeArchivePayloadV7(
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
) -> LinuxNativeBundleV7:
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
