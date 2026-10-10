"""Build one immutable internal Windows bundle from reviewed native authorities.

The script never invokes inference.  It builds from an exact clean DevFabric
commit, an accepted Windows Codex receipt/binary, the reviewed CPython embedded
archive, and dependency wheels selected from ``uv.lock``.  The manifest stays
outside the bundle so a future trusted launcher can verify it before execution.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.parse
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, cast

from packaging.utils import parse_wheel_filename
from pydantic import JsonValue

from devhub.benchmark import canonical, digest, write_new
from devhub.native_bundle import (
    EmbeddedPythonAuthorityV1,
    NativeBundlePayloadV1,
    NativeBundleV1,
    NativeCodexAuthorityV1,
    NativeDependencyWheelV1,
    NativeLauncherV1,
    embedded_archive_members_sha256,
    file_sha256,
    inspect_embedded_windows_runtime,
    inventory_native_bundle,
    sanitize_installed_wheel_tree,
    verify_native_bundle,
)
from devhub.runtime_artifact import normalize_distribution_name

PYTHON_ARCHIVE = "python-3.12.10-embed-amd64.zip"
PYTHON_ARCHIVE_SHA256 = "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3"
PYTHON_SBOM = "python-3.12.10-embed-amd64.zip.spdx.json"
PYTHON_SBOM_SHA256 = "efa53ba4f26e8a06410677ec6d010e97133a7a1ab38e0485f6936da2911879fa"
PYTHON_LICENSE = "PSF-2.0"
CODEX_SOURCE_COMMIT = "4607249e430dac1c961df4dc615beae88e33cec8"
CODEX_SOURCE_ARCHIVE_SHA256 = "d9478b4d5bb98d4f6eaa6f57dc51b759f0fc70ebd29614f6b1edf7979564ebd2"
CANDIDATE_SHA256 = "d2e27068ca8020f014c7cd3bea2cc73181b1b892d8e6869814680d2076eb3e36"
HOST_SHA256 = "f22369f10ed45d04a740205fca0cb7111ddb56d3b1bdbee603dfcfdfdd7de9ad"
COMBINED_SHA256 = "e63b68840ecec005703fc61fa1e26aba988c5a9e44a956efedbfbdea96d10c59"
ORIGINAL_CARGO_LOCK_SHA256 = "7bb060a9b67a22503f9d15030c22122fea38623be9077d44cbadb919896a4146"
PROOF_CARGO_LOCK_SHA256 = "9236f6c0b8703eaf337dd219c8fdfb6834c14fa430a0a83b938159016371bb88"
# This is a locator for the exact GitHub artifact authority. The corresponding
# receipt and executable still have to pass every content check below.
WINDOWS_BUILD_ARTIFACT_RUN_ID = 38065801496
DELEGATE = "mcp__devhub_delegate.devhub_delegate"
SCHEMA_SHA256 = "0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"
COMMIT = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
PTH = (
    "python312.zip\n"
    ".\n"
    "site-packages\n"
    "site-packages\\win32\n"
    "site-packages\\win32\\lib\n"
    "site-packages\\pythonwin\n"
    "site-packages\\pywin32_system32\n"
)


def _run(argv: list[str], *, cwd: Path | None = None, timeout: int = 900) -> None:
    subprocess.run(argv, cwd=cwd, check=True, timeout=timeout)


def _output(argv: list[str], *, cwd: Path | None = None) -> str:
    return subprocess.check_output(argv, cwd=cwd, text=True, timeout=60).strip()


def reviewed_commit(repo: Path, expected: str) -> str:
    if COMMIT.fullmatch(expected) is None:
        raise ValueError("Expected implementation commit must be lowercase 40-hex")
    if _output(["git", "status", "--porcelain=v1"], cwd=repo):
        raise ValueError("Native bundle must be built from an exact clean repository")
    actual = _output(["git", "rev-parse", "HEAD"], cwd=repo)
    if actual != expected:
        raise ValueError("Repository HEAD differs from expected implementation commit")
    return actual


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return cast(dict[str, Any], value)


def _zero_counters(value: dict[str, Any], label: str) -> None:
    for key in ("model_requests", "provider_sends", "mcp_tool_executions"):
        if value.get(key) != 0:
            raise ValueError(f"{label} reports a nonzero {key}")
    task_key = (
        "real_task_executions" if "real_task_executions" in value else "real_codex_executions"
    )
    if value.get(task_key) != 0:
        raise ValueError(f"{label} reports a nonzero real task execution count")


def validate_windows_codex_artifact(artifact: Path, accepted_run_id: int) -> NativeCodexAuthorityV1:
    if accepted_run_id != WINDOWS_BUILD_ARTIFACT_RUN_ID:
        raise ValueError("Windows Codex artifact run differs from the reviewed workflow run")
    receipt_path = artifact / "windows-build-result.json"
    binary = artifact / "binary/codex.exe"
    raw = json.loads(receipt_path.read_bytes())
    receipt = _mapping(raw, "Windows build receipt")
    required = {
        "schema_version": 1,
        "build_id": "windows-build-001",
        "status": "PASS",
        "phase": "complete",
        "compilation": "PASS",
        "rust_compilation_started": True,
        "qualification": "WINDOWS_PRODUCTION_HOST_QUALIFIED_PRE_SAMPLING",
        "target": "x86_64-pc-windows-msvc",
        "source_commit": CODEX_SOURCE_COMMIT,
        "source_archive_sha256": CODEX_SOURCE_ARCHIVE_SHA256,
        "candidate_b_base_patch_sha256": CANDIDATE_SHA256,
        "host_integration_patch_sha256": HOST_SHA256,
        "combined_patchset_sha256": COMBINED_SHA256,
        "canonical_schema_sha256": SCHEMA_SHA256,
        "formatting": "PASS",
        "failure": None,
    }
    for key, expected in required.items():
        if receipt.get(key) != expected:
            raise ValueError(f"Windows Codex receipt differs at {key}")
    _zero_counters(receipt, "Windows build receipt")
    implementation_commit = receipt.get("devfabric_implementation_commit")
    if (
        not isinstance(implementation_commit, str)
        or COMMIT.fullmatch(implementation_commit) is None
        or receipt.get("expected_implementation_commit") != implementation_commit
    ):
        raise ValueError("Windows receipt implementation identity is incomplete")
    source_preparation = _mapping(receipt.get("source_preparation"), "source preparation")
    if source_preparation != {
        "candidate_patch_applied": True,
        "candidate_patch_cwd": "pinned_source_parent",
        "host_patch_applied": True,
        "host_patch_cwd": "codex-rs",
        "lock_strategy": "complete_patched_manifest_bound_derived_lock",
        "original_cargo_lock_sha256": ORIGINAL_CARGO_LOCK_SHA256,
        "proof_cargo_lock_sha256": PROOF_CARGO_LOCK_SHA256,
    }:
        raise ValueError("Windows source preparation differs from the reviewed build")
    toolchain = _mapping(receipt.get("toolchain"), "Windows toolchain")
    if (
        toolchain.get("rustc_command") != ["rustup", "run", "1.95.0", "rustc", "-vV"]
        or toolchain.get("cargo_command")
        != ["rustup", "run", "1.95.0", "cargo", "--version", "--verbose"]
        or toolchain.get("target") != "x86_64-pc-windows-msvc"
        or "release: 1.95.0" not in str(toolchain.get("rustc", ""))
        or "cargo 1.95.0 " not in str(toolchain.get("cargo", ""))
    ):
        raise ValueError("Windows pinned toolchain identity differs")
    locked = _mapping(receipt.get("locked_resolution"), "Windows locked resolution")
    expected_commands = {
        "metadata": [
            "cargo",
            "+1.95.0",
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--filter-platform",
            "x86_64-pc-windows-msvc",
        ],
        "fetch": [
            "cargo",
            "+1.95.0",
            "fetch",
            "--locked",
            "--target",
            "x86_64-pc-windows-msvc",
        ],
    }
    if set(locked) != set(expected_commands):
        raise ValueError("Windows locked resolution receipt set differs")
    for label, command in expected_commands.items():
        observation = _mapping(locked.get(label), f"Windows locked resolution {label}")
        if (
            observation.get("command") != command
            or observation.get("exit_code") != 0
            or observation.get("lock_sha256_before") != PROOF_CARGO_LOCK_SHA256
            or observation.get("lock_sha256_after") != PROOF_CARGO_LOCK_SHA256
            or observation.get("lock_unchanged") is not True
            or not isinstance(observation.get("stdout_sha256"), str)
            or SHA256.fullmatch(cast(str, observation["stdout_sha256"])) is None
            or not isinstance(observation.get("stderr_sha256"), str)
            or SHA256.fullmatch(cast(str, observation["stderr_sha256"])) is None
        ):
            raise ValueError(f"Windows locked {label} authority differs")
    if receipt.get("build_command") != [
        "cargo",
        "+1.95.0",
        "build",
        "--release",
        "--locked",
        "-p",
        "codex-cli",
        "--bin",
        "codex",
    ]:
        raise ValueError("Windows build command differs from the reviewed locked build")
    executable = _mapping(receipt.get("executable"), "Windows executable receipt")
    if executable.get("relative_path") != "binary/codex.exe":
        raise ValueError("Windows executable locator differs from reviewed layout")
    binary_sha256 = file_sha256(binary)
    if executable.get("sha256") != binary_sha256:
        raise ValueError("Windows executable bytes differ from its build receipt")
    if executable.get("version_stdout") != "codex-cli 0.155.0-alpha.9.2":
        raise ValueError("Windows executable version differs from reviewed build")
    proof = _mapping(receipt.get("process_proof"), "Windows process proof")
    _zero_counters(proof, "Windows process proof")
    if (
        proof.get("final_binary_sha256") != binary_sha256
        or proof.get("final_binary_integrity") != "PASS"
        or proof.get("scope")
        != "native Windows Codex host construction and finalized pre-sampling visibility"
        or proof.get("windows_executor_isolation_qualified") is not False
    ):
        raise ValueError("Windows process proof is not bound to the exact retained binary")
    same = _mapping(proof.get("same_binary"), "Windows same-binary proof")
    if same != {
        "binary_sha256": binary_sha256,
        "b_minus_a": [DELEGATE],
        "a_minus_b": [],
        "passed": True,
    }:
        raise ValueError("Windows A/B same-binary surface proof differs")
    arms = _mapping(proof.get("arms"), "Windows arm proofs")
    host_authority = _mapping(receipt.get("windows_host_authority"), "Windows host authority")
    manifest_sha256 = host_authority.get("manifest_sha256")
    if not isinstance(manifest_sha256, str) or SHA256.fullmatch(manifest_sha256) is None:
        raise ValueError("Windows host authority lacks an exact manifest identity")
    for arm, expected in (("A", []), ("B", [DELEGATE])):
        arm_proof = _mapping(arms.get(arm), f"Windows Arm {arm}")
        observer = _mapping(arm_proof.get("observer"), f"Windows Arm {arm} observer")
        expected_policy = arm == "B"
        if (
            arm_proof.get("passed") is not True
            or observer.get("effective_tool_mode") != "CodeModeOnly"
            or observer.get("visible_model_tools") != expected
            or observer.get("nested_code_mode_map") != []
            or observer.get("hosted_tools") != []
            or observer.get("dynamic_tool_count") != 0
            or observer.get("allowed_tools") != expected
            or observer.get("allowed_tools_ceiling_present") is not True
            or observer.get("approved_delegate_policy_present") is not expected_policy
            or observer.get("host_manifest_sha256") != manifest_sha256
            or observer.get("expected_schema_sha256")
            != (SCHEMA_SHA256 if expected_policy else None)
            or observer.get("model_requests") != 0
            or observer.get("provider_sends") != 0
        ):
            raise ValueError(f"Windows Arm {arm} surface differs")
        identity = observer.get("approved_identity")
        if arm == "A" and identity is not None:
            raise ValueError("Windows Arm A unexpectedly has approved delegate identity")
        if arm == "B":
            expected_identity = {
                "server_key": "devhub_delegate",
                "raw_tool": "devhub_delegate",
                "canonical_namespace": "mcp__devhub_delegate",
                "canonical_function": "devhub_delegate",
                "schema_sha256": SCHEMA_SHA256,
            }
            observed_identity = _mapping(identity, "Windows Arm B approved identity")
            if {key: observed_identity.get(key) for key in expected_identity} != expected_identity:
                raise ValueError("Windows Arm B approved delegate identity differs")
            if arm_proof.get("mcp_child_exited") is not True:
                raise ValueError("Windows Arm B catalog child did not exit")
    default = _mapping(proof.get("default"), "Windows default proof")
    default_observer = _mapping(default.get("observer"), "Windows default observer")
    if (
        default.get("passed") is not True
        or default_observer.get("allowed_tools_ceiling_present") is not False
        or default_observer.get("allowed_tools") != []
        or default_observer.get("approved_delegate_policy_present") is not False
        or default_observer.get("approved_identity") is not None
        or default_observer.get("host_manifest_sha256") is not None
        or default_observer.get("expected_schema_sha256") is not None
        or DELEGATE in default_observer.get("visible_model_tools", [])
        or any(DELEGATE in item for item in default_observer.get("nested_code_mode_map", []))
        or default_observer.get("model_requests") != 0
        or default_observer.get("provider_sends") != 0
    ):
        raise ValueError("Windows default proof did not stop before sampling")
    negatives = _mapping(proof.get("negatives"), "Windows security negatives")
    expected_negatives = {
        "wrong_schema_hash",
        "wrong_config_hash",
        "wrong_namespace",
        "arm_a_with_mcp",
        "arm_b_without_mcp",
        "resume_with_host_authority",
        "fork_with_host_authority",
        "task_lookalike_cannot_authorize",
    }
    if set(negatives) != expected_negatives or any(
        _mapping(value, f"Windows negative {key}").get("passed") is not True
        for key, value in negatives.items()
    ):
        raise ValueError("Windows security-negative proof is incomplete")
    catalog = _mapping(proof.get("mcp_catalog_receipt"), "Windows MCP catalog receipt")
    if catalog.get("tool_call_count") != 0 or catalog.get("records") != [
        {"event": "tools_list", "schema_sha256": SCHEMA_SHA256, "provider_send": False}
    ]:
        raise ValueError("Windows catalog proof invoked an MCP tool")
    return NativeCodexAuthorityV1(
        accepted_run_id=accepted_run_id,
        devfabric_implementation_commit=implementation_commit,
        build_receipt_sha256=file_sha256(receipt_path),
        executable_sha256=binary_sha256,
        codex_source_commit=CODEX_SOURCE_COMMIT,
        source_archive_sha256=CODEX_SOURCE_ARCHIVE_SHA256,
        candidate_b_base_patch_sha256=CANDIDATE_SHA256,
        host_integration_patch_sha256=HOST_SHA256,
        combined_patchset_sha256=COMBINED_SHA256,
    )


def archive_members_sha256(archive: Path) -> str:
    return embedded_archive_members_sha256(archive.read_bytes())


def archive_snapshot_members_sha256(raw: bytes) -> str:
    return embedded_archive_members_sha256(raw)


def extract_embedded_python(archive: Path, destination: Path) -> str:
    raw = archive.read_bytes()
    identity = archive_snapshot_members_sha256(raw)
    destination.mkdir(parents=True, exist_ok=False)
    extracted: list[dict[str, JsonValue]] = []
    with zipfile.ZipFile(io.BytesIO(raw)) as stream:
        for item in stream.infolist():
            if item.is_dir():
                continue
            relative = PurePosixPath(item.filename)
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            member = stream.read(item)
            target.write_bytes(member)
            extracted.append(
                {
                    "path": item.filename,
                    "size": len(member),
                    "sha256": file_sha256(target),
                }
            )
    extracted.sort(key=lambda item: cast(str, item["path"]))
    if digest(canonical(cast(JsonValue, extracted))) != identity:
        raise ValueError("Extracted CPython members differ from the immutable archive snapshot")
    (destination / "python312._pth").write_text(PTH, encoding="ascii", newline="\n")
    return identity


def locked_wheel_authority(lock_path: Path) -> dict[tuple[str, str, str], str]:
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    result: dict[tuple[str, str, str], str] = {}
    for package in lock.get("package", []):
        if not isinstance(package, dict) or package.get("source", {}).get("registry") is None:
            continue
        name = normalize_distribution_name(str(package["name"]))
        version = str(package["version"])
        for wheel in package.get("wheels", []):
            filename = Path(urllib.parse.unquote(urllib.parse.urlparse(wheel["url"]).path)).name
            value = str(wheel["hash"])
            if not value.startswith("sha256:") or SHA256.fullmatch(value[7:]) is None:
                raise ValueError("uv.lock contains a malformed wheel identity")
            result[(name, version, filename)] = value[7:]
    return result


def review_dependency_wheels(
    wheelhouse: Path, lock_path: Path
) -> tuple[NativeDependencyWheelV1, ...]:
    allowed = locked_wheel_authority(lock_path)
    reviewed: list[NativeDependencyWheelV1] = []
    for wheel in sorted(wheelhouse.glob("*.whl")):
        parsed_name, version, _, _ = parse_wheel_filename(wheel.name)
        name = normalize_distribution_name(str(parsed_name))
        key = (name, str(version), wheel.name)
        observed = file_sha256(wheel)
        if allowed.get(key) != observed:
            raise ValueError(
                f"Selected dependency wheel is absent or mismatched in uv.lock: {wheel.name}"
            )
        reviewed.append(
            NativeDependencyWheelV1(
                name=name,
                version=str(version),
                filename=wheel.name,
                sha256=observed,
            )
        )
    if not reviewed:
        raise ValueError("No dependency wheels were selected")
    names = [item.name for item in reviewed]
    if len(names) != len(set(names)):
        raise ValueError("Dependency resolution selected duplicate distributions")
    reviewed.sort(key=lambda item: item.name)
    return tuple(reviewed)


def reject_build_locators(root: Path, locators: tuple[Path, ...]) -> None:
    needles: set[bytes] = set()
    for locator in locators:
        text = str(locator.resolve())
        for variant in {text, text.replace("\\", "/")}:
            needles.add(variant.encode("utf-8"))
            needles.add(variant.encode("utf-16-le"))
    for path in root.rglob("*"):
        if path.is_file():
            overlap = b""
            overlap_size = max(len(needle) for needle in needles) - 1
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    candidate = overlap + block
                    if any(needle and needle in candidate for needle in needles):
                        raise ValueError(f"Native bundle leaks a build-time locator: {path.name}")
                    overlap = candidate[-overlap_size:] if overlap_size else b""


def _build_devhub_wheel(repo: Path, commit: str, output: Path, uv: Path) -> tuple[Path, str]:
    source = output / "source"
    source.mkdir()
    archive = output / "source.tar"
    _run(["git", "archive", "--format=tar", "-o", str(archive), commit], cwd=repo)
    with tarfile.open(archive) as stream:
        stream.extractall(source, filter="data")
    wheels = output / "devhub-wheel"
    wheels.mkdir()
    _run([str(uv), "build", "--wheel", "--out-dir", str(wheels)], cwd=source)
    built = tuple(wheels.glob("*.whl"))
    if len(built) != 1:
        raise ValueError("DevFabric build did not produce exactly one wheel")
    return built[0], file_sha256(archive)


def _assemble_bundle(
    repo: Path,
    bundle_root: Path,
    manifest_path: Path,
    expected_commit: str,
    python_archive: Path,
    python_sbom: Path,
    codex_artifact: Path,
    accepted_run_id: int,
) -> NativeBundleV1:
    repo = repo.resolve(strict=True)
    commit = reviewed_commit(repo, expected_commit)
    if bundle_root.exists() or manifest_path.exists():
        raise ValueError("Bundle root and external manifest path must be new")
    if file_sha256(python_archive) != PYTHON_ARCHIVE_SHA256:
        raise ValueError("CPython embedded archive differs from the reviewed release asset")
    if file_sha256(python_sbom) != PYTHON_SBOM_SHA256:
        raise ValueError("CPython SPDX document differs from the reviewed release asset")
    codex = validate_windows_codex_artifact(codex_artifact, accepted_run_id)
    uv_name = "uv.exe" if os.name == "nt" else "uv"
    uv_value = shutil.which(uv_name)
    if uv_value is None:
        raise ValueError("Reviewed uv executable is required")
    uv = Path(uv_value).resolve(strict=True)
    bundle_root.mkdir(parents=True)
    authority = bundle_root / "authority"
    wheelhouse = authority / "wheels"
    wheelhouse.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix="devfabric-native-bundle-") as temporary:
        scratch = Path(temporary)
        built_wheel, source_archive_sha256 = _build_devhub_wheel(repo, commit, scratch, uv)
        source = scratch / "source"
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
                sys.executable,
                "-m",
                "pip",
                "download",
                "--only-binary=:all:",
                "--platform=win_amd64",
                "--python-version=312",
                "--implementation=cp",
                "--abi=cp312",
                "--require-hashes",
                "--dest",
                str(wheelhouse),
                "-r",
                str(requirements),
            ],
            timeout=1800,
        )
        dependencies = review_dependency_wheels(wheelhouse, source / "uv.lock")
        shutil.copy2(python_archive, authority / PYTHON_ARCHIVE)
        shutil.copy2(python_sbom, authority / PYTHON_SBOM)
        if (
            file_sha256(authority / PYTHON_ARCHIVE) != PYTHON_ARCHIVE_SHA256
            or file_sha256(authority / PYTHON_SBOM) != PYTHON_SBOM_SHA256
        ):
            raise ValueError("Copied CPython authority changed during bundle assembly")
        shutil.copy2(source / "uv.lock", authority / "uv.lock")
        devhub_wheel = authority / built_wheel.name
        shutil.copy2(built_wheel, devhub_wheel)
        archive_members = extract_embedded_python(
            authority / PYTHON_ARCHIVE, bundle_root / "python"
        )
        site_packages = bundle_root / "python/site-packages"
        _run(
            [
                str(uv),
                "pip",
                "install",
                "--target",
                str(site_packages),
                "--python-version=3.12",
                "--python-platform=windows",
                "--no-index",
                "--find-links",
                str(wheelhouse),
                "--require-hashes",
                "-r",
                str(requirements),
            ],
            timeout=1800,
        )
        _run(
            [
                str(uv),
                "pip",
                "install",
                "--target",
                str(site_packages),
                "--python-version=3.12",
                "--python-platform=windows",
                "--no-index",
                "--no-deps",
                str(devhub_wheel),
            ]
        )
        sanitize_installed_wheel_tree(
            site_packages, (*tuple(sorted(wheelhouse.glob("*.whl"))), devhub_wheel)
        )
        codex_dir = bundle_root / "codex"
        codex_dir.mkdir()
        shutil.copy2(codex_artifact / "binary/codex.exe", codex_dir / "codex.exe")
        shutil.copy2(
            codex_artifact / "windows-build-result.json",
            authority / "windows-build-result.json",
        )
        runtime = inspect_embedded_windows_runtime(
            bundle_root / "python/python.exe", devhub_wheel, authority / "uv.lock", commit
        )
        reject_build_locators(bundle_root, (repo, scratch))
    python = EmbeddedPythonAuthorityV1(
        archive_sha256=PYTHON_ARCHIVE_SHA256,
        archive_members_sha256=archive_members,
        sbom_sha256=PYTHON_SBOM_SHA256,
        executable_sha256=file_sha256(bundle_root / "python/python.exe"),
        pth_sha256=file_sha256(bundle_root / "python/python312._pth"),
        devhub_wheel_path=f"authority/{devhub_wheel.name}",
        devhub_source_archive_sha256=source_archive_sha256,
        devhub_wheel_sha256=file_sha256(devhub_wheel),
        dependency_lock_sha256=file_sha256(authority / "uv.lock"),
        dependency_wheels=dependencies,
        runtime=runtime,
    )
    bundle = NativeBundleV1.create(
        NativeBundlePayloadV1(
            platform="windows",
            architecture="x86_64",
            implementation_commit=commit,
            python=python,
            codex=codex,
            launcher=NativeLauncherV1(),
            files=inventory_native_bundle(bundle_root),
        )
    )
    verify_native_bundle(
        bundle, bundle_root, expected_platform="windows", expected_architecture="x86_64"
    )
    write_new(manifest_path, canonical(cast(JsonValue, bundle.model_dump(mode="json"))))
    return bundle


def build(
    repo: Path,
    release_root: Path,
    expected_commit: str,
    python_archive: Path,
    python_sbom: Path,
    codex_artifact: Path,
    accepted_run_id: int,
) -> NativeBundleV1:
    """Assemble and verify privately, then atomically publish one release root."""

    if release_root.exists():
        raise ValueError("Native release root must be new")
    release_root.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".devfabric-native-publication-", dir=release_root.parent
    ) as temporary:
        publication = Path(temporary) / "release"
        publication.mkdir()
        staged_bundle = publication / "bundle"
        staged_manifest = publication / "native-bundle.json"
        bundle = _assemble_bundle(
            repo,
            staged_bundle,
            staged_manifest,
            expected_commit,
            python_archive,
            python_sbom,
            codex_artifact,
            accepted_run_id,
        )
        os.replace(publication, release_root)
    return bundle


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--python-archive", required=True, type=Path)
    parser.add_argument("--python-sbom", required=True, type=Path)
    parser.add_argument("--codex-artifact", required=True, type=Path)
    parser.add_argument("--accepted-run-id", required=True, type=int)
    args = parser.parse_args()
    bundle = build(
        Path(__file__).resolve().parents[1],
        args.output,
        args.expected_commit,
        args.python_archive.resolve(strict=True),
        args.python_sbom.resolve(strict=True),
        args.codex_artifact.resolve(strict=True),
        args.accepted_run_id,
    )
    print(json.dumps(bundle.model_dump(mode="json"), sort_keys=True))


if __name__ == "__main__":
    main()
