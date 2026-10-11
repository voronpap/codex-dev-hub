"""Build and qualify the pinned native Linux Codex executable pair.

The slice is limited to immutable build authority and pre-sampling host proof.
It never invokes an MCP tool, model, provider, benchmark task, or Linux native
executor workload.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path
from typing import Any

import build_stage3g_build009 as retained
import build_windows_native_codex as shared
from derive_stage3g_production_lock import PRODUCTION_HOST_LOCK_SHA256
from stage3g_schema_hash import read_schema_identity

from devhub.linux_native import (
    LinuxBuildProvenanceV1,
    LinuxElfIdentityV1,
    LinuxHostProofSummaryV1,
    LinuxNativeBinaryV1,
    LinuxNativeCodexBuildPayloadV1,
    LinuxNativeCodexBuildV1,
)
from devhub.native_bundle import git_blob_sha256

BUILD_ID = "linux-build-001"
TARGET = "x86_64-unknown-linux-gnu"
SCHEMA_ENV = shared.SCHEMA_ENV
MCP_PID_ENV = shared.MCP_PID_ENV
MISSING_HOST_TEXT = "host executable was not found"
CODE_MODE_FAILURE_TEXT = (
    "code mode is unavailable",
    "failed to spawn code-mode host",
    "failed to read code-mode host hello",
    "failed to write code-mode host hello",
    "code-mode host protocol",
    "error while loading shared libraries",
    "cannot open shared object file",
)
LINUX_RUNNER_ASSETS = frozenset(
    {
        "build_linux_native_codex.py",
        "build_stage3g_build009.py",
        "build_windows_native_codex.py",
        "candidate.patch",
        "delegation-request-schema.json",
        "derive_router_build_lock.py",
        "derive_stage3g_production_lock.py",
        "host-integration.patch",
        "linux-native-codex.yml",
        "preflight_stage3g_build009.py",
        "production-router-proof.yml",
        "stage3g-host-manifest-v2.json",
        "stage3g_build009_mcp.py",
        "stage3g_schema_hash.py",
    }
)
_NEEDED = re.compile(r"\(NEEDED\).*Shared library: \[([^\]]+)\]")
_SEARCH_PATH = re.compile(r"\((RPATH|RUNPATH)\).*Library (?:rpath|runpath): \[([^\]]*)\]")
_VERSION = re.compile(r"\bName: ([A-Za-z0-9_.+\-]+)")
_INTERPRETER = re.compile(r"Requesting program interpreter: ([^\]]+)")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def committed_provenance_hashes(repo: Path, commit: str) -> dict[str, str]:
    """Hash committed authority bytes without worktree line-ending filters."""

    return {
        "build_script_sha256": git_blob_sha256(repo, commit, "scripts/build_linux_native_codex.py"),
        "shared_proof_script_sha256": git_blob_sha256(
            repo, commit, "scripts/build_windows_native_codex.py"
        ),
        "workflow_sha256": git_blob_sha256(
            repo, commit, ".github/workflows/linux-native-codex.yml"
        ),
    }


def _tool_path(tool: str) -> Path:
    raw = subprocess.check_output(
        ["rustup", "which", "--toolchain", "1.95.0", tool], text=True
    ).strip()
    return Path(raw).resolve(strict=True)


def preserve_linux_runner_assets(
    repo: Path,
    output: Path,
    *,
    schema: Path,
    shipping_manifest: Path,
    python: Path,
) -> tuple[Path, Path, dict[str, object], str, dict[str, str]]:
    assets, hashes = retained._preserve_runner_assets(
        repo,
        output,
        manifest=shipping_manifest,
        schema=schema,
        additional_sources=(
            (repo / "scripts/build_windows_native_codex.py", "build_windows_native_codex.py"),
            (repo / "scripts/build_linux_native_codex.py", "build_linux_native_codex.py"),
            (repo / ".github/workflows/linux-native-codex.yml", "linux-native-codex.yml"),
        ),
    )
    config = shared.native_mcp_config(python, (assets / "stage3g_build009_mcp.py").resolve())
    config_hash = shared.canonical_sha256(config)
    manifest = assets / "linux-host-manifest-v2.json"
    manifest_hash = shared.native_host_manifest(shipping_manifest, manifest, config_hash)
    original_manifest = assets / "stage3g-host-manifest-v2.json"
    original_manifest.unlink()
    hashes.pop(original_manifest.name)
    hashes[manifest.name] = manifest_hash
    observed = {path.name: sha256_file(path) for path in sorted(assets.iterdir())}
    if set(observed) != LINUX_RUNNER_ASSETS - {"stage3g-host-manifest-v2.json"} | {
        "linux-host-manifest-v2.json"
    }:
        raise ValueError("Linux runner asset set is incomplete or contains an extra input")
    if observed != hashes:
        raise ValueError("Linux runner asset changed after preservation")
    return assets, manifest, config, manifest_hash, hashes


def _readelf(binary: Path, output: Path) -> LinuxElfIdentityV1:
    sections: list[tuple[str, bytes]] = []
    decoded: dict[str, str] = {}
    for label, args in (
        ("header", ("-W", "-h")),
        ("program", ("-W", "-l")),
        ("dynamic", ("-W", "-d")),
        ("versions", ("-W", "-V")),
    ):
        result = subprocess.run(["readelf", *args, str(binary)], capture_output=True, check=False)
        if result.returncode != 0 or result.stderr:
            raise ValueError(f"readelf {label} inspection failed")
        sections.append((label, result.stdout))
        decoded[label] = result.stdout.decode("utf-8", errors="strict")
    raw = b"".join(label.encode() + b"\n" + value for label, value in sections)
    output.write_bytes(raw)
    header = decoded["header"]
    if "Class:                             ELF64" not in header:
        raise ValueError("native Linux binary is not ELF64")
    if "Data:                              2's complement, little endian" not in header:
        raise ValueError("native Linux binary is not little-endian")
    if "Machine:                           Advanced Micro Devices X86-64" not in header:
        raise ValueError("native Linux binary machine differs from x86_64")
    interpreter_match = _INTERPRETER.search(decoded["program"])
    if interpreter_match is None:
        raise ValueError("native Linux binary lacks a program interpreter")
    needed = tuple(sorted(set(_NEEDED.findall(decoded["dynamic"]))))
    rpath: list[str] = []
    runpath: list[str] = []
    for kind, value in _SEARCH_PATH.findall(decoded["dynamic"]):
        target = rpath if kind == "RPATH" else runpath
        target.extend(item for item in value.split(":") if item)
    return LinuxElfIdentityV1(
        interpreter=interpreter_match.group(1),
        needed=needed,
        rpath=tuple(sorted(set(rpath))),
        runpath=tuple(sorted(set(runpath))),
        required_symbol_versions=tuple(sorted(set(_VERSION.findall(decoded["versions"])))),
    )


def inspect_binary(role: str, binary: Path, output: Path) -> LinuxNativeBinaryV1:
    identity_path = output / f"{role}.readelf.txt"
    elf = _readelf(binary, identity_path)
    if role == "codex":
        identity = subprocess.run(
            [str(binary), "--version"], capture_output=True, check=False, timeout=30
        )
        if identity.returncode != 0 or b"codex-cli 0.155.0-alpha.9.2" not in identity.stdout:
            raise ValueError("native Linux Codex version identity mismatch")
    else:
        identity = subprocess.run(
            [str(binary), "--help"], capture_output=True, check=False, timeout=30
        )
        if identity.returncode != 0 or b"Transport endpoint" not in identity.stdout:
            raise ValueError("native Linux code-mode host CLI identity mismatch")
    identity_output = identity.stdout + b"\n---stderr---\n" + identity.stderr
    (output / f"{role}.identity.txt").write_bytes(identity_output)
    return LinuxNativeBinaryV1(
        role=role,
        relative_path=f"binary/{role}",
        sha256=sha256_file(binary),
        size=binary.stat().st_size,
        elf=elf,
        identity_output_sha256=sha256_bytes(identity_output),
    )


def _isolated(command: list[str]) -> list[str]:
    preserved = ",".join(
        (
            "PATH",
            "HOME",
            "LANG",
            "TMPDIR",
            "CODEX_HOME",
            "OPENAI_API_KEY",
            retained.MCP_RECEIPT_ENV_VAR,
            SCHEMA_ENV,
            MCP_PID_ENV,
        )
    )
    return [
        "sudo",
        f"--preserve-env={preserved}",
        "unshare",
        "--net",
        "--",
        "setpriv",
        f"--reuid={os.getuid()}",
        f"--regid={os.getgid()}",
        "--init-groups",
        *command,
    ]


def _capture(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> dict[str, Any]:
    started = time.monotonic()
    process = subprocess.Popen(
        _isolated(command),
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(
            b"linux native pre-sampling router proof\n", timeout=timeout
        )
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=10)
    return {
        "command": command,
        "isolated_command": _isolated(command),
        "exit_code": None if timed_out else process.returncode,
        "timed_out": timed_out,
        "duration_seconds": time.monotonic() - started,
        "stdin_bytes": len(b"linux native pre-sampling router proof\n"),
        "stdin_closed": True,
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
    }


def _pid_active(pid: int) -> bool:
    stat_path = Path(f"/proc/{pid}/stat")
    try:
        fields = stat_path.read_text(encoding="ascii").split()
    except FileNotFoundError:
        return False
    if len(fields) >= 3 and fields[2] == "Z":
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True


def _wait_pid_exit(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_active(pid):
            return True
        time.sleep(0.05)
    return not _pid_active(pid)


def _proof_env(home: Path, receipt: Path, schema: Path, pid_path: Path) -> dict[str, str]:
    env = {
        key: value for key, value in os.environ.items() if key in {"PATH", "HOME", "LANG", "TMPDIR"}
    }
    env.update(
        HOME=str(home),
        CODEX_HOME=str(home),
        OPENAI_API_KEY="linux-native-build-no-send-placeholder",
        DEVHUB_BUILD009_MCP_RECEIPT=str(receipt),
        DEVHUB_BUILD009_SCHEMA=str(schema),
        DEVHUB_BUILD009_MCP_PID=str(pid_path),
    )
    return env


def _host_eof_proof(binary: Path, output: Path) -> dict[str, object]:
    binary_sha256 = sha256_file(binary)
    process = subprocess.Popen(
        [str(binary), "--listen", "stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(b"", timeout=15)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate(timeout=10)
    result = {
        "schema_version": 1,
        "binary_relative_path": "binary/codex-code-mode-host",
        "binary_sha256": binary_sha256,
        "exit_code": None if timed_out else process.returncode,
        "timed_out": timed_out,
        "request_count": 0,
        "stdin_bytes": 0,
        "stdin_closed": True,
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "process_exited": not _pid_active(process.pid),
    }
    write_json(output, result)
    if timed_out or process.returncode != 0 or not result["process_exited"]:
        raise ValueError("code-mode host did not terminate cleanly on stdio EOF")
    return result


def _proof_summary(
    proof: dict[str, object],
    proof_sha256: str,
    eof: dict[str, object],
    eof_receipt_sha256: str,
    host_binary: LinuxNativeBinaryV1,
) -> LinuxHostProofSummaryV1:
    arms = proof["arms"]
    default = proof["default"]
    same = proof["same_binary"]
    negatives = proof["negatives"]
    assert isinstance(arms, dict) and isinstance(default, dict)
    assert isinstance(same, dict) and isinstance(negatives, dict)
    serialized = json.dumps(proof, sort_keys=True).lower()
    observed_failures = tuple(
        failure for failure in CODE_MODE_FAILURE_TEXT if failure in serialized
    )
    if MISSING_HOST_TEXT in serialized or observed_failures:
        raise ValueError(
            "pre-sampling proof observed a code-mode host failure: "
            + ", ".join(observed_failures or (MISSING_HOST_TEXT,))
        )
    if (
        host_binary.role != "codex-code-mode-host"
        or host_binary.relative_path != "binary/codex-code-mode-host"
        or eof.get("binary_sha256") != host_binary.sha256
        or eof.get("binary_relative_path") != host_binary.relative_path
    ):
        raise ValueError("EOF proof does not bind the exact sibling code-mode host")
    return LinuxHostProofSummaryV1(
        process_proof_sha256=proof_sha256,
        code_mode_host_sha256=host_binary.sha256,
        code_mode_host_eof_receipt_sha256=eof_receipt_sha256,
        code_mode_host_eof_exit_code=eof["exit_code"],
        code_mode_host_eof_timed_out=eof["timed_out"],
        default_visible_tools=tuple(default["observer"]["visible_model_tools"]),
        arm_a_visible_tools=tuple(arms["A"]["observer"]["visible_model_tools"]),
        arm_b_visible_tools=tuple(arms["B"]["observer"]["visible_model_tools"]),
        b_minus_a=tuple(same["b_minus_a"]),
        a_minus_b=tuple(same["a_minus_b"]),
        default_allowed_tools_ceiling_present=default["observer"]["allowed_tools_ceiling_present"],
        arm_a_allowed_tools_ceiling_present=arms["A"]["observer"]["allowed_tools_ceiling_present"],
        arm_b_allowed_tools_ceiling_present=arms["B"]["observer"]["allowed_tools_ceiling_present"],
        approved_delegate_policy_arm_a=arms["A"]["observer"]["approved_delegate_policy_present"],
        approved_delegate_policy_arm_b=arms["B"]["observer"]["approved_delegate_policy_present"],
        code_mode_host_stdio_eof_passed=bool(eof["process_exited"]),
        mcp_child_cleanup_passed=bool(arms["B"].get("mcp_child_exited")),
        security_negatives_passed=all(bool(item.get("passed")) for item in negatives.values()),
        model_requests=proof["model_requests"],
        provider_sends=proof["provider_sends"],
        mcp_tool_executions=proof["mcp_tool_executions"],
        real_task_executions=proof["real_task_executions"],
    )


def _run_cargo_build(
    command: list[str],
    *,
    root: Path,
    output: Path,
    state: dict[str, object],
    state_path: Path,
) -> int:
    """Start Cargo before recording that a meaningful compilation began."""

    state["build_command"] = command
    state["phase"] = "cargo_start"
    write_json(state_path, state)
    started = time.monotonic()
    with (
        (output / "build.stdout").open("xb") as stdout,
        (output / "build.stderr").open("xb") as stderr,
    ):
        build = subprocess.Popen(
            command,
            cwd=root,
            env={**os.environ, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0"},
            stdout=stdout,
            stderr=stderr,
        )
        state["rust_compilation_started"] = True
        state["status"] = "COMPILING"
        state["phase"] = "cargo_compile"
        write_json(state_path, state)
        exit_code = build.wait()
    state["build_duration_seconds"] = time.monotonic() - started
    state["build_exit_code"] = exit_code
    state["compilation"] = "PASS" if exit_code == 0 else "FAIL"
    write_json(state_path, state)
    return exit_code


def _seal_phase(state: dict[str, object], state_path: Path, phase: str) -> None:
    state["phase"] = phase
    write_json(state_path, state)


def _record_failure(state: dict[str, object], state_path: Path, error: Exception) -> None:
    state.update(
        status="FAIL",
        failure={
            "phase": state.get("phase"),
            "type": type(error).__name__,
            "message": str(error),
        },
    )
    write_json(state_path, state)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-implementation-commit", required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine().lower() != "x86_64":
        parser.error("linux-build-001 requires native Linux x86_64")
    if args.workspace.exists() or args.output.exists():
        parser.error("workspace and output must not already exist")
    repo = Path(__file__).resolve().parents[1]
    args.workspace.mkdir(parents=True)
    args.output.mkdir(parents=True)
    state: dict[str, object] = {
        "schema_version": 1,
        "build_id": BUILD_ID,
        "status": "PREBUILD",
        "phase": "implementation_identity",
        "rust_compilation_started": False,
        "compilation": "NOT_RUN",
        "process_proof": None,
        "model_requests": 0,
        "provider_sends": 0,
        "mcp_tool_executions": 0,
        "real_task_executions": 0,
    }
    state_path = args.output / "linux-build-result.json"
    write_json(state_path, state)
    try:
        implementation_commit = shared.validate_implementation_head(
            repo, args.expected_implementation_commit
        )
        candidate = (repo / "patches/stage3g-approved-call/candidate.patch").read_bytes()
        host = (repo / "patches/stage3g-approved-call/host-integration.patch").read_bytes()
        schema = repo / "docs/evidence/stage3g-production-router/delegate-input-schema.json"
        shipping_manifest = repo / "benchmarks/stage3g-host-manifest-v2.json"
        identities = {
            "candidate_b_base_patch_sha256": sha256_bytes(candidate),
            "host_integration_patch_sha256": sha256_bytes(host),
            "combined_patchset_sha256": sha256_bytes(candidate + host),
        }
        if identities != {
            "candidate_b_base_patch_sha256": retained.CANDIDATE_SHA256,
            "host_integration_patch_sha256": retained.HOST_SHA256,
            "combined_patchset_sha256": retained.COMBINED_SHA256,
        }:
            raise ValueError("reviewed production patch identities changed")
        schema_identity = read_schema_identity(
            schema, expected_canonical_sha256=retained.SCHEMA_SHA256
        )
        state.update(
            devfabric_implementation_commit=implementation_commit,
            source_commit=retained.SOURCE_COMMIT,
            source_archive_sha256=retained.SOURCE_ARCHIVE_SHA256,
            canonical_schema_sha256=schema_identity.canonical_schema_sha256,
            raw_schema_file_sha256=schema_identity.raw_file_sha256,
            **identities,
        )
        state["phase"] = "runner_asset_preservation"
        assets, manifest, config, manifest_hash, asset_hashes = preserve_linux_runner_assets(
            repo,
            args.output,
            schema=schema,
            shipping_manifest=shipping_manifest,
            python=Path(sys.executable).resolve(),
        )
        state["asset_hashes"] = asset_hashes
        state["linux_host_authority"] = {
            "manifest_sha256": manifest_hash,
            "resolved_mcp_config_sha256": shared.canonical_sha256(config),
            "manifest_relative_path": "assets/linux-host-manifest-v2.json",
        }
        state["phase"] = "source_download"
        raw = urllib.request.urlopen(
            f"https://codeload.github.com/openai/codex/tar.gz/{retained.SOURCE_COMMIT}",
            timeout=120,
        ).read()
        if sha256_bytes(raw) != retained.SOURCE_ARCHIVE_SHA256:
            raise ValueError("pinned Codex source archive changed")
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            archive.extractall(args.workspace, filter="data")
        root = args.workspace / f"codex-{retained.SOURCE_COMMIT}" / "codex-rs"
        state["phase"] = "source_preparation"
        preparation = retained.prepare_build_source(
            root,
            candidate_patch=candidate,
            host_patch=host,
            evidence_directory=args.output,
            build_id=BUILD_ID,
        )
        state["source_preparation"] = preparation
        state["phase"] = "toolchain_identity"
        toolchain = retained._pinned_toolchain_identity(root, expected_host=TARGET)
        state["toolchain"] = toolchain
        state["phase"] = "locked_resolution"
        state["locked_resolution"] = retained._verify_locked_resolution(
            root, args.output, PRODUCTION_HOST_LOCK_SHA256, target=TARGET
        )
        state["phase"] = "formatting"
        fmt = subprocess.run(
            [
                "cargo",
                "+1.95.0",
                "fmt",
                "--all",
                "--manifest-path",
                str(root / "Cargo.toml"),
                "--",
                "--check",
            ],
            cwd=root,
            capture_output=True,
            check=False,
        )
        (args.output / "cargo-fmt.stdout").write_bytes(fmt.stdout)
        (args.output / "cargo-fmt.stderr").write_bytes(fmt.stderr)
        if fmt.returncode != 0:
            raise ValueError("pinned patched source failed cargo fmt --check")
        state["formatting"] = "PASS"
        state["status"] = "READY_FOR_COMPILE"
        state["phase"] = "ready_for_cargo"
        write_json(args.output / "runner-manifest.json", state)
        write_json(state_path, state)
        command = [
            "cargo",
            "+1.95.0",
            "build",
            "--release",
            "--locked",
            "--target",
            TARGET,
            "-p",
            "codex-cli",
            "--bin",
            "codex",
            "-p",
            "codex-code-mode-host",
            "--bin",
            "codex-code-mode-host",
        ]
        build_exit_code = _run_cargo_build(
            command,
            root=root,
            output=args.output,
            state=state,
            state_path=state_path,
        )
        if build_exit_code != 0:
            raise ValueError("linux-build-001 Rust compilation failed")
        _seal_phase(state, state_path, "binary_identity")
        binary_dir = args.output / "binary"
        binary_dir.mkdir()
        target_dir = root / "target" / TARGET / "release"
        for name in ("codex", "codex-code-mode-host"):
            target = binary_dir / name
            shutil.copy2(target_dir / name, target)
            target.chmod(0o755)
        identity_dir = args.output / "elf"
        identity_dir.mkdir()
        binaries = (
            inspect_binary("codex", binary_dir / "codex", identity_dir),
            inspect_binary(
                "codex-code-mode-host", binary_dir / "codex-code-mode-host", identity_dir
            ),
        )
        _seal_phase(state, state_path, "code_mode_host_eof")
        eof_path = args.output / "code-mode-host-eof.json"
        eof = _host_eof_proof(binary_dir / "codex-code-mode-host", eof_path)
        _seal_phase(state, state_path, "process_proof")
        proof = shared.process_proof(
            binary_dir / "codex",
            output=args.output,
            manifest=manifest,
            manifest_sha256=manifest_hash,
            schema=assets / "delegation-request-schema.json",
            python=Path(sys.executable).resolve(),
            server=(assets / "stage3g_build009_mcp.py").resolve(),
            capture=_capture,
            wait_pid_exit=_wait_pid_exit,
            proof_env=_proof_env,
            platform_label="Linux",
            scope="native Linux Codex host construction and finalized pre-sampling visibility",
            isolation_field="linux_native_isolation_qualified",
        )
        for binary in binaries:
            if sha256_file(args.output / binary.relative_path) != binary.sha256:
                raise ValueError("native Linux binary changed during process proof")
        proof_path = args.output / "linux-process-proof.json"
        write_json(proof_path, proof)
        summary = _proof_summary(
            proof,
            sha256_file(proof_path),
            eof,
            sha256_file(eof_path),
            binaries[1],
        )
        _seal_phase(state, state_path, "receipt_assembly")
        rustc = _tool_path("rustc")
        cargo = _tool_path("cargo")
        provenance_hashes = committed_provenance_hashes(repo, implementation_commit)
        payload = LinuxNativeCodexBuildPayloadV1(
            provenance=LinuxBuildProvenanceV1(
                implementation_commit=implementation_commit,
                codex_source_commit=retained.SOURCE_COMMIT,
                source_archive_sha256=retained.SOURCE_ARCHIVE_SHA256,
                **identities,
                canonical_schema_sha256=schema_identity.canonical_schema_sha256,
                raw_schema_file_sha256=schema_identity.raw_file_sha256,
                host_manifest_sha256=manifest_hash,
                resolved_mcp_config_sha256=shared.canonical_sha256(config),
                original_cargo_lock_sha256=preparation["original_cargo_lock_sha256"],
                derived_cargo_lock_sha256=preparation["proof_cargo_lock_sha256"],
                rustc_version=toolchain["rustc"],
                cargo_version=toolchain["cargo"],
                rustc_sha256=sha256_file(rustc),
                cargo_sha256=sha256_file(cargo),
                **provenance_hashes,
            ),
            binaries=binaries,
            process_proof=summary,
        )
        final = LinuxNativeCodexBuildV1.create(payload)
        (args.output / "linux-native-codex-build.json").write_text(
            final.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        state.update(
            status="PASS",
            phase="complete",
            process_proof="PASS",
            linux_native_codex_build_id=final.linux_native_codex_build_id,
            executable_sha256=binaries[0].sha256,
            code_mode_host_sha256=binaries[1].sha256,
            qualification="LINUX_NATIVE_CODEX_AUTHORITY_PRE_SAMPLING",
        )
        write_json(state_path, state)
    except Exception as error:
        _record_failure(state, state_path, error)
        raise


if __name__ == "__main__":
    main()
