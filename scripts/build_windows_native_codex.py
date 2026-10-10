"""Build and qualify one pinned patched native Windows Codex executable.

This is a pre-sampling host-visibility proof. It never sends a model request,
invokes an MCP tool, contacts a provider, or qualifies the Windows executor sandbox.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path
from typing import Any

import build_stage3g_build009 as retained
from derive_stage3g_production_lock import PRODUCTION_HOST_LOCK_SHA256
from stage3g_schema_hash import read_schema_identity

BUILD_ID = "windows-build-001"
TARGET = "x86_64-pc-windows-msvc"
SCHEMA_ENV = "DEVHUB_BUILD009_SCHEMA"
MCP_PID_ENV = "DEVHUB_BUILD009_MCP_PID"
DELEGATE = retained.DELEGATE
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
WINDOWS_RUNNER_ASSETS = frozenset(
    {
        "build_stage3g_build009.py",
        "build_windows_native_codex.py",
        "candidate.patch",
        "delegation-request-schema.json",
        "derive_router_build_lock.py",
        "derive_stage3g_production_lock.py",
        "host-integration.patch",
        "preflight_stage3g_build009.py",
        "production-router-proof.yml",
        "stage3g-host-manifest-v2.json",
        "stage3g_build009_mcp.py",
        "stage3g_schema_hash.py",
        "windows-host-manifest-v2.json",
        "windows-native-qualification.yml",
    }
)


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_sha256(value: object) -> str:
    return sha256_bytes(
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    )


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _toml(value: object) -> str:
    """JSON strings/arrays are valid TOML values and preserve Windows backslashes."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def windows_mcp_config(python: Path, server: Path) -> dict[str, object]:
    return {
        "args": [str(server), "mcp"],
        "command": str(python),
        "enabled": True,
        "enabled_tools": ["devhub_delegate"],
        "environment_id": "local",
        "env_vars": [retained.MCP_RECEIPT_ENV_VAR, SCHEMA_ENV, MCP_PID_ENV],
        "required": True,
        "tool_timeout_sec": None,
        "tools": {"devhub_delegate": {"approval_mode": "approve"}},
    }


def windows_host_manifest(source: Path, destination: Path, config_hash: str) -> str:
    value = json.loads(source.read_bytes())
    value["arms"]["arm_b"]["approved_delegate"]["expected_mcp_server_config_sha256"] = config_hash
    write_json(destination, value)
    return sha256_file(destination)


def validate_implementation_head(repo: Path, expected: str) -> str:
    if COMMIT_PATTERN.fullmatch(expected) is None:
        raise ValueError("expected implementation commit must be lowercase 40-hex")
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    if actual != expected:
        raise ValueError("checked-out implementation commit does not match workflow authority")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=repo).strip():
        raise ValueError("Windows build requires a clean reviewed repository")
    return actual


def verify_runner_assets(assets: Path, expected: dict[str, str]) -> None:
    observed = {path.name: sha256_file(path) for path in sorted(assets.iterdir())}
    if set(observed) != WINDOWS_RUNNER_ASSETS:
        raise ValueError("Windows runner asset set is incomplete or contains an extra input")
    if observed != expected:
        raise ValueError("Windows runner asset changed after preservation")


def verify_binary_identity(binary: Path, expected_sha256: str) -> str:
    observed = sha256_file(binary)
    if observed != expected_sha256:
        raise ValueError("compiled binary changed after the final process proof")
    return observed


def preserve_windows_runner_assets(
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
            (
                repo / ".github/workflows/windows-native-qualification.yml",
                "windows-native-qualification.yml",
            ),
        ),
    )
    config = windows_mcp_config(python, (assets / "stage3g_build009_mcp.py").resolve())
    config_hash = canonical_sha256(config)
    manifest = assets / "windows-host-manifest-v2.json"
    manifest_hash = windows_host_manifest(shipping_manifest, manifest, config_hash)
    hashes[manifest.name] = manifest_hash
    verify_runner_assets(assets, hashes)
    return assets, manifest, config, manifest_hash, hashes


def write_build_state(output: Path, receipt: dict[str, object]) -> None:
    write_json(output / "windows-build-result.json", receipt)


def record_build_failure(
    output: Path, receipt: dict[str, object], phase: str, error: BaseException
) -> None:
    receipt["status"] = "FAIL"
    receipt["failure"] = {
        "phase": phase,
        "type": type(error).__name__,
        "message": str(error),
    }
    write_build_state(output, receipt)


def _host_exec(
    work: Path,
    manifest: Path,
    observer: Path,
    arm: str,
    config: dict[str, object],
    *,
    with_mcp: bool | None = None,
) -> list[str]:
    args = retained._base_exec(work)
    args += [
        "--devhub-stage3g-host-manifest",
        str(manifest),
        "--devhub-stage3g-arm",
        arm,
        "--devhub-proof-observe-router",
        str(observer),
    ]
    include_mcp = arm == "b" if with_mcp is None else with_mcp
    if include_mcp:
        args += [
            "-c",
            'features.code_mode.direct_only_tool_namespaces=["mcp__devhub_delegate"]',
            "-c",
            f"mcp_servers.devhub_delegate.command={_toml(config['command'])}",
            "-c",
            f"mcp_servers.devhub_delegate.args={_toml(config['args'])}",
            "-c",
            f"mcp_servers.devhub_delegate.env_vars={_toml(config['env_vars'])}",
            "-c",
            "mcp_servers.devhub_delegate.required=true",
            "-c",
            'mcp_servers.devhub_delegate.enabled_tools=["devhub_delegate"]',
            "-c",
            'mcp_servers.devhub_delegate.tools.devhub_delegate.approval_mode="approve"',
        ]
    return [*args, "-"]


def _capture(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> dict[str, Any]:
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(
            b"windows native pre-sampling router proof\n", timeout=timeout
        )
    except subprocess.TimeoutExpired:
        timed_out = True
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            capture_output=True,
        )
        stdout, stderr = process.communicate(timeout=10)
    return {
        "command": command,
        "exit_code": None if timed_out else process.returncode,
        "timed_out": timed_out,
        "duration_seconds": time.monotonic() - started,
        "stdin_bytes": len(b"windows native pre-sampling router proof\n"),
        "stdin_closed": True,
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
    }


def _pid_is_active(pid: int) -> bool:
    process_query_limited_information = 0x1000
    still_active = 259
    handle = ctypes.windll.kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise OSError("GetExitCodeProcess failed")
        return code.value == still_active
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _wait_pid_exit(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_is_active(pid):
            return True
        time.sleep(0.05)
    return not _pid_is_active(pid)


def _proof_env(home: Path, receipt: Path, schema: Path, pid_path: Path) -> dict[str, str]:
    allowed = {
        "APPDATA",
        "COMSPEC",
        "LOCALAPPDATA",
        "PATH",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env.update(
        HOME=str(home),
        CODEX_HOME=str(home),
        OPENAI_API_KEY="windows-build-no-send-placeholder",
        DEVHUB_BUILD009_MCP_RECEIPT=str(receipt),
        DEVHUB_BUILD009_SCHEMA=str(schema),
        DEVHUB_BUILD009_MCP_PID=str(pid_path),
    )
    return env


def _negative(
    binary: Path,
    binary_sha256: str,
    label: str,
    args: list[str],
    expected: str,
    root: Path,
    env: dict[str, str],
) -> dict[str, object]:
    result = _capture([str(binary), *args], cwd=root, env=env, timeout=90)
    combined = str(result["stdout"]) + str(result["stderr"])
    result["expected_rejection"] = expected
    result["passed"] = result["exit_code"] not in (None, 0) and expected in combined
    if sha256_file(binary) != binary_sha256:
        raise ValueError("compiled binary changed during negative proof")
    return result


def process_proof(
    binary: Path,
    *,
    output: Path,
    manifest: Path,
    manifest_sha256: str,
    schema: Path,
    python: Path,
    server: Path,
) -> dict[str, object]:
    root = output / "process-proof"
    root.mkdir(exist_ok=False)
    work = root / "робочий каталог with spaces"
    work.mkdir()
    receipt = root / "mcp-receipt.jsonl"
    receipt.touch()
    config = windows_mcp_config(python, server)
    binary_sha256 = sha256_file(binary)
    arms: dict[str, object] = {}
    for arm in ("a", "b"):
        run_dir = root / f"arm-{arm}"
        run_dir.mkdir()
        home = run_dir / "codex home"
        home.mkdir()
        observer = run_dir / "observer.json"
        mcp_pid = run_dir / "mcp.pid"
        run = _capture(
            [str(binary), *_host_exec(work, manifest, observer, arm, config)],
            cwd=work,
            env=_proof_env(home, receipt, schema, mcp_pid),
            timeout=120,
        )
        run["observer"] = retained._verify_observer(
            observer, arm, expected_manifest_sha256=manifest_sha256
        )
        run["observer_sha256"] = sha256_file(observer)
        run["passed"] = retained._proof_stopped(run)
        if not run["passed"]:
            raise ValueError(f"Windows Arm {arm} did not stop before sampling")
        if arm == "b":
            if not mcp_pid.is_file():
                raise ValueError("Windows Arm B did not record its catalog child PID")
            child_pid = int(mcp_pid.read_text(encoding="ascii").strip())
            run["mcp_child_pid"] = child_pid
            run["mcp_child_exited"] = _wait_pid_exit(child_pid)
            if not run["mcp_child_exited"]:
                raise ValueError("Windows catalog MCP child survived parent proof exit")
        arms[arm.upper()] = run
        if sha256_file(binary) != binary_sha256:
            raise ValueError("compiled binary changed between arm proofs")
    records = [json.loads(line) for line in receipt.read_bytes().splitlines()]
    retained._verify_mcp_catalog_records(records)
    a_visible = set(arms["A"]["observer"]["visible_model_tools"])  # type: ignore[index]
    b_visible = set(arms["B"]["observer"]["visible_model_tools"])  # type: ignore[index]
    same_binary = {
        "binary_sha256": binary_sha256,
        "b_minus_a": sorted(b_visible - a_visible),
        "a_minus_b": sorted(a_visible - b_visible),
        "passed": b_visible - a_visible == {DELEGATE} and not (a_visible - b_visible),
    }
    if not same_binary["passed"]:
        raise ValueError("Windows A/B surface difference changed")

    default_dir = root / "default"
    default_dir.mkdir()
    default_home = default_dir / "codex home"
    default_home.mkdir()
    default_observer = default_dir / "observer.json"
    default = _capture(
        [str(binary), *retained._default_exec(work, default_observer)],
        cwd=work,
        env=_proof_env(default_home, receipt, schema, default_dir / "unused-mcp.pid"),
        timeout=120,
    )
    default["observer"] = retained._verify_default_observer(default_observer)
    default["observer_sha256"] = sha256_file(default_observer)
    default["passed"] = retained._proof_stopped(default)
    if not default["passed"]:
        raise ValueError("Windows default host proof did not stop before sampling")

    mutations = root / "mutations"
    mutations.mkdir()
    negative_specs: list[tuple[str, list[str], str]] = []
    for label, path, value, expected in (
        (
            "wrong_schema_hash",
            ("arms", "arm_b", "approved_delegate", "expected_input_schema_sha256"),
            "0" * 64,
            "unreviewed schema hash",
        ),
        (
            "wrong_config_hash",
            ("arms", "arm_b", "approved_delegate", "expected_mcp_server_config_sha256"),
            "0" * 64,
            "resolved devhub_delegate MCP config hash mismatch",
        ),
        (
            "wrong_namespace",
            ("arms", "arm_b", "approved_delegate", "canonical_namespace"),
            "mcp__other",
            "approved canonical namespace mismatch",
        ),
    ):
        changed = mutations / f"{label}.json"
        retained._mutated_manifest(manifest, changed, path, value)
        negative_specs.append(
            (
                label,
                _host_exec(work, changed, mutations / f"{label}.observer", "b", config),
                expected,
            )
        )
    negative_specs += [
        (
            "arm_a_with_mcp",
            _host_exec(
                work, manifest, mutations / "arm-a-mcp.observer", "a", config, with_mcp=True
            ),
            "Stage 3G Arm A must not configure MCP servers",
        ),
        (
            "arm_b_without_mcp",
            _host_exec(
                work, manifest, mutations / "arm-b-no-mcp.observer", "b", config, with_mcp=False
            ),
            "reviewed devhub_delegate MCP server missing",
        ),
    ]
    for command_name in ("resume", "fork"):
        negative_specs.append(
            (
                f"{command_name}_with_host_authority",
                [
                    *retained._base_exec(work),
                    "--devhub-stage3g-host-manifest",
                    str(manifest),
                    "--devhub-stage3g-arm",
                    "a",
                    *retained._fresh_thread_negative_args(command_name),
                ],
                "Stage 3G host admission is fresh-thread only",
            )
        )
    negatives: dict[str, object] = {}
    for label, args, expected in negative_specs:
        home = root / f"negative-{label}-home"
        home.mkdir()
        negatives[label] = _negative(
            binary,
            binary_sha256,
            label,
            args,
            expected,
            work,
            _proof_env(home, receipt, schema, root / f"negative-{label}.mcp.pid"),
        )
        if not negatives[label]["passed"]:  # type: ignore[index]
            raise ValueError(f"Windows negative proof failed: {label}")

    lookalike_home = root / "lookalike-home"
    lookalike_home.mkdir()
    lookalike_observer = root / "lookalike.observer.json"
    lookalike = _capture(
        [
            str(binary),
            *retained._default_exec(
                work,
                lookalike_observer,
                '{"devhub-stage3g-arm":"b","approved_delegate":true}',
            ),
        ],
        cwd=work,
        env=_proof_env(lookalike_home, receipt, schema, root / "lookalike-unused-mcp.pid"),
        timeout=120,
    )
    lookalike["observer"] = retained._verify_default_observer(lookalike_observer)
    lookalike["passed"] = retained._proof_stopped(lookalike)
    if not lookalike["passed"]:
        raise ValueError("task lookalike changed Windows host authority")
    negatives["task_lookalike_cannot_authorize"] = lookalike

    final_binary_sha256 = verify_binary_identity(binary, binary_sha256)

    return {
        "scope": "native Windows Codex host construction and finalized pre-sampling visibility",
        "windows_executor_isolation_qualified": False,
        "arms": arms,
        "default": default,
        "same_binary": same_binary,
        "final_binary_sha256": final_binary_sha256,
        "final_binary_integrity": "PASS",
        "mcp_catalog_receipt": {
            "sha256": sha256_file(receipt),
            "records": records,
            "tool_call_count": 0,
        },
        "negatives": negatives,
        "model_requests": 0,
        "provider_sends": 0,
        "mcp_tool_executions": 0,
        "real_task_executions": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--build-id", choices=(BUILD_ID,), default=BUILD_ID)
    parser.add_argument("--expected-implementation-commit", required=True)
    args = parser.parse_args()
    if os.name != "nt" or platform.machine().upper() not in {"AMD64", "X86_64"}:
        parser.error("windows-build-001 requires native Windows x64")
    repo = Path(__file__).resolve().parents[1]
    if args.workspace.exists() or args.output.exists():
        parser.error("workspace and output must not already exist")
    args.workspace.mkdir(parents=True)
    args.output.mkdir(parents=True)
    receipt: dict[str, object] = {
        "schema_version": 1,
        "build_id": BUILD_ID,
        "expected_implementation_commit": args.expected_implementation_commit,
        "devfabric_implementation_commit": None,
        "source_commit": retained.SOURCE_COMMIT,
        "source_archive_sha256": retained.SOURCE_ARCHIVE_SHA256,
        "target": TARGET,
        "status": "PREBUILD",
        "phase": "initialization",
        "compilation": "NOT_RUN",
        "rust_compilation_started": False,
        "process_proof": None,
        "model_requests": 0,
        "provider_sends": 0,
        "mcp_tool_executions": 0,
        "real_task_executions": 0,
    }
    write_build_state(args.output, receipt)
    phase = "implementation_identity"
    try:
        implementation_commit = validate_implementation_head(
            repo, args.expected_implementation_commit
        )
        receipt["devfabric_implementation_commit"] = implementation_commit

        candidate = (repo / "patches/stage3g-approved-call/candidate.patch").read_bytes()
        host = (repo / "patches/stage3g-approved-call/host-integration.patch").read_bytes()
        schema = repo / "docs/evidence/stage3g-production-router/delegate-input-schema.json"
        shipping_manifest = repo / "benchmarks/stage3g-host-manifest-v2.json"
        identities = {
            "candidate_b_base_patch_sha256": sha256_bytes(candidate),
            "host_integration_patch_sha256": sha256_bytes(host),
            "combined_patchset_sha256": sha256_bytes(candidate + host),
        }
        expected = {
            "candidate_b_base_patch_sha256": retained.CANDIDATE_SHA256,
            "host_integration_patch_sha256": retained.HOST_SHA256,
            "combined_patchset_sha256": retained.COMBINED_SHA256,
        }
        if identities != expected:
            raise ValueError("reviewed production patch identities changed")
        receipt.update(identities)
        schema_identity = read_schema_identity(
            schema, expected_canonical_sha256=retained.SCHEMA_SHA256
        )
        receipt["canonical_schema_sha256"] = schema_identity.canonical_schema_sha256
        receipt["raw_schema_file_sha256"] = schema_identity.raw_file_sha256

        phase = "runner_asset_preservation"
        assets, manifest, config, manifest_hash, asset_hashes = preserve_windows_runner_assets(
            repo,
            args.output,
            schema=schema,
            shipping_manifest=shipping_manifest,
            python=Path(sys.executable).resolve(),
        )
        receipt["asset_hashes"] = asset_hashes
        receipt["windows_host_authority"] = {
            "manifest_sha256": manifest_hash,
            "resolved_mcp_config_sha256": canonical_sha256(config),
            "resolved_mcp_config": config,
            "manifest_relative_path": "assets/windows-host-manifest-v2.json",
        }

        phase = "source_download"
        raw = urllib.request.urlopen(
            f"https://codeload.github.com/openai/codex/tar.gz/{retained.SOURCE_COMMIT}",
            timeout=120,
        ).read()
        if sha256_bytes(raw) != retained.SOURCE_ARCHIVE_SHA256:
            raise ValueError("pinned Codex source archive changed")
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            archive.extractall(args.workspace, filter="data")
        root = args.workspace / f"codex-{retained.SOURCE_COMMIT}" / "codex-rs"

        phase = "source_preparation"
        receipt["source_preparation"] = retained.prepare_build_source(
            root,
            candidate_patch=candidate,
            host_patch=host,
            evidence_directory=args.output,
            build_id=BUILD_ID,
        )
        phase = "toolchain_identity"
        receipt["toolchain"] = retained._pinned_toolchain_identity(root, expected_host=TARGET)
        phase = "locked_resolution"
        receipt["locked_resolution"] = retained._verify_locked_resolution(
            root, args.output, PRODUCTION_HOST_LOCK_SHA256, target=TARGET
        )
        phase = "formatting"
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
        receipt["formatting"] = "PASS"
        verify_runner_assets(assets, asset_hashes)
        receipt["phase"] = "ready_for_cargo"
        receipt["status"] = "READY_FOR_COMPILE"
        write_json(args.output / "runner-manifest.json", receipt)
        write_build_state(args.output, receipt)

        command = [
            "cargo",
            "+1.95.0",
            "build",
            "--release",
            "--locked",
            "-p",
            "codex-cli",
            "--bin",
            "codex",
        ]
        receipt["build_command"] = command
        phase = "cargo_start"
        started = time.monotonic()
        with (
            (args.output / "build.stdout").open("xb") as stdout,
            (args.output / "build.stderr").open("xb") as stderr,
        ):
            build = subprocess.Popen(
                command,
                cwd=root,
                env={**os.environ, "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0"},
                stdout=stdout,
                stderr=stderr,
            )
            receipt["rust_compilation_started"] = True
            receipt["phase"] = "cargo_compile"
            receipt["status"] = "COMPILING"
            write_build_state(args.output, receipt)
            phase = "cargo_compile"
            build_exit_code = build.wait()
        receipt["build_duration_seconds"] = time.monotonic() - started
        receipt["build_exit_code"] = build_exit_code
        receipt["compilation"] = "PASS" if build_exit_code == 0 else "FAIL"
        write_build_state(args.output, receipt)
        if build_exit_code != 0:
            raise ValueError("windows-build-001 Rust compilation failed")

        phase = "binary_identity"
        binary_dir = args.output / "binary"
        binary_dir.mkdir()
        binary = binary_dir / "codex.exe"
        shutil.copy2(root / "target" / "release" / "codex.exe", binary)
        version = subprocess.run([binary, "--version"], capture_output=True, text=True, check=False)
        if version.returncode != 0 or "codex-cli 0.155.0-alpha.9.2" not in version.stdout:
            raise ValueError("native Windows Codex version identity mismatch")
        binary_sha256 = sha256_file(binary)
        receipt["executable"] = {
            "relative_path": "binary/codex.exe",
            "sha256": binary_sha256,
            "bytes": binary.stat().st_size,
            "version_stdout": version.stdout.strip(),
            "version_stderr": version.stderr.strip(),
        }
        receipt["windows_environment"] = {
            "platform": platform.platform(),
            "win32_ver": list(platform.win32_ver()),
            "machine": platform.machine(),
            "runner_image": os.environ.get("ImageOS"),
            "runner_image_version": os.environ.get("ImageVersion"),
        }

        phase = "process_proof"
        proof = process_proof(
            binary,
            output=args.output,
            manifest=manifest,
            manifest_sha256=manifest_hash,
            schema=assets / "delegation-request-schema.json",
            python=Path(sys.executable).resolve(),
            server=(assets / "stage3g_build009_mcp.py").resolve(),
        )
        if proof["final_binary_sha256"] != binary_sha256:
            raise ValueError("final proof binary identity does not match retained executable")
        receipt["process_proof"] = proof
        receipt["phase"] = "complete"
        receipt["status"] = "PASS"
        receipt["qualification"] = "WINDOWS_PRODUCTION_HOST_QUALIFIED_PRE_SAMPLING"
        receipt["failure"] = None
        write_build_state(args.output, receipt)
    except Exception as error:
        record_build_failure(args.output, receipt, phase, error)
        raise


if __name__ == "__main__":
    main()
