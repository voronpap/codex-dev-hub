"""Build and qualify the pinned patched native Windows Codex executable pair.

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
import struct
import subprocess
import sys
import tarfile
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

import build_stage3g_build009 as retained
from derive_stage3g_production_lock import PRODUCTION_HOST_LOCK_SHA256
from stage3g_schema_hash import read_schema_identity

from devhub.native_bundle import git_blob_sha256
from devhub.windows_native import (
    WindowsBuildProvenanceV6,
    WindowsHostProofSummaryV3,
    WindowsNativeBinaryV2,
    WindowsNativeCodexBuildPayloadV6,
    WindowsNativeCodexBuildV6,
    WindowsPeIdentityV1,
)

BUILD_ID = "windows-build-007"
TARGET = "x86_64-pc-windows-msvc"
V8_RELEASE_TAG = "rusty-v8-v150.4.0"
V8_RELEASE_BASE = f"https://github.com/openai/codex/releases/download/{V8_RELEASE_TAG}"
V8_ARCHIVE_NAME = "rusty_v8_ptrcomp_sandbox_release_x86_64-pc-windows-msvc.lib.gz"
V8_ARCHIVE_SHA256 = "732ec5da4243aa166799780c8519a5eea6f32f6e47657a323342794dc3c239d6"
V8_BINDING_NAME = "src_binding_ptrcomp_sandbox_release_x86_64-pc-windows-msvc.rs"
V8_BINDING_SHA256 = "dabf78ba1faac127660db9862b1d0354175c71b8db2d4fcb5bacbd9c93576b16"
V8_CHECKSUM_NAME = "rusty_v8_ptrcomp_sandbox_release_x86_64-pc-windows-msvc.sha256"
V8_CHECKSUM_SHA256 = "a4d6221dddb4b5724b23411eaac47caf6095489fbf9d126f65b33cef96a0a8ef"
CODEX_MODULE_BAZEL_SHA256 = "1a6c8685d241a5390ff94432581e842c2950cbe5262b47b27d8db467cebec4c2"
SCHEMA_ENV = "DEVHUB_BUILD009_SCHEMA"
MCP_PID_ENV = "DEVHUB_BUILD009_MCP_PID"
DELEGATE = retained.DELEGATE
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
CODE_MODE_FAILURE_TEXT = (
    "host executable was not found",
    "code mode is unavailable",
    "failed to spawn code-mode host",
    "failed to read code-mode host hello",
    "failed to write code-mode host hello",
    "code-mode host protocol",
)
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


def _download_exact(url: str, destination: Path, expected_sha256: str, limit: int) -> int:
    """Download one immutable release asset with a hard byte ceiling."""

    hasher = hashlib.sha256()
    observed = 0
    try:
        with urllib.request.urlopen(url, timeout=120) as response, destination.open("xb") as stream:
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) > limit:
                raise ValueError("V8 release asset exceeds its reviewed byte limit")
            while block := response.read(min(1024 * 1024, limit - observed + 1)):
                observed += len(block)
                if observed > limit:
                    raise ValueError("V8 release asset exceeds its reviewed byte limit")
                hasher.update(block)
                stream.write(block)
        if hasher.hexdigest() != expected_sha256:
            raise ValueError("V8 release asset SHA-256 mismatch")
        return observed
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def _verify_pinned_v8_authority(root: Path) -> str:
    module = root.parent / "MODULE.bazel"
    raw = module.read_bytes()
    if sha256_bytes(raw) != CODEX_MODULE_BAZEL_SHA256:
        raise ValueError("pinned Codex MODULE.bazel identity changed")
    text = raw.decode("utf-8", errors="strict")
    required = (
        'crate = "v8"',
        '"x86_64-pc-windows-msvc": ["v8_enable_sandbox"]',
        'name = "v8_crate_150_4_0"',
        'urls = ["https://static.crates.io/crates/v8/v8-150.4.0.crate"]',
    )
    if any(item not in text for item in required):
        raise ValueError("pinned Codex V8 sandbox authority changed")
    return CODEX_MODULE_BAZEL_SHA256


def _v8_release_environment(root: Path, output: Path) -> tuple[dict[str, str], dict[str, object]]:
    """Bind exact OpenAI sandbox archive/binding assets before Cargo starts."""

    module_sha256 = _verify_pinned_v8_authority(root)
    asset_dir = output / "v8-release"
    asset_dir.mkdir()
    authority = (
        (V8_CHECKSUM_NAME, V8_CHECKSUM_SHA256, 4096),
        (V8_ARCHIVE_NAME, V8_ARCHIVE_SHA256, 64 * 1024 * 1024),
        (V8_BINDING_NAME, V8_BINDING_SHA256, 1024 * 1024),
    )
    try:
        sizes = {
            name: _download_exact(f"{V8_RELEASE_BASE}/{name}", asset_dir / name, sha256, limit)
            for name, sha256, limit in authority
        }
        checksum_lines = (asset_dir / V8_CHECKSUM_NAME).read_text(encoding="ascii").splitlines()
        if checksum_lines != [
            f"{V8_ARCHIVE_SHA256}  {V8_ARCHIVE_NAME}",
            f"{V8_BINDING_SHA256}  {V8_BINDING_NAME}",
        ]:
            raise ValueError("official V8 checksum manifest content mismatch")
    except Exception:
        shutil.rmtree(asset_dir)
        raise
    archive = (asset_dir / V8_ARCHIVE_NAME).resolve(strict=True)
    binding = (asset_dir / V8_BINDING_NAME).resolve(strict=True)
    environment = {
        "RUSTY_V8_ARCHIVE": str(archive),
        "RUSTY_V8_ARCHIVE_SHA256": V8_ARCHIVE_SHA256,
        "RUSTY_V8_SRC_BINDING_PATH": str(binding),
    }
    observed: dict[str, object] = {
        "release_tag": V8_RELEASE_TAG,
        "module_bazel_sha256": module_sha256,
        "sandbox_feature_enabled": True,
        "archive_url": f"{V8_RELEASE_BASE}/{V8_ARCHIVE_NAME}",
        "archive_sha256": V8_ARCHIVE_SHA256,
        "binding_url": f"{V8_RELEASE_BASE}/{V8_BINDING_NAME}",
        "binding_sha256": V8_BINDING_SHA256,
        "checksum_url": f"{V8_RELEASE_BASE}/{V8_CHECKSUM_NAME}",
        "checksum_sha256": V8_CHECKSUM_SHA256,
        "sizes": sizes,
    }
    return environment, observed


def _rehash_v8_assets(output: Path) -> dict[str, str]:
    asset_dir = output / "v8-release"
    observed = {
        "archive_sha256": sha256_file(asset_dir / V8_ARCHIVE_NAME),
        "binding_sha256": sha256_file(asset_dir / V8_BINDING_NAME),
        "checksum_sha256": sha256_file(asset_dir / V8_CHECKSUM_NAME),
    }
    expected = {
        "archive_sha256": V8_ARCHIVE_SHA256,
        "binding_sha256": V8_BINDING_SHA256,
        "checksum_sha256": V8_CHECKSUM_SHA256,
    }
    if observed != expected:
        raise ValueError("V8 release asset changed during build")
    return observed


def _verify_post_build_v8_assets(receipt: dict[str, object], output: Path) -> dict[str, str]:
    receipt["phase"] = "v8_release_post_build"
    write_build_state(output, receipt)
    observed = _rehash_v8_assets(output)
    receipt["v8_release_post_build"] = observed
    write_build_state(output, receipt)
    return observed


def committed_provenance_hashes(repo: Path, commit: str) -> dict[str, str]:
    """Hash committed authority bytes without worktree line-ending filters."""

    return {
        "build_script_sha256": git_blob_sha256(
            repo, commit, "scripts/build_windows_native_codex.py"
        ),
        "shared_proof_script_sha256": git_blob_sha256(
            repo, commit, "scripts/build_stage3g_build009.py"
        ),
        "workflow_sha256": git_blob_sha256(
            repo, commit, ".github/workflows/windows-native-qualification.yml"
        ),
    }


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _toml(value: object) -> str:
    """JSON strings/arrays are valid TOML values and preserve Windows backslashes."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def native_mcp_config(python: Path, server: Path) -> dict[str, object]:
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


def windows_mcp_config(python: Path, server: Path) -> dict[str, object]:
    """Compatibility name for the platform-neutral reviewed MCP config shape."""

    return native_mcp_config(python, server)


def native_host_manifest(source: Path, destination: Path, config_hash: str) -> str:
    value = json.loads(source.read_bytes())
    value["arms"]["arm_b"]["approved_delegate"]["expected_mcp_server_config_sha256"] = config_hash
    write_json(destination, value)
    return sha256_file(destination)


def windows_host_manifest(source: Path, destination: Path, config_hash: str) -> str:
    """Compatibility name for the platform-neutral reviewed manifest binding."""

    return native_host_manifest(source, destination, config_hash)


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
    sealed_phase = receipt.get("phase")
    if phase in {"cargo_start", "cargo_compile"} and sealed_phase in {
        "cargo_start",
        "cargo_compile",
        "v8_release_post_build",
    }:
        phase = str(sealed_phase)
    receipt["status"] = "FAIL"
    receipt["phase"] = phase
    receipt["failure"] = {
        "phase": phase,
        "type": type(error).__name__,
        "message": str(error),
    }
    write_build_state(output, receipt)


def _run_cargo_build(
    command: list[str],
    *,
    root: Path,
    output: Path,
    receipt: dict[str, object],
    build_environment: dict[str, str],
) -> int:
    """Start Cargo before recording that a meaningful compilation began."""

    receipt["build_command"] = command
    receipt["phase"] = "cargo_start"
    write_build_state(output, receipt)
    started = time.monotonic()
    with (
        (output / "build.stdout").open("xb") as stdout,
        (output / "build.stderr").open("xb") as stderr,
    ):
        child_environment = os.environ.copy()
        child_environment.pop("V8_FROM_SOURCE", None)
        child_environment.pop("RUSTY_V8_MIRROR", None)
        child_environment.update(build_environment)
        child_environment.update(
            {
                "CARGO_BUILD_JOBS": "2",
                "CARGO_INCREMENTAL": "0",
            }
        )
        build = subprocess.Popen(
            command,
            cwd=root,
            env=child_environment,
            stdout=stdout,
            stderr=stderr,
        )
        receipt["rust_compilation_started"] = True
        receipt["phase"] = "cargo_compile"
        receipt["status"] = "COMPILING"
        write_build_state(output, receipt)
        exit_code = build.wait()
    receipt["build_duration_seconds"] = time.monotonic() - started
    receipt["build_exit_code"] = exit_code
    receipt["compilation"] = "PASS" if exit_code == 0 else "FAIL"
    write_build_state(output, receipt)
    return exit_code


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
    capture: Callable[..., dict[str, Any]] = _capture,
) -> dict[str, object]:
    result = capture([str(binary), *args], cwd=root, env=env, timeout=90)
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
    capture: Callable[..., dict[str, Any]] = _capture,
    wait_pid_exit: Callable[[int, float], bool] = _wait_pid_exit,
    proof_env: Callable[[Path, Path, Path, Path], dict[str, str]] = _proof_env,
    platform_label: str = "Windows",
    scope: str = "native Windows Codex host construction and finalized pre-sampling visibility",
    isolation_field: str = "windows_executor_isolation_qualified",
    runtime_home_root: Path | None = None,
) -> dict[str, object]:
    root = output / "process-proof"
    root.mkdir(exist_ok=False)
    if runtime_home_root is not None:
        runtime_home_root = runtime_home_root.absolute()
        if (
            runtime_home_root.is_symlink()
            or not runtime_home_root.is_dir()
            or any(runtime_home_root.iterdir())
        ):
            raise ValueError("Process-proof runtime home root must be a fresh plain directory")
        if os.path.commonpath((str(output.absolute()), str(runtime_home_root))) in {
            str(output.absolute()),
            str(runtime_home_root),
        }:
            raise ValueError("Process-proof runtime home root must not overlap sealed output")

    def runtime_home(label: str, legacy_home: Path) -> Path:
        home = legacy_home if runtime_home_root is None else runtime_home_root / label
        home.mkdir()
        return home

    work = root / "робочий каталог with spaces"
    work.mkdir()
    receipt = root / "mcp-receipt.jsonl"
    receipt.touch()
    config = native_mcp_config(python, server)
    binary_sha256 = sha256_file(binary)
    arms: dict[str, object] = {}
    for arm in ("a", "b"):
        run_dir = root / f"arm-{arm}"
        run_dir.mkdir()
        home = runtime_home(f"arm-{arm}", run_dir / "codex home")
        observer = run_dir / "observer.json"
        mcp_pid = run_dir / "mcp.pid"
        run = capture(
            [str(binary), *_host_exec(work, manifest, observer, arm, config)],
            cwd=work,
            env=proof_env(home, receipt, schema, mcp_pid),
            timeout=120,
        )
        run["observer"] = retained._verify_observer(
            observer, arm, expected_manifest_sha256=manifest_sha256
        )
        run["observer_sha256"] = sha256_file(observer)
        run["passed"] = retained._proof_stopped(run)
        if not run["passed"]:
            raise ValueError(f"{platform_label} Arm {arm} did not stop before sampling")
        if arm == "b":
            if not mcp_pid.is_file():
                raise ValueError(f"{platform_label} Arm B did not record its catalog child PID")
            child_pid = int(mcp_pid.read_text(encoding="ascii").strip())
            run["mcp_child_pid"] = child_pid
            run["mcp_child_exited"] = wait_pid_exit(child_pid, 5.0)
            if not run["mcp_child_exited"]:
                raise ValueError(f"{platform_label} catalog MCP child survived parent proof exit")
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
        raise ValueError(f"{platform_label} A/B surface difference changed")

    default_dir = root / "default"
    default_dir.mkdir()
    default_home = runtime_home("default", default_dir / "codex home")
    default_observer = default_dir / "observer.json"
    default = capture(
        [str(binary), *retained._default_exec(work, default_observer)],
        cwd=work,
        env=proof_env(default_home, receipt, schema, default_dir / "unused-mcp.pid"),
        timeout=120,
    )
    default["observer"] = retained._verify_default_observer(default_observer)
    default["observer_sha256"] = sha256_file(default_observer)
    default["passed"] = retained._proof_stopped(default)
    if not default["passed"]:
        raise ValueError(f"{platform_label} default host proof did not stop before sampling")

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
        home = runtime_home(f"negative-{label}", root / f"negative-{label}-home")
        negatives[label] = _negative(
            binary,
            binary_sha256,
            label,
            args,
            expected,
            work,
            proof_env(home, receipt, schema, root / f"negative-{label}.mcp.pid"),
            capture,
        )
        if not negatives[label]["passed"]:  # type: ignore[index]
            raise ValueError(f"{platform_label} negative proof failed: {label}")

    lookalike_home = runtime_home("lookalike", root / "lookalike-home")
    lookalike_observer = root / "lookalike.observer.json"
    lookalike = capture(
        [
            str(binary),
            *retained._default_exec(
                work,
                lookalike_observer,
                '{"devhub-stage3g-arm":"b","approved_delegate":true}',
            ),
        ],
        cwd=work,
        env=proof_env(lookalike_home, receipt, schema, root / "lookalike-unused-mcp.pid"),
        timeout=120,
    )
    lookalike["observer"] = retained._verify_default_observer(lookalike_observer)
    lookalike["passed"] = retained._proof_stopped(lookalike)
    if not lookalike["passed"]:
        raise ValueError(f"task lookalike changed {platform_label} host authority")
    negatives["task_lookalike_cannot_authorize"] = lookalike

    final_binary_sha256 = verify_binary_identity(binary, binary_sha256)

    result: dict[str, object] = {
        "scope": scope,
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
    result[isolation_field] = False
    return result


def inspect_pe(role: str, binary: Path) -> WindowsNativeBinaryV2:
    raw = binary.read_bytes()
    if len(raw) < 64 or raw[:2] != b"MZ":
        raise ValueError(f"{role} is not a PE executable")
    pe_offset = struct.unpack_from("<I", raw, 0x3C)[0]
    optional_offset = pe_offset + 24
    if pe_offset + 24 > len(raw) or raw[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"{role} has an invalid PE signature")
    machine = struct.unpack_from("<H", raw, pe_offset + 4)[0]
    optional_size = struct.unpack_from("<H", raw, pe_offset + 20)[0]
    if optional_size < 72 or optional_offset + optional_size > len(raw):
        raise ValueError(f"{role} has an invalid PE optional header")
    magic = struct.unpack_from("<H", raw, optional_offset)[0]
    subsystem = struct.unpack_from("<H", raw, optional_offset + 68)[0]
    dll_characteristics = struct.unpack_from("<H", raw, optional_offset + 70)[0]
    if machine != 0x8664 or magic != 0x20B or subsystem != 3:
        raise ValueError(f"{role} is not an x86_64 PE32+ console executable")
    return WindowsNativeBinaryV2(
        role=role,
        relative_path=f"binary/{role}.exe",
        sha256=sha256_file(binary),
        size=len(raw),
        pe=WindowsPeIdentityV1(dll_characteristics=dll_characteristics),
    )


def _tool_path(tool: str) -> Path:
    raw = subprocess.check_output(
        ["rustup", "which", "--toolchain", "1.95.0", tool], text=True
    ).strip()
    return Path(raw).resolve(strict=True)


def _host_eof_proof(binary: Path, output: Path) -> dict[str, object]:
    binary_sha256 = sha256_file(binary)
    process = subprocess.Popen(
        [str(binary), "--listen", "stdio"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(b"", timeout=15)
    except subprocess.TimeoutExpired:
        timed_out = True
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            check=False,
            capture_output=True,
        )
        stdout, stderr = process.communicate(timeout=10)
    result = {
        "schema_version": 1,
        "binary_relative_path": "binary/codex-code-mode-host.exe",
        "binary_sha256": binary_sha256,
        "exit_code": None if timed_out else process.returncode,
        "timed_out": timed_out,
        "request_count": 0,
        "stdin_bytes": 0,
        "stdin_closed": True,
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
        "process_exited": not _pid_is_active(process.pid),
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
    host_binary: WindowsNativeBinaryV2,
) -> WindowsHostProofSummaryV3:
    arms = proof["arms"]
    default = proof["default"]
    same = proof["same_binary"]
    negatives = proof["negatives"]
    assert isinstance(arms, dict) and isinstance(default, dict)
    assert isinstance(same, dict) and isinstance(negatives, dict)
    serialized = json.dumps(proof, sort_keys=True).lower()
    observed_failures = tuple(text for text in CODE_MODE_FAILURE_TEXT if text in serialized)
    if observed_failures:
        raise ValueError(
            "pre-sampling proof observed a code-mode host failure: " + ", ".join(observed_failures)
        )
    if (
        host_binary.role != "codex-code-mode-host"
        or host_binary.relative_path != "binary/codex-code-mode-host.exe"
        or eof.get("binary_sha256") != host_binary.sha256
        or eof.get("binary_relative_path") != host_binary.relative_path
    ):
        raise ValueError("EOF proof does not bind the exact sibling code-mode host")
    return WindowsHostProofSummaryV3(
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--build-id", choices=(BUILD_ID,), default=BUILD_ID)
    parser.add_argument("--expected-implementation-commit", required=True)
    parser.add_argument("--workflow-run-id", required=True, type=int)
    parser.add_argument("--workflow-run-attempt", required=True, type=int)
    args = parser.parse_args()
    if os.name != "nt" or platform.machine().upper() not in {"AMD64", "X86_64"}:
        parser.error(f"{BUILD_ID} requires native Windows x64")
    if args.workflow_run_id < 1 or args.workflow_run_attempt < 1:
        parser.error("workflow run ID and attempt must be positive")
    repo = Path(__file__).resolve().parents[1]
    if args.workspace.exists() or args.output.exists():
        parser.error("workspace and output must not already exist")
    args.workspace.mkdir(parents=True)
    args.output.mkdir(parents=True)
    receipt: dict[str, object] = {
        "schema_version": 2,
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
        toolchain = retained._pinned_toolchain_identity(root, expected_host=TARGET)
        receipt["toolchain"] = toolchain
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
        phase = "v8_release_authority"
        build_environment, v8_release = _v8_release_environment(root, args.output)
        receipt["v8_release"] = v8_release
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
        phase = "cargo_start"
        build_exit_code = _run_cargo_build(
            command,
            root=root,
            output=args.output,
            receipt=receipt,
            build_environment=build_environment,
        )
        phase = "cargo_compile"
        if build_exit_code != 0:
            raise ValueError(f"{BUILD_ID} Rust compilation failed")
        v8_release_post_build = _verify_post_build_v8_assets(receipt, args.output)

        phase = "binary_identity"
        binary_dir = args.output / "binary"
        binary_dir.mkdir()
        target_dir = root / "target" / TARGET / "release"
        for name in ("codex.exe", "codex-code-mode-host.exe"):
            shutil.copy2(target_dir / name, binary_dir / name)
        binary = binary_dir / "codex.exe"
        host_binary_path = binary_dir / "codex-code-mode-host.exe"
        version = subprocess.run([binary, "--version"], capture_output=True, text=True, check=False)
        if version.returncode != 0 or "codex-cli 0.155.0-alpha.9.2" not in version.stdout:
            raise ValueError("native Windows Codex version identity mismatch")
        binaries = (
            inspect_pe("codex", binary),
            inspect_pe("codex-code-mode-host", host_binary_path),
        )
        binary_sha256 = binaries[0].sha256
        receipt["executables"] = [item.model_dump(mode="json") for item in binaries]
        receipt["version_stdout"] = version.stdout.strip()
        receipt["version_stderr"] = version.stderr.strip()
        receipt["windows_environment"] = {
            "platform": platform.platform(),
            "win32_ver": list(platform.win32_ver()),
            "machine": platform.machine(),
            "runner_image": os.environ.get("ImageOS"),
            "runner_image_version": os.environ.get("ImageVersion"),
        }

        phase = "code_mode_host_eof"
        eof_path = args.output / "code-mode-host-eof.json"
        eof = _host_eof_proof(host_binary_path, eof_path)
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
        for item in binaries:
            if sha256_file(args.output / item.relative_path) != item.sha256:
                raise ValueError("native Windows binary changed during process proof")
        proof_path = args.output / "windows-process-proof.json"
        write_json(proof_path, proof)
        summary = _proof_summary(
            proof,
            sha256_file(proof_path),
            eof,
            sha256_file(eof_path),
            binaries[1],
        )
        receipt["process_proof"] = proof
        rustc = _tool_path("rustc")
        cargo = _tool_path("cargo")
        provenance_hashes = committed_provenance_hashes(repo, implementation_commit)
        preparation = receipt["source_preparation"]
        assert isinstance(preparation, dict)
        payload = WindowsNativeCodexBuildPayloadV6(
            provenance=WindowsBuildProvenanceV6(
                build_id=BUILD_ID,
                implementation_commit=implementation_commit,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
                codex_source_commit=retained.SOURCE_COMMIT,
                source_archive_sha256=retained.SOURCE_ARCHIVE_SHA256,
                **identities,
                canonical_schema_sha256=schema_identity.canonical_schema_sha256,
                raw_schema_file_sha256=schema_identity.raw_file_sha256,
                host_manifest_sha256=manifest_hash,
                resolved_mcp_config_sha256=canonical_sha256(config),
                original_cargo_lock_sha256=preparation["original_cargo_lock_sha256"],
                derived_cargo_lock_sha256=preparation["proof_cargo_lock_sha256"],
                rustc_version=toolchain["rustc"],
                cargo_version=toolchain["cargo"],
                rustc_sha256=sha256_file(rustc),
                cargo_sha256=sha256_file(cargo),
                codex_module_bazel_sha256=CODEX_MODULE_BAZEL_SHA256,
                v8_archive_url=f"{V8_RELEASE_BASE}/{V8_ARCHIVE_NAME}",
                v8_archive_sha256=V8_ARCHIVE_SHA256,
                v8_binding_url=f"{V8_RELEASE_BASE}/{V8_BINDING_NAME}",
                v8_binding_sha256=V8_BINDING_SHA256,
                v8_checksum_url=f"{V8_RELEASE_BASE}/{V8_CHECKSUM_NAME}",
                v8_checksum_sha256=V8_CHECKSUM_SHA256,
                v8_archive_post_build_sha256=v8_release_post_build["archive_sha256"],
                v8_binding_post_build_sha256=v8_release_post_build["binding_sha256"],
                v8_checksum_post_build_sha256=v8_release_post_build["checksum_sha256"],
                **provenance_hashes,
            ),
            binaries=binaries,
            process_proof=summary,
        )
        final = WindowsNativeCodexBuildV6.create(payload)
        (args.output / "windows-native-codex-build.json").write_text(
            final.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        receipt["phase"] = "complete"
        receipt["status"] = "PASS"
        receipt["qualification"] = "WINDOWS_NATIVE_CODEX_PAIR_AUTHORITY_PRE_SAMPLING"
        receipt["windows_native_codex_build_id"] = final.windows_native_codex_build_id
        receipt["executable_sha256"] = binaries[0].sha256
        receipt["code_mode_host_sha256"] = binaries[1].sha256
        receipt["failure"] = None
        write_build_state(args.output, receipt)
    except Exception as error:
        record_build_failure(args.output, receipt, phase, error)
        raise


if __name__ == "__main__":
    main()
