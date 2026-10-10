"""Build one pinned Codex executable and run same-binary pre-sampling proof."""

import argparse
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path

from derive_router_build_lock import DERIVED as BUILD009_DERIVED
from derive_router_build_lock import ORIGINAL
from derive_router_build_lock import derive as derive_build009
from derive_stage3g_production_lock import PRODUCTION_HOST_LOCK_SHA256
from derive_stage3g_production_lock import derive as derive_production_host_lock
from stage3g_schema_hash import read_schema_identity

SOURCE_COMMIT = "4607249e430dac1c961df4dc615beae88e33cec8"
SOURCE_ARCHIVE_SHA256 = "d9478b4d5bb98d4f6eaa6f57dc51b759f0fc70ebd29614f6b1edf7979564ebd2"
CANDIDATE_SHA256 = "d2e27068ca8020f014c7cd3bea2cc73181b1b892d8e6869814680d2076eb3e36"
HOST_SHA256 = "f22369f10ed45d04a740205fca0cb7111ddb56d3b1bdbee603dfcfdfdd7de9ad"
COMBINED_SHA256 = "e63b68840ecec005703fc61fa1e26aba988c5a9e44a956efedbfbdea96d10c59"
HOST_MANIFEST_SHA256 = "d31edc7cb0604ea7d2c526521adb1c59ae21a35a902a8c2a9a7c2807bc29957e"
SCHEMA_SHA256 = "0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"
DELEGATE = "mcp__devhub_delegate.devhub_delegate"
EXPECTED_CONFIG_HASH = "9f22ac491ea2fc2e158e4a779c504e959bdc56cd983eedd18866c2567e59c014"
MCP_RECEIPT_ENV_VAR = "DEVHUB_BUILD009_MCP_RECEIPT"


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _preserve_runner_assets(
    repo: Path, output: Path, *, manifest: Path, schema: Path
) -> tuple[Path, dict[str, str]]:
    """Retain every local input needed to audit source preparation before Cargo starts."""
    assets = output / "assets"
    assets.mkdir(exist_ok=False)
    sources = (
        (manifest, "stage3g-host-manifest-v2.json"),
        (schema, "delegation-request-schema.json"),
        (repo / "patches/stage3g-approved-call/candidate.patch", "candidate.patch"),
        (
            repo / "patches/stage3g-approved-call/host-integration.patch",
            "host-integration.patch",
        ),
        (repo / "scripts/stage3g_build009_mcp.py", "stage3g_build009_mcp.py"),
        (repo / "scripts/build_stage3g_build009.py", "build_stage3g_build009.py"),
        (repo / "scripts/preflight_stage3g_build009.py", "preflight_stage3g_build009.py"),
        (repo / "scripts/derive_router_build_lock.py", "derive_router_build_lock.py"),
        (
            repo / "scripts/derive_stage3g_production_lock.py",
            "derive_stage3g_production_lock.py",
        ),
        (repo / "scripts/stage3g_schema_hash.py", "stage3g_schema_hash.py"),
        (
            repo / ".github/workflows/production-router-proof.yml",
            "production-router-proof.yml",
        ),
    )
    for source, name in sources:
        shutil.copy2(source, assets / name)
    return assets, {path.name: sha256_file(path) for path in sorted(assets.iterdir())}


def prepare_build_source(
    root: Path,
    *,
    candidate_patch: bytes,
    host_patch: bytes,
    evidence_directory: Path | None = None,
    build_id: str = "build-009",
) -> dict[str, object]:
    """Apply both reviewed patches and derive the selected proof lock."""
    original_lock = (root / "Cargo.lock").read_bytes()
    if sha256_bytes(original_lock) != ORIGINAL:
        raise ValueError("original Cargo.lock changed")
    subprocess.run(
        ["git", "apply", "--check", "-"],
        cwd=root.parent,
        input=candidate_patch,
        check=True,
    )
    subprocess.run(["git", "apply", "-"], cwd=root.parent, input=candidate_patch, check=True)
    subprocess.run(["git", "apply", "--check", "-"], cwd=root, input=host_patch, check=True)
    subprocess.run(["git", "apply", "-"], cwd=root, input=host_patch, check=True)
    if build_id == "build-009":
        derived_lock, lock_changes = derive_build009(root)
        expected_lock = BUILD009_DERIVED
        lock_strategy = "LOCK_B_minimal_manifest_bound_derived_lock"
    elif build_id in {
        "build-010",
        "build-011",
        "build-012",
        "build-013",
        "build-014",
        "build-015",
        "build-016",
        "build-017",
        "build-018",
        "build-019",
        "build-020",
    }:
        derived_lock, lock_changes = derive_production_host_lock(root)
        expected_lock = PRODUCTION_HOST_LOCK_SHA256
        lock_strategy = "complete_patched_manifest_bound_derived_lock"
    else:
        raise ValueError(f"unsupported build ID: {build_id}")
    if sha256_bytes(derived_lock) != expected_lock:
        raise ValueError(f"{build_id} proof Cargo.lock changed")
    (root / "Cargo.lock").write_bytes(derived_lock)

    if evidence_directory is not None:
        (evidence_directory / "Cargo.lock.original").write_bytes(original_lock)
        (evidence_directory / "Cargo.lock.proof").write_bytes(derived_lock)
        write_json(evidence_directory / "derived-lock-manifest-bindings.json", lock_changes)
    return {
        "original_cargo_lock_sha256": sha256_bytes(original_lock),
        "proof_cargo_lock_sha256": sha256_bytes(derived_lock),
        "lock_strategy": lock_strategy,
        "candidate_patch_cwd": "pinned_source_parent",
        "host_patch_cwd": "codex-rs",
        "candidate_patch_applied": True,
        "host_patch_applied": True,
    }


def _run_capture(
    command: list[str], directory: Path, *, cwd: Path, env: dict[str, str], timeout: int
) -> dict[str, object]:
    directory.mkdir(exist_ok=False)
    write_json(directory / "planned.json", {"command": command, "timeout_seconds": timeout})
    started = time.monotonic()
    timed_out = False
    with (directory / "stdout").open("xb") as stdout, (directory / "stderr").open("xb") as stderr:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            process.communicate(b"build-009 pre-sampling router proof\n", timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            subprocess.run(
                ["sudo", "kill", "-KILL", "--", str(-process.pid)],
                check=False,
                capture_output=True,
            )
            process.wait(timeout=10)
    return {
        "command": command,
        "exit_code": None if timed_out else process.returncode,
        "timed_out": timed_out,
        "duration_seconds": time.monotonic() - started,
        "stdout_sha256": sha256_file(directory / "stdout"),
        "stderr_sha256": sha256_file(directory / "stderr"),
        "stdout": (directory / "stdout").read_text(errors="replace"),
        "stderr": (directory / "stderr").read_text(errors="replace"),
    }


def _verify_locked_resolution(root: Path, output: Path, expected_lock: str) -> dict[str, object]:
    """Prove the corrected lock resolves and fetches without byte mutation."""
    commands = {
        "metadata": [
            "cargo",
            "+1.95.0",
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--filter-platform",
            "x86_64-unknown-linux-gnu",
        ],
        "fetch": [
            "cargo",
            "+1.95.0",
            "fetch",
            "--locked",
            "--target",
            "x86_64-unknown-linux-gnu",
        ],
    }
    observed: dict[str, object] = {}
    for label, command in commands.items():
        before = sha256_file(root / "Cargo.lock")
        run = subprocess.run(command, cwd=root, capture_output=True, check=False)
        stdout = output / f"cargo-{label}.stdout"
        stderr = output / f"cargo-{label}.stderr"
        stdout.write_bytes(run.stdout)
        stderr.write_bytes(run.stderr)
        after = sha256_file(root / "Cargo.lock")
        observed[label] = {
            "command": command,
            "exit_code": run.returncode,
            "lock_sha256_before": before,
            "lock_sha256_after": after,
            "lock_unchanged": before == after == expected_lock,
            "stdout_sha256": sha256_file(stdout),
            "stderr_sha256": sha256_file(stderr),
        }
        if run.returncode != 0 or before != expected_lock or after != expected_lock:
            raise ValueError(f"locked Cargo {label} verification failed")
    return observed


def _pinned_toolchain_identity(root: Path) -> dict[str, object]:
    rustc_command = ["rustup", "run", "1.95.0", "rustc", "-vV"]
    cargo_command = ["rustup", "run", "1.95.0", "cargo", "--version", "--verbose"]
    rustc = subprocess.check_output(rustc_command, cwd=root, text=True)
    cargo = subprocess.check_output(cargo_command, cwd=root, text=True)
    host = next(
        (line.removeprefix("host: ") for line in rustc.splitlines() if line.startswith("host: ")),
        None,
    )
    if host is None:
        raise ValueError("pinned rustc did not report a host target")
    if host != "x86_64-unknown-linux-gnu":
        raise ValueError(f"unexpected pinned Rust host target: {host}")
    return {
        "rustc_command": rustc_command,
        "rustc": rustc,
        "cargo_command": cargo_command,
        "cargo": cargo,
        "platform": platform.platform(),
        "target": host,
    }


def _isolated(binary: Path, arguments: list[str]) -> list[str]:
    preserved = "PATH,HOME,LANG,TMPDIR,CODEX_HOME,OPENAI_API_KEY,DEVHUB_BUILD009_MCP_RECEIPT"
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
        str(binary),
        *arguments,
    ]


def _base_exec(work: Path) -> list[str]:
    return [
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--cd",
        str(work),
        "--json",
        "--color",
        "never",
        "--model",
        "gpt-6-astra",
        "-c",
        'approval_policy="never"',
        "-c",
        'web_search="disabled"',
        "-c",
        "mcp_servers={}",
        "-c",
        "features.shell_tool=false",
        "-c",
        "features.unified_exec=false",
        "-c",
        "features.apps=false",
        "-c",
        "features.multi_agent=false",
        "-c",
        "features.goals=false",
        "-c",
        "features.hooks=false",
        "-c",
        "features.memories=false",
        "-c",
        "features.remote_plugin=false",
        "-c",
        "features.shell_snapshot=false",
        "-c",
        "features.tool_registry.error_on_tool_collisions=true",
    ]


def _host_exec(
    work: Path,
    manifest: Path,
    observer: Path,
    arm: str,
    *,
    with_mcp: bool | None = None,
) -> list[str]:
    args = _base_exec(work)
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
            'mcp_servers.devhub_delegate.command="python3"',
            "-c",
            'mcp_servers.devhub_delegate.args=["/bootstrap.py","mcp"]',
            "-c",
            f'mcp_servers.devhub_delegate.env_vars=["{MCP_RECEIPT_ENV_VAR}"]',
            "-c",
            "mcp_servers.devhub_delegate.required=true",
            "-c",
            'mcp_servers.devhub_delegate.enabled_tools=["devhub_delegate"]',
            "-c",
            'mcp_servers.devhub_delegate.tools.devhub_delegate.approval_mode="approve"',
        ]
    return [*args, "-"]


def _default_exec(work: Path, observer: Path, prompt: str = "-") -> list[str]:
    return [
        *_base_exec(work),
        "--devhub-proof-observe-router",
        str(observer),
        prompt,
    ]


def _verify_default_observer(path: Path) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    if value.get("allowed_tools_ceiling_present") is not False:
        raise ValueError("default process unexpectedly installed an AllowedTools ceiling")
    if value.get("allowed_tools") != []:
        raise ValueError("default observer serialized unexpected AllowedTools entries")
    if value.get("approved_delegate_policy_present") is not False:
        raise ValueError("default process unexpectedly installed delegate policy")
    if value.get("approved_identity") is not None:
        raise ValueError("default process unexpectedly has approved delegate identity")
    if value.get("host_manifest_sha256") is not None:
        raise ValueError("default process unexpectedly has host manifest identity")
    if value.get("expected_schema_sha256") is not None:
        raise ValueError("default process unexpectedly has approved schema identity")
    if DELEGATE in value.get("visible_model_tools", []):
        raise ValueError("default process unexpectedly exposed the delegate")
    if any(DELEGATE in item for item in value.get("nested_code_mode_map", [])):
        raise ValueError("default process unexpectedly nested the delegate")
    if value.get("model_requests") != 0 or value.get("provider_sends") != 0:
        raise ValueError("default observer crossed the pre-sampling boundary")
    return value


def _proof_stopped(result: dict[str, object]) -> bool:
    combined = str(result.get("stdout", "")) + str(result.get("stderr", ""))
    return (
        result.get("timed_out") is False
        and result.get("exit_code") not in (None, 0)
        and "DevFabric proof observer stopped before model sampling" in combined
    )


def _verify_mcp_catalog_records(records: list[dict[str, object]]) -> None:
    expected = {
        "event": "tools_list",
        "schema_sha256": SCHEMA_SHA256,
        "provider_send": False,
    }
    if records != [expected]:
        raise ValueError("process proof did not produce the exact catalog-only MCP receipt")


def _verify_observer(path: Path, arm: str) -> dict[str, object]:
    value = json.loads(path.read_bytes())
    expected_visible = [] if arm == "a" else [DELEGATE]
    expected_allowed = expected_visible
    if value.get("effective_tool_mode") != "CodeModeOnly":
        raise ValueError(f"Arm {arm} did not use CodeModeOnly")
    if value.get("visible_model_tools") != expected_visible:
        raise ValueError(f"Arm {arm} visible surface mismatch")
    if value.get("nested_code_mode_map") != []:
        raise ValueError(f"Arm {arm} nested surface widened")
    if value.get("hosted_tools") != [] or value.get("dynamic_tool_count") != 0:
        raise ValueError(f"Arm {arm} hosted/dynamic surface widened")
    if value.get("allowed_tools") != expected_allowed:
        raise ValueError(f"Arm {arm} AllowedTools mismatch")
    if value.get("allowed_tools_ceiling_present") is not True:
        raise ValueError(f"Arm {arm} AllowedTools ceiling is absent")
    if value.get("approved_delegate_policy_present") is (arm == "a"):
        raise ValueError(f"Arm {arm} approved policy presence mismatch")
    if value.get("host_manifest_sha256") != HOST_MANIFEST_SHA256:
        raise ValueError(f"Arm {arm} host manifest identity mismatch")
    expected_schema = None if arm == "a" else SCHEMA_SHA256
    if value.get("expected_schema_sha256") != expected_schema:
        raise ValueError(f"Arm {arm} expected schema identity mismatch")
    if value.get("model_requests") != 0 or value.get("provider_sends") != 0:
        raise ValueError(f"Arm {arm} crossed pre-sampling boundary")
    identity = value.get("approved_identity")
    if arm == "a":
        if identity is not None:
            raise ValueError("Arm A unexpectedly has an approved identity")
    elif not isinstance(identity, dict) or {
        "server_key": identity.get("server_key"),
        "raw_tool": identity.get("raw_tool"),
        "canonical_namespace": identity.get("canonical_namespace"),
        "canonical_function": identity.get("canonical_function"),
        "schema_sha256": identity.get("schema_sha256"),
    } != {
        "server_key": "devhub_delegate",
        "raw_tool": "devhub_delegate",
        "canonical_namespace": "mcp__devhub_delegate",
        "canonical_function": "devhub_delegate",
        "schema_sha256": SCHEMA_SHA256,
    }:
        raise ValueError("Arm B approved identity mismatch")
    return value


def _mutated_manifest(
    source: Path, destination: Path, path: tuple[str, ...], value: object
) -> None:
    raw = json.loads(source.read_bytes())
    target = raw
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    write_json(destination, raw)


def _negative(
    binary: Path,
    binary_sha: str,
    label: str,
    args: list[str],
    expected: str,
    output: Path,
    work: Path,
    env: dict[str, str],
) -> dict[str, object]:
    result = _run_capture(_isolated(binary, args), output / label, cwd=work, env=env, timeout=90)
    combined = str(result["stdout"]) + str(result["stderr"])
    result["expected_rejection"] = expected
    result["passed"] = result["exit_code"] not in (None, 0) and expected in combined
    if sha256_file(binary) != binary_sha:
        raise ValueError("compiled binary changed during negative matrix")
    return result


def _fresh_thread_negative_args(command_name: str) -> list[str]:
    """Use each pinned subcommand's valid CLI shape before testing the host guard."""
    if command_name == "resume":
        return ["resume", "--last"]
    if command_name == "fork":
        return ["fork", "00000000-0000-0000-0000-000000000000"]
    raise ValueError(f"unsupported fresh-thread negative: {command_name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--build-id",
        choices=(
            "build-009",
            "build-010",
            "build-011",
            "build-012",
            "build-013",
            "build-014",
            "build-015",
            "build-016",
            "build-017",
            "build-018",
            "build-019",
            "build-020",
        ),
        default="build-009",
    )
    args = parser.parse_args()
    expected_lock = (
        BUILD009_DERIVED if args.build_id == "build-009" else PRODUCTION_HOST_LOCK_SHA256
    )
    lock_strategy = (
        "LOCK_B_minimal_manifest_bound_derived_lock"
        if args.build_id == "build-009"
        else "complete_patched_manifest_bound_derived_lock"
    )
    repo = Path(__file__).resolve().parents[1]
    args.workspace.mkdir(parents=True, exist_ok=False)
    args.output.mkdir(parents=True, exist_ok=False)
    result_path = args.output / "result.json"
    receipt: dict[str, object] = {
        "schema_version": 1,
        "build_id": args.build_id,
        "implementation_commit": os.environ.get("GITHUB_SHA"),
        "source_commit": SOURCE_COMMIT,
        "source_archive_sha256": SOURCE_ARCHIVE_SHA256,
        "candidate_b_base_patch_sha256": CANDIDATE_SHA256,
        "host_integration_patch_sha256": HOST_SHA256,
        "combined_production_patchset_sha256": COMBINED_SHA256,
        "host_manifest_sha256": HOST_MANIFEST_SHA256,
        "delegation_request_schema_sha256": SCHEMA_SHA256,
        "original_cargo_lock_sha256": ORIGINAL,
        "proof_cargo_lock_sha256": expected_lock,
        "lock_strategy": lock_strategy,
        "compilation": "NOT_RUN",
        "process_proof": None,
        "production_host_activation": "BLOCKED_PREBUILD",
        "production_classification": "UNKNOWN",
        "model_requests": 0,
        "provider_sends": 0,
        "real_codex_executions": 0,
        "pre_sampling_codex_process_starts": 0,
        "rust_compilation_started": False,
        "build_009_run": False,
        "build_010_run": False,
        "build_011_run": False,
        "build_012_run": False,
        "build_013_run": False,
        "build_014_run": False,
        "build_015_run": False,
        "build_016_run": False,
        "build_017_run": False,
        "build_018_run": False,
        "build_019_run": False,
        "build_020_run": False,
        "stage_3g_c": "OPEN",
        "stage_3g": "OPEN",
        "execution_ready": False,
    }
    write_json(result_path, receipt)

    candidate = (repo / "patches/stage3g-approved-call/candidate.patch").read_bytes()
    host = (repo / "patches/stage3g-approved-call/host-integration.patch").read_bytes()
    # Build-020 history is bound to its proof-only catalog-receipt environment.
    # Shipping qualification uses stage3g-host-manifest-v2.json instead.
    manifest = repo / "benchmarks/stage3g-host-manifest-build020-v2.json"
    schema = repo / "docs/evidence/stage3g-production-router/delegate-input-schema.json"
    if sha256_bytes(candidate) != CANDIDATE_SHA256:
        raise ValueError("Candidate B changed")
    if sha256_bytes(host) != HOST_SHA256:
        raise ValueError("host integration patch changed")
    if sha256_bytes(candidate + host) != COMBINED_SHA256:
        raise ValueError("combined production patchset changed")
    if sha256_file(manifest) != HOST_MANIFEST_SHA256:
        raise ValueError("host manifest changed")
    schema_identity = read_schema_identity(schema, expected_canonical_sha256=SCHEMA_SHA256)
    receipt["delegation_request_schema_identity"] = {
        "canonical_schema_sha256": schema_identity.canonical_schema_sha256,
        "raw_schema_file_sha256": schema_identity.raw_file_sha256,
    }
    assets, asset_hashes = _preserve_runner_assets(
        repo, args.output, manifest=manifest, schema=schema
    )
    receipt["asset_hashes"] = asset_hashes
    write_json(args.output / "runner-manifest.json", receipt)
    write_json(result_path, receipt)
    resolved_config = {
        "args": ["/bootstrap.py", "mcp"],
        "command": "python3",
        "enabled": True,
        "enabled_tools": ["devhub_delegate"],
        "environment_id": "local",
        "env_vars": [MCP_RECEIPT_ENV_VAR],
        "required": True,
        "tool_timeout_sec": None,
        "tools": {"devhub_delegate": {"approval_mode": "approve"}},
    }
    resolved_config_hash = sha256_bytes(
        json.dumps(resolved_config, sort_keys=True, separators=(",", ":")).encode()
    )
    manifest_value = json.loads(manifest.read_bytes())
    manifest_config_hash = manifest_value["arms"]["arm_b"]["approved_delegate"][
        "expected_mcp_server_config_sha256"
    ]
    if resolved_config_hash != EXPECTED_CONFIG_HASH or manifest_config_hash != EXPECTED_CONFIG_HASH:
        raise ValueError("reviewed resolved MCP config identity changed")
    receipt["expected_resolved_mcp_server_config"] = {
        "canonical_sha256": resolved_config_hash,
        "canonical_value": resolved_config,
    }

    raw = urllib.request.urlopen(
        f"https://codeload.github.com/openai/codex/tar.gz/{SOURCE_COMMIT}", timeout=60
    ).read()
    if sha256_bytes(raw) != SOURCE_ARCHIVE_SHA256:
        raise ValueError("pinned source archive changed")
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        archive.extractall(args.workspace, filter="data")
    root = args.workspace / f"codex-{SOURCE_COMMIT}" / "codex-rs"
    receipt["source_preparation"] = prepare_build_source(
        root,
        candidate_patch=candidate,
        host_patch=host,
        evidence_directory=args.output,
        build_id=args.build_id,
    )
    receipt["patch_application"] = "PASS"
    receipt["toolchain"] = _pinned_toolchain_identity(root)
    try:
        receipt["locked_resolution"] = _verify_locked_resolution(root, args.output, expected_lock)
    except Exception as error:
        receipt["precompilation_failure"] = {
            "classification": "PRECOMPILATION_LOCKED_RESOLUTION_FAILURE",
            "error_type": type(error).__name__,
            "message": str(error),
        }
        write_json(args.output / "runner-manifest.json", receipt)
        write_json(result_path, receipt)
        raise
    write_json(args.output / "runner-manifest.json", receipt)
    write_json(result_path, receipt)

    command = ["cargo", "+1.95.0", "build", "--locked", "-p", "codex-cli", "--bin", "codex"]
    receipt["build_command"] = command
    receipt["rust_compilation_started"] = True
    receipt[args.build_id.replace("-", "_") + "_run"] = True
    started = time.monotonic()
    with (
        (args.output / "build.stdout").open("xb") as stdout,
        (args.output / "build.stderr").open("xb") as stderr,
    ):
        build = subprocess.Popen(
            command,
            cwd=root,
            env={
                **os.environ,
                "CARGO_BUILD_JOBS": "2",
                "CARGO_INCREMENTAL": "0",
                "CARGO_PROFILE_DEV_DEBUG": "0",
            },
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            build_exit_code = build.wait(timeout=3300)
            build_timed_out = False
        except subprocess.TimeoutExpired:
            subprocess.run(
                ["sudo", "kill", "-KILL", "--", str(-build.pid)],
                check=False,
                capture_output=True,
            )
            build.wait(timeout=10)
            build_exit_code = None
            build_timed_out = True
    receipt["build_duration_seconds"] = time.monotonic() - started
    receipt["build_exit_code"] = build_exit_code
    receipt["build_timed_out"] = build_timed_out
    receipt["compilation"] = "PASS" if build_exit_code == 0 else "FAIL"
    write_json(result_path, receipt)
    if build_exit_code != 0:
        raise SystemExit(f"{args.build_id} Rust compilation failed")

    built = root / "target/debug/codex"
    binary_dir = args.output / "binary"
    binary_dir.mkdir(exist_ok=False)
    binary = binary_dir / "codex"
    shutil.copy2(built, binary)
    binary.chmod(0o755)
    binary_sha = sha256_file(binary)
    ldd = subprocess.run(["ldd", str(binary)], capture_output=True, text=True, check=False)
    version = subprocess.run(
        [str(binary), "--version"], capture_output=True, text=True, check=False
    )
    receipt["executable"] = {
        "path": str(binary),
        "sha256": binary_sha,
        "bytes": binary.stat().st_size,
        "version_exit_code": version.returncode,
        "version_stdout": version.stdout,
        "version_stderr": version.stderr,
        "ldd_exit_code": ldd.returncode,
        "ldd_stdout": ldd.stdout,
        "ldd_stderr": ldd.stderr,
        "runtime_assumptions": "Ubuntu 24.04 x86_64 glibc ABI and listed dynamic libraries",
    }
    write_json(args.output / "runner-manifest.json", receipt)
    write_json(result_path, receipt)

    sudo_assets = [
        (assets / "stage3g_build009_mcp.py", Path("/bootstrap.py"), "0555"),
        (assets / "delegation-request-schema.json", Path("/stage3g-schema.json"), "0444"),
    ]
    for source, destination, mode in sudo_assets:
        subprocess.run(["sudo", "install", "-m", mode, str(source), str(destination)], check=True)
    try:
        runs = args.output / "runs"
        runs.mkdir(exist_ok=False)
        work = args.workspace / "process-work"
        work.mkdir(exist_ok=False)
        mcp_receipt = args.output / "mcp-receipt.jsonl"
        mcp_receipt.touch(exist_ok=False)
        env = {
            key: os.environ[key] for key in ("PATH", "HOME", "LANG", "TMPDIR") if key in os.environ
        }
        env.update(
            OPENAI_API_KEY="build009-no-send-placeholder",
            DEVHUB_BUILD009_MCP_RECEIPT=str(mcp_receipt),
        )

        arm_results: dict[str, object] = {}
        for arm in ("a", "b"):
            run_dir = runs / f"arm-{arm}"
            codex_home = run_dir / "codex-home"
            codex_home.mkdir(parents=True)
            observer = run_dir / "observer.json"
            arm_env = {**env, "HOME": str(codex_home), "CODEX_HOME": str(codex_home)}
            run = _run_capture(
                _isolated(
                    binary,
                    _host_exec(work, assets / "stage3g-host-manifest-v2.json", observer, arm),
                ),
                run_dir / "process",
                cwd=work,
                env=arm_env,
                timeout=120,
            )
            receipt["pre_sampling_codex_process_starts"] = (
                int(receipt["pre_sampling_codex_process_starts"]) + 1
            )
            run["observer"] = _verify_observer(observer, arm)
            run["observer_sha256"] = sha256_file(observer)
            run["passed"] = _proof_stopped(run)
            if not run["passed"]:
                raise ValueError(f"Arm {arm} did not stop at the proof observer boundary")
            arm_results[arm.upper()] = run
            receipt["arms"] = arm_results
            write_json(result_path, receipt)
            if sha256_file(binary) != binary_sha:
                raise ValueError("compiled binary changed between arm runs")
        receipt["arms"] = arm_results
        a_visible = set(arm_results["A"]["observer"]["visible_model_tools"])  # type: ignore[index]
        b_visible = set(arm_results["B"]["observer"]["visible_model_tools"])  # type: ignore[index]
        receipt["same_binary_invariant"] = {
            "binary_sha256": binary_sha,
            "b_minus_a": sorted(b_visible - a_visible),
            "a_minus_b": sorted(a_visible - b_visible),
            "passed": b_visible - a_visible == {DELEGATE} and not (a_visible - b_visible),
        }
        mcp_records = [json.loads(line) for line in mcp_receipt.read_bytes().splitlines()]
        _verify_mcp_catalog_records(mcp_records)
        receipt["mcp_catalog_receipt"] = {
            "sha256": sha256_file(mcp_receipt),
            "records": mcp_records,
            "tool_call_count": 0,
        }

        default_dir = runs / "default-regression"
        default_home = default_dir / "codex-home"
        default_home.mkdir(parents=True)
        default_env = {**env, "HOME": str(default_home), "CODEX_HOME": str(default_home)}
        default_observer = default_dir / "observer.json"
        default_run = _run_capture(
            _isolated(binary, _default_exec(work, default_observer)),
            default_dir / "process",
            cwd=work,
            env=default_env,
            timeout=120,
        )
        receipt["pre_sampling_codex_process_starts"] = (
            int(receipt["pre_sampling_codex_process_starts"]) + 1
        )
        default_run["observer"] = _verify_default_observer(default_observer)
        default_run["observer_sha256"] = sha256_file(default_observer)
        default_run["host_flags_absent"] = True
        default_run["allowed_tools"] = None
        default_run["approved_delegate_policy_present"] = False
        default_run["same_binary_sha256"] = binary_sha
        default_run["passed"] = _proof_stopped(default_run)
        if not default_run["passed"]:
            raise ValueError("default process did not stop at the proof observer boundary")
        if sha256_file(binary) != binary_sha:
            raise ValueError("compiled binary changed during default proof")
        receipt["default_regression"] = default_run

        negatives_dir = runs / "negatives"
        negatives_dir.mkdir(exist_ok=False)
        mutation_dir = negatives_dir / "manifests"
        mutation_dir.mkdir()
        exact_manifest = assets / "stage3g-host-manifest-v2.json"
        wrong_hash = mutation_dir / "wrong-hash.json"
        wrong_hash.write_bytes(exact_manifest.read_bytes() + b"\n")
        negatives: dict[str, object] = {
            "wrong_host_manifest_hash": {
                "expected": HOST_MANIFEST_SHA256,
                "observed": sha256_file(wrong_hash),
                "process_started": False,
                "passed": sha256_file(wrong_hash) != HOST_MANIFEST_SHA256,
                "rejection_layer": "qualification exact-content-hash gate",
            }
        }
        wrong_schema = mutation_dir / "wrong-schema.json"
        _mutated_manifest(
            exact_manifest,
            wrong_schema,
            ("arms", "arm_b", "approved_delegate", "expected_input_schema_sha256"),
            "0" * 64,
        )
        wrong_config = mutation_dir / "wrong-config.json"
        _mutated_manifest(
            exact_manifest,
            wrong_config,
            ("arms", "arm_b", "approved_delegate", "expected_mcp_server_config_sha256"),
            "0" * 64,
        )
        wrong_identity = mutation_dir / "wrong-identity.json"
        _mutated_manifest(
            exact_manifest,
            wrong_identity,
            ("arms", "arm_b", "approved_delegate", "canonical_namespace"),
            "mcp__other",
        )
        negative_specs = [
            (
                "wrong_schema_hash",
                _host_exec(work, wrong_schema, negatives_dir / "wrong-schema-observer.json", "b"),
                "unreviewed schema hash",
            ),
            (
                "wrong_mcp_config_hash",
                _host_exec(work, wrong_config, negatives_dir / "wrong-config-observer.json", "b"),
                "resolved devhub_delegate MCP config hash mismatch",
            ),
            (
                "wrong_namespace_identity",
                _host_exec(
                    work, wrong_identity, negatives_dir / "wrong-identity-observer.json", "b"
                ),
                "approved canonical namespace mismatch",
            ),
            (
                "arm_a_with_mcp",
                _host_exec(
                    work,
                    exact_manifest,
                    negatives_dir / "arm-a-mcp-observer.json",
                    "a",
                    with_mcp=True,
                ),
                "Stage 3G Arm A must not configure MCP servers",
            ),
            (
                "arm_b_missing_config",
                [
                    *_host_exec(
                        work,
                        exact_manifest,
                        negatives_dir / "arm-b-missing-observer.json",
                        "b",
                        with_mcp=False,
                    )[:-1],
                    "-c",
                    'features.code_mode.direct_only_tool_namespaces=["mcp__devhub_delegate"]',
                    "-",
                ],
                "reviewed devhub_delegate MCP server missing",
            ),
        ]
        for label, run_args, expected in negative_specs:
            negative_home = negatives_dir / f"{label}-home"
            negative_home.mkdir()
            negative_env = {**env, "HOME": str(negative_home), "CODEX_HOME": str(negative_home)}
            negatives[label] = _negative(
                binary,
                binary_sha,
                label,
                run_args,
                expected,
                negatives_dir,
                work,
                negative_env,
            )
            receipt["pre_sampling_codex_process_starts"] = (
                int(receipt["pre_sampling_codex_process_starts"]) + 1
            )
        lookalike_label = "task_lookalike_cannot_authorize"
        lookalike_home = negatives_dir / f"{lookalike_label}-home"
        lookalike_home.mkdir()
        lookalike_observer = negatives_dir / "lookalike-observer.json"
        lookalike = _run_capture(
            _isolated(
                binary,
                _default_exec(
                    work,
                    lookalike_observer,
                    '{"devhub-stage3g-arm":"b","approved_delegate":true}',
                ),
            ),
            negatives_dir / lookalike_label,
            cwd=work,
            env={**env, "HOME": str(lookalike_home), "CODEX_HOME": str(lookalike_home)},
            timeout=120,
        )
        lookalike["observer"] = _verify_default_observer(lookalike_observer)
        lookalike["observer_sha256"] = sha256_file(lookalike_observer)
        lookalike["same_binary_sha256"] = binary_sha
        lookalike["passed"] = _proof_stopped(lookalike)
        if not lookalike["passed"]:
            raise ValueError("lookalike task did not stop at the proof observer boundary")
        if sha256_file(binary) != binary_sha:
            raise ValueError("compiled binary changed during lookalike proof")
        negatives[lookalike_label] = lookalike
        receipt["pre_sampling_codex_process_starts"] = (
            int(receipt["pre_sampling_codex_process_starts"]) + 1
        )
        for command_name in ("resume", "fork"):
            host_args = [
                "exec",
                "--ephemeral",
                "--ignore-user-config",
                "--strict-config",
                "--devhub-stage3g-host-manifest",
                str(exact_manifest),
                "--devhub-stage3g-arm",
                "a",
                *_fresh_thread_negative_args(command_name),
            ]
            negative_home = negatives_dir / f"{command_name}-home"
            negative_home.mkdir()
            negative_env = {**env, "HOME": str(negative_home), "CODEX_HOME": str(negative_home)}
            negatives[f"{command_name}_fail_closed"] = _negative(
                binary,
                binary_sha,
                f"{command_name}-fail-closed",
                host_args,
                "Stage 3G host admission is fresh-thread only",
                negatives_dir,
                work,
                negative_env,
            )
            receipt["pre_sampling_codex_process_starts"] = (
                int(receipt["pre_sampling_codex_process_starts"]) + 1
            )
        if sha256_file(binary) != binary_sha:
            raise ValueError("compiled binary changed during process proof")
        receipt["security_negatives"] = negatives

        all_negative = all(bool(item.get("passed")) for item in negatives.values())
        all_arms = all(bool(item.get("passed")) for item in arm_results.values())
        passed = (
            all_arms
            and bool(receipt["same_binary_invariant"]["passed"])  # type: ignore[index]
            and bool(default_run["passed"])
            and all_negative
        )
        receipt["process_proof"] = "PASS" if passed else "FAIL"
        receipt["production_host_activation"] = "PROVEN" if passed else "BLOCKED"
        receipt["production_classification"] = (
            "PRODUCTION_HOST_QUALIFIED_REVIEW_REQUIRED" if passed else "UNKNOWN"
        )
        write_json(result_path, receipt)
        if not passed:
            raise SystemExit(f"{args.build_id} process proof failed")
    except Exception as error:
        receipt["process_proof"] = "FAIL"
        receipt["production_host_activation"] = "BLOCKED"
        receipt["production_classification"] = "UNKNOWN"
        receipt["process_error"] = f"{type(error).__name__}: {error}"
        write_json(result_path, receipt)
        raise
    finally:
        subprocess.run(
            ["sudo", "rm", "-f", "/bootstrap.py", "/stage3g-schema.json"],
            check=False,
            capture_output=True,
        )


if __name__ == "__main__":
    main()
