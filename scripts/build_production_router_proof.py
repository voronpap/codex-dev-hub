"""Compile the admission patch in a disposable tree; no shipping/runtime activation."""

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

from derive_router_build_lock import DERIVED, ORIGINAL, derive
from instrument_approval_proof import instrument
from run_production_diagnostics import run_suite

COMMIT = "4607249e430dac1c961df4dc615beae88e33cec8"
ARCHIVE = "d9478b4d5bb98d4f6eaa6f57dc51b759f0fc70ebd29614f6b1edf7979564ebd2"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--derived-test-build-lock", action="store_true")
    args = parser.parse_args()
    args.workspace.mkdir(parents=True, exist_ok=False)
    repo = Path(__file__).resolve().parents[1]
    raw = urllib.request.urlopen(
        f"https://codeload.github.com/openai/codex/tar.gz/{COMMIT}", timeout=60
    ).read()
    assert hashlib.sha256(raw).hexdigest() == ARCHIVE
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        archive.extractall(args.workspace, filter="data")
    root = args.workspace / f"codex-{COMMIT}" / "codex-rs"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    original_lock = (root / "Cargo.lock").read_bytes()
    assert hashlib.sha256(original_lock).hexdigest() == ORIGINAL
    (args.output.parent / "Cargo.lock.original").write_bytes(original_lock)
    if args.derived_test_build_lock:
        derived, changes = derive(root)
        (args.output.parent / "derived-lock-manifest-bindings.json").write_text(
            json.dumps(changes, indent=2) + "\n", encoding="utf-8"
        )
        # Disposable proof tree only; original bytes retained separately, production unchanged.
        (root / "Cargo.lock").write_bytes(derived)
    patch = (repo / "patches/stage3g-approved-call/candidate.patch").read_bytes()
    assert (
        hashlib.sha256(patch).hexdigest()
        == "d2e27068ca8020f014c7cd3bea2cc73181b1b892d8e6869814680d2076eb3e36"
    )
    subprocess.run(["git", "apply", "--check", "-"], cwd=root.parent, input=patch, check=True)
    subprocess.run(["git", "apply", "-"], cwd=root.parent, input=patch, check=True)
    diagnostic_hashes = instrument(root)
    target = root / "core/src/tools/spec_plan_tests.rs"
    original = target.read_bytes()
    test_name = "production_router_test.rs"
    test_filter = "devhub_production_admission_path"
    test = (repo / "scripts" / test_name).read_bytes()
    adversarial = (repo / "scripts/production_router_adversarial_test.rs").read_bytes()
    catalog_test = (repo / "scripts/production_catalog_test.rs").read_bytes()
    target.write_bytes(original + b"\n" + test + b"\n" + adversarial)
    catalog_target = root / "codex-mcp/src/binding.rs"
    catalog_target.write_bytes(catalog_target.read_bytes() + b"\n" + catalog_test)
    metadata = (repo / "docs/evidence/stage3g-full-router/metadata.json").read_bytes()
    target.with_name("devhub_metadata.json").write_bytes(metadata)
    schema = (
        repo / "docs/evidence/stage3g-production-router/delegate-input-schema.json"
    ).read_bytes()
    target.with_name("devhub_real_schema.json").write_bytes(schema)
    payload = (repo / "patches/stage3g-approved-call/synthetic-payload.json").read_bytes()
    target.with_name("devhub_synthetic_payload.json").write_bytes(payload)
    catalog_target.with_name("devhub_real_schema.json").write_bytes(schema)
    catalog_target.with_name("devhub_synthetic_payload.json").write_bytes(payload)
    environment = dict(
        os.environ,
        DEVHUB_SYNTHETIC_MCP=str(repo / "scripts/synthetic_approved_mcp.py"),
        DEVHUB_REAL_SCHEMA=str(target.with_name("devhub_real_schema.json")),
        CARGO_BUILD_JOBS="2",
        CARGO_INCREMENTAL="0",
        CARGO_PROFILE_DEV_DEBUG="0",
        CARGO_PROFILE_TEST_DEBUG="0",
    )
    # Compilation may fetch locked dependencies; test execution must have network denied.
    command = [
        "cargo",
        "test",
        "--locked",
        "-p",
        "codex-core",
        "-p",
        "codex-mcp",
        "--lib",
        test_filter,
        "--no-run",
        "--message-format=json",
    ]
    timed_out = False
    build_started = time.monotonic()
    with (args.output.parent / "build.jsonl").open("xb") as stdout:
        with (args.output.parent / "build.stderr").open("xb") as stderr:
            try:
                build = subprocess.run(
                    command,
                    cwd=root,
                    env=environment,
                    stdout=stdout,
                    stderr=stderr,
                    timeout=2400,
                    check=False,
                )
                build_exit_code = build.returncode
            except subprocess.TimeoutExpired:
                build_exit_code = None
                timed_out = True
    receipt = {
        "source_commit": COMMIT,
        "build_id": "build-008",
        "diagnostic_source_hashes": diagnostic_hashes,
        "adversarial_sha256": hashlib.sha256(adversarial).hexdigest(),
        "catalog_test_sha256": hashlib.sha256(catalog_test).hexdigest(),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "archive_sha256": ARCHIVE,
        "test_sha256": hashlib.sha256(test).hexdigest(),
        "test_file": test_name,
        "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
        "implementation_commit": os.environ.get("GITHUB_SHA"),
        "build_duration_seconds": time.monotonic() - build_started,
        "production_modified": True,
        "shipping_runtime_modified": False,
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
        "classification": "UNKNOWN",
        "scope": "partial production admission implementation; full required gate unproven",
        "original_lock_sha256": ORIGINAL,
        "proof_build_lock_sha256": DERIVED if args.derived_test_build_lock else ORIGINAL,
        "lock_strategy": "LOCK_B_derived_test_build"
        if args.derived_test_build_lock
        else "original",
        "build_command": command,
        "build_exit_code": build_exit_code,
        "build_timed_out": timed_out,
        "actual_pinned_router_code": None,
        "method_slice_only": False,
        "inference_requests": 0,
        "real_codex_executions": 0,
        "provider_sends": 0,
    }
    assert (
        hashlib.sha256((root / "Cargo.lock").read_bytes()).hexdigest()
        == receipt["proof_build_lock_sha256"]
    )
    if build_exit_code == 0:
        events = [
            json.loads(line)
            for line in (args.output.parent / "build.jsonl").read_bytes().splitlines()
        ]
        binaries = {
            e["target"]["name"]: e["executable"]
            for e in events
            if e.get("reason") == "compiler-artifact"
            and e.get("executable")
            and e.get("target", {}).get("name") in {"codex_core", "codex_mcp"}
        }
        assert set(binaries) == {"codex_core", "codex_mcp"}
        assets = args.output.parent / "assets"
        assets.mkdir(exist_ok=False)
        for filename in [
            "synthetic_approved_mcp.py",
            "run_production_diagnostics.py",
            "build_production_router_proof.py",
            "instrument_approval_proof.py",
            "production_router_test.rs",
            "production_router_adversarial_test.rs",
            "production_catalog_test.rs",
        ]:
            shutil.copy2(repo / "scripts" / filename, assets / filename)
        for filename, content in [
            ("devhub_real_schema.json", schema),
            ("devhub_synthetic_payload.json", payload),
            ("devhub_metadata.json", metadata),
        ]:
            (assets / filename).write_bytes(content)
        asset_hashes = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in assets.iterdir()
        }
        receipt["diagnostic_harness_sha256"] = hashlib.sha256(
            json.dumps(asset_hashes, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        receipt["asset_hashes"] = asset_hashes
        receipt["toolchain"] = {
            "rustc": subprocess.check_output(["rustc", "-vV"], cwd=root).decode(),
            "cargo": subprocess.check_output(["cargo", "--version"], cwd=root).decode(),
            "platform": platform.platform(),
            "target": "default rustc host target (no --target override)",
            "build_environment": {
                k: environment[k]
                for k in environment
                if k.startswith("CARGO_")
                and k
                in {
                    "CARGO_BUILD_JOBS",
                    "CARGO_INCREMENTAL",
                    "CARGO_PROFILE_DEV_DEBUG",
                    "CARGO_PROFILE_TEST_DEBUG",
                }
            },
        }
        preserved = {}
        binary_dir = args.output.parent / "binaries"
        binary_dir.mkdir(exist_ok=False)
        # Retain BOTH executables and their provenance before enumeration/tests.
        for crate, executable in binaries.items():
            original_binary = Path(executable)
            saved = binary_dir / original_binary.name
            shutil.copy2(original_binary, saved)
            digest = hashlib.sha256(saved.read_bytes()).hexdigest()
            assert digest == hashlib.sha256(original_binary.read_bytes()).hexdigest()
            libraries = subprocess.run(["ldd", str(saved)], capture_output=True, check=False)
            preserved[crate] = {
                "crate": crate,
                "path": str(saved),
                "original_path": executable,
                "sha256": digest,
                "source_commit": COMMIT,
                "patch_sha256": receipt["patch_sha256"],
                "diagnostic_harness_sha256": receipt["diagnostic_harness_sha256"],
                "proof_lock_sha256": receipt["proof_build_lock_sha256"],
                "ldd": libraries.stdout.decode(errors="replace"),
                "ldd_stderr": libraries.stderr.decode(errors="replace"),
                "ldd_exit": libraries.returncode,
                "runtime_assumptions": (
                    "Linux runner ABI; python3; sudo/unshare/setpriv; "
                    "restore executable bit after download; "
                    "paths in manifest require rebinding after relocation"
                ),
            }
        receipt["compiled_binaries"] = preserved
        receipt["instrumentation_changes_stack_layout"] = True
        receipt["build_007_root_cause"] = "UNKNOWN"
        receipt["process_proof"] = None
        receipt["execution_ready"] = False
        # A pre-test manifest survives abort/timeout and includes all immutable assets.
        (args.output.parent / "runner-manifest.json").write_text(
            json.dumps(receipt, indent=2) + "\n"
        )
        receipt["test_runs"] = run_suite(preserved, args.output.parent / "runs", assets)
        receipt["actual_pinned_router_code"] = (
            all(run["exit_code"] == 0 for run in receipt["test_runs"])
            and len(receipt["test_runs"]) >= 3
        )
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    if receipt["actual_pinned_router_code"] is not True:
        raise SystemExit("Full pinned proof incomplete; classification UNKNOWN")


if __name__ == "__main__":
    main()
