"""Compile the admission patch in a disposable tree; no shipping/runtime activation."""

import argparse
import hashlib
import io
import json
import os
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path

from derive_router_build_lock import DERIVED, ORIGINAL, derive

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
    subprocess.run(["git", "apply", "--check", "-"], cwd=root.parent, input=patch, check=True)
    subprocess.run(["git", "apply", "-"], cwd=root.parent, input=patch, check=True)
    target = root / "core/src/tools/spec_plan_tests.rs"
    original = target.read_bytes()
    test_name = "production_router_test.rs"
    test_filter = "devhub_production_admission_path"
    test = (repo / "scripts" / test_name).read_bytes()
    target.write_bytes(original + b"\n" + test)
    metadata = (repo / "docs/evidence/stage3g-full-router/metadata.json").read_bytes()
    target.with_name("devhub_metadata.json").write_bytes(metadata)
    schema = (
        repo / "docs/evidence/stage3g-production-router/delegate-input-schema.json"
    ).read_bytes()
    target.with_name("devhub_real_schema.json").write_bytes(schema)
    payload = (repo / "patches/stage3g-approved-call/synthetic-payload.json").read_bytes()
    target.with_name("devhub_synthetic_payload.json").write_bytes(payload)
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
        "build_id": "build-002",
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
        binaries = [
            e["executable"]
            for e in events
            if e.get("reason") == "compiler-artifact"
            and e.get("executable")
            and e.get("target", {}).get("name") == "codex_core"
        ]
        assert len(binaries) == 1
        receipt["test_binary_sha256"] = hashlib.sha256(Path(binaries[0]).read_bytes()).hexdigest()
        # Root is used only to create an isolated network namespace, then drop to runner UID.
        test_started = time.monotonic()
        run = subprocess.run(
            [
                "sudo",
                "--preserve-env=DEVHUB_SYNTHETIC_MCP,DEVHUB_REAL_SCHEMA",
                "unshare",
                "--net",
                "--",
                "setpriv",
                f"--reuid={os.getuid()}",
                f"--regid={os.getgid()}",
                "--init-groups",
                binaries[0],
                test_filter,
                "--nocapture",
            ],
            cwd=root,
            env=environment,
            capture_output=True,
            timeout=120,
        )
        (args.output.parent / "test.stdout").write_bytes(run.stdout)
        (args.output.parent / "test.stderr").write_bytes(run.stderr)
        receipt["test_exit_code"] = run.returncode
        receipt["test_duration_seconds"] = time.monotonic() - test_started
        for line in run.stdout.decode().splitlines():
            if line.startswith("DEVHUB_ROUTER_PROOF="):
                receipt["proof"] = json.loads(line.split("=", 1)[1])
        receipt["actual_pinned_router_code"] = run.returncode == 0 and "proof" in receipt
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    if receipt["actual_pinned_router_code"] is not True:
        raise SystemExit("Full pinned proof incomplete; classification UNKNOWN")


if __name__ == "__main__":
    main()
