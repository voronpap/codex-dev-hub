"""Compile the admission patch in a disposable tree; no shipping/runtime activation."""

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import time
import urllib.request
from pathlib import Path

from derive_router_build_lock import DERIVED, ORIGINAL, derive
from instrument_approval_proof import instrument

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
    artifact_dir = args.output.parent / "runtime-artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    environment = dict(
        os.environ,
        DEVHUB_SYNTHETIC_MCP=str(repo / "scripts/synthetic_approved_mcp.py"),
        DEVHUB_REAL_SCHEMA=str(target.with_name("devhub_real_schema.json")),
        DEVHUB_PROOF_ARTIFACT_DIR=str(artifact_dir),
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
            e["target"]["name"]: Path(e["executable"])
            for e in events
            if e.get("reason") == "compiler-artifact"
            and e.get("executable")
            and e.get("target", {}).get("name") in {"codex_core", "codex_mcp"}
        }
        assert set(binaries) == {"codex_core", "codex_mcp"}

        preserved = {}
        binary_dir = artifact_dir / "binaries"
        binary_dir.mkdir(parents=True, exist_ok=True)
        for crate, source_binary in binaries.items():
            destination = binary_dir / source_binary.name
            shutil.copy2(source_binary, destination)
            destination.chmod(destination.stat().st_mode | 0o100)
            preserved[crate] = destination

        rustc = subprocess.run(
            ["rustc", "--version", "--verbose"],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        manifest = {
            "source_commit": COMMIT,
            "production_patch_sha256": hashlib.sha256(patch).hexdigest(),
            "diagnostic_source_hashes": diagnostic_hashes,
            "proof_build_lock_sha256": receipt["proof_build_lock_sha256"],
            "toolchain": rustc,
            "platform": os.uname().sysname + " " + os.uname().machine,
            "binaries": {},
        }
        for crate, binary in preserved.items():
            ldd = subprocess.run(
                ["ldd", str(binary)],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            manifest["binaries"][crate] = {
                "artifact_path": str(binary.relative_to(args.output.parent)),
                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "runtime_requirements": ldd.stdout if ldd.returncode == 0 else ldd.stderr,
            }
        (artifact_dir / "binary-manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        receipt["binary_manifest"] = manifest

        def list_tests(crate, binary):
            listed = subprocess.run(
                [str(binary), "--list", "--format=terse"],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
                check=True,
            )
            (artifact_dir / f"{crate}-tests.txt").write_text(listed.stdout, encoding="utf-8")
            return [
                line[:-6] for line in listed.stdout.splitlines() if line.endswith(": test")
            ]

        test_names = {
            crate: list_tests(crate, binary) for crate, binary in preserved.items()
        }

        def exact_name(crate, short):
            matches = [
                name
                for name in test_names[crate]
                if name == short or name.endswith("::" + short)
            ]
            assert len(matches) == 1, (crate, short, matches)
            return matches[0]

        exact = {
            "baseline": (
                "codex_core",
                exact_name("codex_core", "devhub_production_admission_path"),
            ),
            "handler": (
                "codex_core",
                exact_name("codex_core", "devhub_production_admission_path_adversarial"),
            ),
            "catalog": (
                "codex_mcp",
                exact_name("codex_mcp", "devhub_production_admission_path_catalog"),
            ),
        }
        receipt["exact_test_names"] = {key: value[1] for key, value in exact.items()}
        receipt["test_runs"] = []

        def receipt_state(path):
            if not path.exists():
                return {
                    "present": False,
                    "byte_length": None,
                    "sha256": None,
                    "record_count": None,
                }
            raw = path.read_bytes()
            count = 0
            parseable = True
            for line in raw.splitlines():
                try:
                    json.loads(line)
                    count += 1
                except json.JSONDecodeError:
                    parseable = False
                    break
            return {
                "present": True,
                "byte_length": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "record_count": count if parseable else None,
            }

        preserve = (
            "DEVHUB_SYNTHETIC_MCP,DEVHUB_REAL_SCHEMA,DEVHUB_PROOF_ARTIFACT_DIR,"
            "DEVHUB_PROOF_RECEIPT,RUST_BACKTRACE,RUST_MIN_STACK"
        )

        def run_exact(label, crate, full_name, *, backtrace=False, min_stack=None):
            binary = preserved[crate]
            run_env = dict(environment)
            receipt_path = artifact_dir / f"{label}-receipt.jsonl"
            run_env["DEVHUB_PROOF_RECEIPT"] = str(receipt_path)
            if backtrace:
                run_env["RUST_BACKTRACE"] = "full"
            else:
                run_env.pop("RUST_BACKTRACE", None)
            if min_stack is None:
                run_env.pop("RUST_MIN_STACK", None)
            else:
                run_env["RUST_MIN_STACK"] = str(min_stack)
            command = [
                "sudo",
                f"--preserve-env={preserve}",
                "unshare",
                "--net",
                "--",
                "setpriv",
                f"--reuid={os.getuid()}",
                f"--regid={os.getgid()}",
                "--init-groups",
                str(binary),
                full_name,
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ]
            started = time.monotonic()
            try:
                result = subprocess.run(
                    command,
                    cwd=root,
                    env=run_env,
                    capture_output=True,
                    timeout=120,
                    check=False,
                )
                stdout, stderr, exit_code = result.stdout, result.stderr, result.returncode
                did_timeout = False
            except subprocess.TimeoutExpired as error:
                stdout, stderr, exit_code = error.stdout or b"", error.stderr or b"", None
                did_timeout = True
            duration = time.monotonic() - started
            (artifact_dir / f"{label}.stdout").write_bytes(stdout)
            (artifact_dir / f"{label}.stderr").write_bytes(stderr)
            record = {
                "label": label,
                "crate": crate,
                "test": full_name,
                "exit_code": exit_code,
                "timed_out": did_timeout,
                "duration_seconds": duration,
                "binary_sha256": manifest["binaries"][crate]["sha256"],
                "rust_backtrace": "full" if backtrace else None,
                "rust_min_stack": min_stack,
                "stack_overflow_observed": b"stack overflow" in stderr.lower(),
                "receipt": receipt_state(receipt_path),
            }
            receipt["test_runs"].append(record)
            decoded = stdout.decode(errors="replace")
            for line in decoded.splitlines():
                for prefix, key in [
                    ("DEVHUB_ROUTER_PROOF=", "proof"),
                    ("DEVHUB_ADVERSARIAL_PROOF=", "adversarial_proof"),
                    ("DEVHUB_CATALOG_PROOF=", "catalog_proof"),
                ]:
                    if line.startswith(prefix):
                        receipt[key] = json.loads(line.split("=", 1)[1])
            return record

        baseline_crate, baseline_name = exact["baseline"]
        baseline = run_exact("baseline", baseline_crate, baseline_name)
        receipt["baseline_passed"] = baseline["exit_code"] == 0 and not baseline["timed_out"]

        if receipt["baseline_passed"]:
            handler_crate, handler_name = exact["handler"]
            handler = run_exact("handler-normal", handler_crate, handler_name, backtrace=True)
            receipt["handler_normal"] = handler
            if handler["stack_overflow_observed"]:
                receipt["handler_large_stack"] = run_exact(
                    "handler-large-stack",
                    handler_crate,
                    handler_name,
                    backtrace=True,
                    min_stack=33554432,
                )
            else:
                receipt["handler_large_stack"] = None
            catalog_crate, catalog_name = exact["catalog"]
            receipt["catalog"] = run_exact("catalog", catalog_crate, catalog_name)
        else:
            receipt["handler_normal"] = None
            receipt["handler_large_stack"] = None
            receipt["catalog"] = None

        handler_normal = receipt.get("handler_normal")
        catalog = receipt.get("catalog")
        receipt["handler_dispatch"] = bool(
            handler_normal
            and handler_normal["exit_code"] == 0
            and "adversarial_proof" in receipt
        )
        receipt["catalog_refresh_after_preparation"] = bool(
            catalog and catalog["exit_code"] == 0 and "catalog_proof" in receipt
        )
        receipt["process_proof"] = None
        receipt["actual_pinned_router_code"] = bool(
            receipt["baseline_passed"]
            and receipt["handler_dispatch"]
            and receipt["catalog_refresh_after_preparation"]
        )
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, indent=2)
        stream.write("\n")
    if receipt["actual_pinned_router_code"] is not True:
        raise SystemExit("Build-008 diagnostic incomplete; classification UNKNOWN")


if __name__ == "__main__":
    main()
