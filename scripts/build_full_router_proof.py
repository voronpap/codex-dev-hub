"""Build actual pinned core unit test in a fresh source tree; never starts a model."""

import argparse
import hashlib
import io
import json
import os
import subprocess
import tarfile
import urllib.request
from pathlib import Path

COMMIT = "4607249e430dac1c961df4dc615beae88e33cec8"
ARCHIVE = "d9478b4d5bb98d4f6eaa6f57dc51b759f0fc70ebd29614f6b1edf7979564ebd2"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
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
    target = root / "core/src/tools/spec_plan_tests.rs"
    original = target.read_bytes()
    test = (repo / "scripts/full_router_test.rs").read_bytes()
    target.write_bytes(original + b"\n" + test)
    metadata = (repo / "docs/evidence/stage3g-full-router/metadata.json").read_bytes()
    target.with_name("devhub_metadata.json").write_bytes(metadata)
    environment = dict(
        os.environ,
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
        "devhub_review_full_router",
        "--no-run",
        "--message-format=json",
    ]
    build = subprocess.run(
        command,
        cwd=root,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=None,
        timeout=2400,
        check=False,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    (args.output.parent / "build.jsonl").write_bytes(build.stdout)
    receipt = {
        "source_commit": COMMIT,
        "archive_sha256": ARCHIVE,
        "test_sha256": hashlib.sha256(test).hexdigest(),
        "production_modified": False,
        "build_exit_code": build.returncode,
        "actual_pinned_router_code": None,
        "method_slice_only": False,
        "inference_requests": 0,
        "real_codex_executions": 0,
        "provider_sends": 0,
    }
    if build.returncode == 0:
        events = [json.loads(line) for line in build.stdout.splitlines()]
        binaries = [
            e["executable"]
            for e in events
            if e.get("reason") == "compiler-artifact"
            and e.get("executable")
            and e.get("target", {}).get("name") == "codex_core"
        ]
        assert len(binaries) == 1
        # Root is used only to create an isolated network namespace, then drop to runner UID.
        run = subprocess.run(
            [
                "sudo",
                "unshare",
                "--net",
                "--",
                "setpriv",
                f"--reuid={os.getuid()}",
                f"--regid={os.getgid()}",
                "--init-groups",
                binaries[0],
                "devhub_review_full_router",
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
