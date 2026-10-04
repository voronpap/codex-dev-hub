"""Run preserved proof binaries independently; no compilation or model requests."""

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

LARGE_STACK = "16777216"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def receipt_observation(path):
    result = {
        "path": str(path),
        "exists": path.exists(),
        "bytes": None,
        "sha256": None,
        "record_count": None,
        "records": None,
    }
    if path.exists():
        raw = path.read_bytes()
        result.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        try:
            records = [json.loads(line) for line in raw.splitlines()]
            result.update(record_count=len(records), records=records)
        except (ValueError, UnicodeError):
            pass
    return result


def isolated_command(binary, arguments):
    return [
        "sudo",
        "--preserve-env=DEVHUB_SYNTHETIC_MCP,DEVHUB_REAL_SCHEMA,DEVHUB_RECEIPT_PATH,RUST_BACKTRACE,RUST_MIN_STACK",
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


def run_one(binary, binary_sha, exact_name, output, label, assets, stack=None):
    assert sha(binary) == binary_sha
    directory = output / label
    directory.mkdir(exist_ok=False)
    receipt = directory / "receipt.jsonl"
    receipt.touch(exist_ok=False)
    settings = {
        "DEVHUB_SYNTHETIC_MCP": str(assets / "synthetic_approved_mcp.py"),
        "DEVHUB_REAL_SCHEMA": str(assets / "devhub_real_schema.json"),
        "DEVHUB_RECEIPT_PATH": str(receipt),
        "RUST_BACKTRACE": "full",
    }
    if stack is not None:
        settings["RUST_MIN_STACK"] = stack
    environment = {
        key: os.environ[key] for key in ("PATH", "HOME", "LANG", "TMPDIR") if key in os.environ
    }
    environment.update(settings)
    command = isolated_command(binary, [exact_name, "--exact", "--nocapture", "--test-threads=1"])
    result = {
        "label": label,
        "binary": str(binary),
        "binary_sha256": binary_sha,
        "exact_filter": exact_name,
        "command": command,
        "environment": settings,
        "normal_stack": stack is None,
        "timeout_seconds": 120,
        "receipt_initialized": receipt_observation(receipt),
    }
    (directory / "planned.json").write_text(json.dumps(result, indent=2) + "\n")
    started = time.monotonic()
    with (directory / "stdout").open("xb") as stdout, (directory / "stderr").open("xb") as stderr:
        process = subprocess.Popen(
            command,
            cwd=assets,
            env=environment,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        timed_out = False
        try:
            exit_code = process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            timed_out = True
            # Preserve output and prevent a timed-out synthetic child outliving its run.
            subprocess.run(
                ["sudo", "kill", "-KILL", "--", str(-process.pid)], check=False, capture_output=True
            )
            process.wait(timeout=10)
            exit_code = None
    out = (directory / "stdout").read_text(errors="replace")
    err = (directory / "stderr").read_text(errors="replace")
    checkpoints = []
    proofs = {}
    for line in out.splitlines():
        for prefix in ("DEVHUB_HANDLER_STAGE=", "DEVHUB_ADVERSARIAL_STAGE="):
            if prefix in line:
                checkpoints.append(line.split(prefix, 1)[1])
        for prefix in (
            "DEVHUB_ROUTER_PROOF=",
            "DEVHUB_ADVERSARIAL_PROOF=",
            "DEVHUB_CATALOG_PROOF=",
        ):
            if prefix in line:
                proofs[prefix[:-1]] = json.loads(line.split(prefix, 1)[1])
    result.update(
        exit_code=exit_code,
        signal=(-exit_code if exit_code is not None and exit_code < 0 else None),
        timed_out=timed_out,
        duration_seconds=time.monotonic() - started,
        checkpoints=checkpoints,
        last_checkpoint=checkpoints[-1] if checkpoints else None,
        stack_overflow="stack overflow" in err or "overflowed its stack" in err,
        backtrace_emitted="stack backtrace:" in err,
        receipt=receipt_observation(receipt),
        proofs=proofs,
        stdout_sha256=sha(directory / "stdout"),
        stderr_sha256=sha(directory / "stderr"),
    )
    assert sha(binary) == binary_sha
    (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def run_suite(binaries, output, assets):
    output.mkdir(exist_ok=False)
    names = {}
    for crate, info in binaries.items():
        binary = Path(info["path"])
        assert sha(binary) == info["sha256"]
        command = isolated_command(binary, ["--list", "--format", "terse"])
        listed = subprocess.run(command, capture_output=True, timeout=60, check=True)
        (output / (crate + "-list.stdout")).write_bytes(listed.stdout)
        (output / (crate + "-list.stderr")).write_bytes(listed.stderr)
        for line in listed.stdout.decode().splitlines():
            if line.endswith(": test"):
                full = line[:-6]
                short = full.rsplit("::", 1)[-1]
                if short in {
                    "devhub_production_admission_path",
                    "devhub_production_admission_path_adversarial",
                    "devhub_production_admission_path_catalog",
                }:
                    assert short not in names
                    names[short] = (crate, full)
    assert len(names) == 3
    (output / "test-names.json").write_text(json.dumps(names, indent=2) + "\n")
    runs = []

    def run(short, label, stack=None):
        crate, full = names[short]
        info = binaries[crate]
        result = run_one(Path(info["path"]), info["sha256"], full, output, label, assets, stack)
        runs.append(result)
        (output / "runs.json").write_text(json.dumps(runs, indent=2) + "\n")
        return result

    baseline = run("devhub_production_admission_path", "baseline")
    if baseline["exit_code"] != 0:
        return runs
    normal = run("devhub_production_admission_path_adversarial", "handler-normal")
    if normal["stack_overflow"]:
        run("devhub_production_admission_path_adversarial", "handler-large-stack", LARGE_STACK)
    run("devhub_production_admission_path_catalog", "catalog")
    return runs
