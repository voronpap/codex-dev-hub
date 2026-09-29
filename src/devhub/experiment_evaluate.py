"""Reviewer-only isolated test execution. Never import generated code on the host."""

import json
import re
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, BinaryIO

from devhub.baseline import verified_cases
from devhub.benchmark import canonical, digest, read_sealed, write_new
from devhub.experiment import ExperimentProtocol, plan
from devhub.experiment_launch import DOCKER, AttemptResult, mount, safe_artifacts


def capture_evaluator(cid: str) -> tuple[bytes, bytes, bool, bool]:
    """Bound untrusted stdout/stderr in memory; stop the entire container on overflow."""
    process = subprocess.Popen(
        [*DOCKER, "start", "--attach", cid], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    assert process.stdout is not None and process.stderr is not None
    overflow = threading.Event()
    streams: list[bytes] = [b"", b""]

    def read(stream: BinaryIO, index: int) -> None:
        data = bytearray()
        while chunk := stream.read(65536):
            if len(data) + len(chunk) > 1024 * 1024:
                overflow.set()
                break
            data.extend(chunk)
        streams[index] = bytes(data)

    threads = [
        threading.Thread(target=read, args=(stream, index), daemon=True)
        for index, stream in enumerate((process.stdout, process.stderr))
    ]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 60
    timed_out = False
    try:
        while process.poll() is None:
            timed_out = time.monotonic() >= deadline
            if timed_out or overflow.is_set():
                subprocess.run([*DOCKER, "kill", cid], capture_output=True, timeout=15, check=False)
                process.kill()
                break
            time.sleep(0.05)
        process.wait(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        for thread in threads:
            thread.join(timeout=5)
        process.stdout.close()
        process.stderr.close()
    return streams[0], streams[1], timed_out, overflow.is_set()


def frozen_pair(
    attempts: tuple[Path, Path], expected_sessions: tuple[str, str]
) -> tuple[bytes, bytes]:
    """Both launch receipts and exact output hashes must verify before evaluator use."""
    if len(set(expected_sessions)) != 2 or attempts[0].resolve() == attempts[1].resolve():
        raise ValueError("Independent A/B attempts required")
    outputs = []
    plans = set()
    for path, session in zip(attempts, expected_sessions, strict=True):
        receipt = AttemptResult.model_validate_json(read_sealed(path / "result.json"))
        raw = (path / "output.bin").read_bytes()
        if (
            receipt.status != "completed"
            or receipt.provenance.session_id != session
            or receipt.provenance.output_sha256 != digest(raw)
        ):
            raise ValueError("Both arms must be frozen before review")
        outputs.append(raw)
        plans.add(receipt.provenance.plan_sha256)
    if len(plans) != 1:
        raise ValueError("Both arms must belong to the same frozen plan")
    return outputs[0], outputs[1]


def evaluation_command(
    image: str, generated: Path, reference: Path, runner: Path, name: str
) -> list[str]:
    if re.fullmatch(r"sha256:[a-f0-9]{64}", image) is None:
        raise ValueError("Immutable evaluator image required")
    return [
        *DOCKER,
        "create",
        "--name",
        name,
        "--pull=never",
        "--network=none",
        "--read-only",
        "--user=1000:1000",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--memory=256m",
        "--cpus=1",
        "--pids-limit=32",
        "--init",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=32m,mode=1777",
        "--env",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        *mount(generated, "/case/test_generated.py"),
        *mount(reference, "/case/solution.py"),
        *mount(runner, "/runner.py"),
        "--entrypoint=python3",
        image,
        "/runner.py",
    ]


def evaluate_bytes(
    generated: bytes,
    buggy: bytes,
    corrected: bytes,
    image: str,
    runner: Path,
    destination: Path,
    *,
    review_barrier_passed: bool = False,
) -> dict[str, Any]:
    """Trusted reviewer API; caller must pass the frozen_pair barrier first.

    Exact raw Python test bytes only. Markdown/prose is not stripped or repaired.
    A synthetic qualification caller may explicitly attest its non-benchmark input.
    This is execution evidence, not acceptance/semantic judging of test adequacy.
    """
    if not review_barrier_passed:
        raise ValueError("Review barrier required")
    destination.mkdir(parents=True, exist_ok=False)
    write_new(destination / "claim.json", canonical({"generated_test_hash": digest(generated)}))
    results = {}
    with tempfile.TemporaryDirectory(prefix="devhub-evaluate-") as temporary:
        root = Path(temporary)
        test = root / "test.py"
        test.write_bytes(generated)
        for label, raw in (("buggy", buggy), ("corrected", corrected)):
            reference = root / f"{label}.py"
            reference.write_bytes(raw)
            name = "devhub-eval-" + uuid.uuid4().hex
            command = evaluation_command(image, test, reference, runner, name)
            cid = subprocess.check_output(command, timeout=30).decode().strip()
            if re.fullmatch(r"[a-f0-9]{64}", cid) is None:
                raise ValueError("Invalid evaluator provenance")
            try:
                stdout, stderr, timeout, overflow = capture_evaluator(cid)
                state = json.loads(
                    subprocess.check_output(
                        [*DOCKER, "inspect", "--format", "{{json .State}}", cid], timeout=10
                    )
                )
                if state["Running"]:
                    raise ValueError("Evaluator still running")
                safe_artifacts((stdout, stderr))
                write_new(destination / f"{label}.stdout", stdout)
                write_new(destination / f"{label}.stderr", stderr)
                results[label] = {
                    "reference_hash": digest(raw),
                    "timeout": timeout,
                    "output_limit_exceeded": overflow,
                    "exit_status": state["ExitCode"],
                    "container_id": cid,
                    "stdout_sha256": digest(stdout),
                    "stderr_sha256": digest(stderr),
                }
            finally:
                subprocess.run(
                    [*DOCKER, "rm", "--force", cid], capture_output=True, timeout=20, check=False
                )
    passed = (
        not any(r["timeout"] or r["output_limit_exceeded"] for r in results.values())
        and results["buggy"]["exit_status"] == 1
        and results["corrected"]["exit_status"] == 0
    )
    evidence = {
        "schema_version": 1,
        "generated_test_hash": digest(generated),
        "runner_sha256": digest(runner.read_bytes()),
        "image_id": image,
        "buggy_result": results["buggy"],
        "corrected_result": results["corrected"],
        "tests_pass": passed,
        "acceptance_pass": None,
    }
    raw = canonical(evidence)
    safe_artifacts((raw,))
    write_new(destination / "result.json", raw)
    return evidence


def evaluate_pair_test(
    repo: Path,
    frozen_plan: dict[str, Any],
    attempts_root: Path,
    fixture_id: str,
    arm: str,
    image: str,
    runner: Path,
    destination: Path,
) -> dict[str, Any]:
    """Only real reviewer entry point: verify pair/plan before opening reviewer material."""
    if fixture_id not in {"tests-01", "tests-02"} or arm not in {"A", "B"}:
        raise ValueError("Only reviewed test-draft pairs")
    protocol = ExperimentProtocol.model_validate_json(json.dumps(frozen_plan["protocol"]))
    if plan(repo, protocol, frozen_plan["run_id"]) != frozen_plan:
        raise ValueError("Reviewer plan changed")
    sessions = {
        s["arm"]: s["session_id"] for s in frozen_plan["sessions"] if s["fixture_id"] == fixture_id
    }
    expected = (sessions["A"], sessions["B"])
    outputs = frozen_pair((attempts_root / expected[0], attempts_root / expected[1]), expected)
    # The execution gate does not replace the frozen oracle's required-case/fact review.
    case = next(c for c in verified_cases(repo / "benchmarks") if c["id"] == fixture_id)
    fixture = json.loads((repo / "benchmarks" / case["fixture"]).read_bytes())
    oracle = json.loads((repo / "benchmarks" / case["oracle"]).read_bytes())
    if "execution_gate" not in oracle:
        raise ValueError("Oracle does not authorize this evaluator")
    corrected = (
        b"from datetime import date, timedelta\n"
        b"def next_day(value): return (date.fromisoformat(value)+timedelta(days=1)).isoformat()\n"
        if fixture_id == "tests-01"
        else b"from threading import Lock\nclass Quota:\n"
        b"    def __init__(self): self.remaining=1; self.lock=Lock()\n"
        b"    def reserve(self,gap):\n        gap()\n        with self.lock:\n"
        b"            if self.remaining<=0: return False\n"
        b"            self.remaining-=1\n            return True\n"
    )
    return evaluate_bytes(
        outputs[0 if arm == "A" else 1],
        fixture["input"].encode(),
        corrected,
        image,
        runner,
        destination,
        review_barrier_passed=True,
    )
