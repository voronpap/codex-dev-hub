"""Reviewer-only isolated test execution. Never import generated code on the host."""

import json
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from devhub.baseline import verified_cases
from devhub.benchmark import canonical, digest, read_sealed, write_new
from devhub.experiment import ExperimentProtocol, plan
from devhub.experiment_launch import DOCKER, AttemptResult, cleanup_container, mount, safe_artifacts
from devhub.process_capture import ProcessCapture, capture_process


def capture_evaluator(cid: str) -> ProcessCapture:
    """Use the same bounded stream algorithm as the main executor."""

    def terminate_container() -> None:
        subprocess.run([*DOCKER, "kill", cid], capture_output=True, timeout=15, check=False)

    return capture_process(
        [*DOCKER, "start", "--attach", cid],
        None,
        60,
        terminate_execution=terminate_container,
    )


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
            cleanup_succeeded = False
            try:
                captured = capture_evaluator(cid)
                stdout, stderr = captured.stdout.data, captured.stderr.data
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
                    "timeout": captured.timed_out,
                    "output_limit_exceeded": captured.output_limit_exceeded,
                    "artifact_withheld": captured.secret_detected,
                    "input_error": captured.input_error,
                    "exit_status": state["ExitCode"],
                    "container_id": cid,
                    "stdout": captured.stdout.evidence.model_dump(mode="json"),
                    "stderr": captured.stderr.evidence.model_dump(mode="json"),
                }
            finally:
                cleanup_succeeded = cleanup_container(cid)
            if not cleanup_succeeded:
                raise ValueError("Evaluator container cleanup failed")
    passed = (
        not any(
            r["timeout"]
            or r["output_limit_exceeded"]
            or r["artifact_withheld"]
            or r["input_error"] is not None
            for r in results.values()
        )
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
