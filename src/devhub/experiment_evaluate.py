"""Reviewer-only isolated test execution. Never import generated code on the host."""

import json
import re
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from devhub.benchmark import canonical, digest, read_sealed, write_new
from devhub.experiment_launch import DOCKER, AttemptResult, mount, safe_artifacts


def frozen_pair(
    attempts: tuple[Path, Path], expected_sessions: tuple[str, str]
) -> tuple[bytes, bytes]:
    """Both launch receipts and exact output hashes must verify before evaluator use."""
    if len(set(expected_sessions)) != 2 or attempts[0].resolve() == attempts[1].resolve():
        raise ValueError("Independent A/B attempts required")
    outputs = []
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
            timeout = False
            try:
                try:
                    completed = subprocess.run(
                        [*DOCKER, "start", "--attach", cid],
                        capture_output=True,
                        timeout=60,
                        check=False,
                    )
                    stdout, stderr = completed.stdout, completed.stderr
                except subprocess.TimeoutExpired:
                    timeout = True
                    stdout, stderr = b"", b""
                    subprocess.run(
                        [*DOCKER, "kill", cid], capture_output=True, timeout=15, check=True
                    )
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
        not any(r["timeout"] for r in results.values())
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
