"""Offline paired benchmark storage. No Codex, provider or generated-code execution.

The CLI prepares/verifies packets. Synthetic capture exercises the storage contract
in tests only; it is never an actual benchmark measurement.
"""

import argparse
import hashlib
import json
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, JsonValue, model_validator

from devhub.baseline import SEED_MANIFEST_SHA256, verified_cases
from devhub.models import Contract, Identifier

Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Count = Annotated[int, Field(ge=0)]
Arm = Literal["A", "B"]
TIMING_BOUNDARY = (
    "Immediately before executor invocation through final output capture, including "
    "startup, context preparation, tools, inference and output validation; excludes "
    "packet preparation and post-freeze reviewer evaluation. Synthetic captures "
    "measure only the supplied offline stub, never Codex/provider latency."
)
CORRECTION_RULES = {
    "none": "All required criteria verified; no edits required.",
    "minor": "All required criteria verified; only presentation edits required.",
    "major": "At least one required criterion fails; substantive repair required.",
    "unusable": "No usable task artifact, or a critical oracle requirement fails.",
    "unknown": "Insufficient verification: store null, not an inferred category.",
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: JsonValue) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()


def policy_hash(value: dict[str, JsonValue] | None) -> str | None:
    return None if value is None else digest(canonical(value))


class BenchmarkConfig(Contract):
    mode: Literal["offline_harness"] = "offline_harness"
    shared_instructions: str = Field(min_length=1)
    arm_b_instructions: str = Field(min_length=1)
    arm_a_instructions: str = Field(
        default="Use Codex alone. Dev Hub and delegated provider tools are unavailable.",
        min_length=1,
    )
    model: str | None = None
    model_digest: Digest | None = None
    routing_policy: dict[str, JsonValue] | None = None
    context_builder_policy: dict[str, JsonValue] | None = None
    timing_boundary: str = TIMING_BOUNDARY

    @model_validator(mode="after")
    def fixed_timing(self) -> "BenchmarkConfig":
        if self.timing_boundary != TIMING_BOUNDARY:
            raise ValueError("Timing boundary is fixed by harness version")
        return self

    # No live executor or provider configuration/credentials belong here.


class Quality(Contract):
    acceptance_pass: bool | None = None
    tests_pass: bool | None = None
    citation_pass: bool | None = None
    required_items_hit: tuple[str, ...] | None = None
    required_items_missing: tuple[str, ...] | None = None
    incorrect_claims: tuple[str, ...] | None = None
    unsupported_claims: tuple[str, ...] | None = None
    human_correction: Literal["none", "minor", "major", "unusable"] | None = None


class Metrics(Contract):
    codex_input_tokens: Count | None = None
    codex_output_tokens: Count | None = None
    codex_context_proxy: Count | None = None
    codex_context_proxy_estimator: str | None = None
    devhub_context_proxy: Count | None = None
    devhub_context_proxy_estimator: str | None = None
    delegated_input_tokens: Count | None = None
    delegated_output_tokens: Count | None = None
    provider_api_cost_microusd: Count | None = None
    local_inference_ms: Count | None = None
    codex_retries: Count | None = None
    devhub_retries: Count | None = None
    provider_sends: Count | None = None
    fallbacks: Count | None = None


class Record(Contract):
    run_id: Identifier
    fixture_id: Identifier
    fixture_sha256: Digest
    oracle_sha256: Digest
    arm: Arm
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    config_sha256: Digest
    status: Literal["not_run", "synthetic"] = "not_run"
    reason: str = Field(min_length=1)
    measurement_source: Literal["unavailable", "offline_stub"] = "unavailable"
    started_at: datetime | None = None
    ended_at: datetime | None = None
    duration_ns: Count | None = None
    output_sha256: Digest | None = None
    provider: None = None
    model: None = None
    metrics: Metrics = Metrics()
    quality: Quality = Quality()
    semantic_acceptance: None = None
    quality_benchmark: None = None
    delegation_value: None = None
    savings: None = None

    @model_validator(mode="after")
    def honest_offline_record(self) -> "Record":
        if self.metrics != Metrics() or self.quality != Quality():
            raise ValueError("Offline captures cannot claim actual metrics or reviewed quality")
        if self.status == "not_run":
            if (
                any(
                    x is not None
                    for x in (self.started_at, self.ended_at, self.duration_ns, self.output_sha256)
                )
                or self.measurement_source != "unavailable"
            ):
                raise ValueError("Unexecuted record must have unknown measurements")
        else:
            if (
                self.started_at is None
                or self.ended_at is None
                or self.duration_ns is None
                or self.output_sha256 is None
                or self.measurement_source != "offline_stub"
            ):
                raise ValueError("Synthetic capture requires output and timing")
            for stamp in (self.started_at, self.ended_at):
                offset = stamp.utcoffset()
                if offset is None or offset.total_seconds() != 0:
                    raise ValueError("Timestamps must be UTC")
            if self.ended_at < self.started_at:
                raise ValueError("End precedes start")
        return self


class RunCase(Contract):
    fixture_id: Identifier
    task_class: str
    fixture_sha256: Digest
    oracle_sha256: Digest


class Manifest(Contract):
    run_id: Identifier
    implementation_commit: Annotated[str, Field(pattern=r"^[a-f0-9]{40}$")]
    baseline_manifest_sha256: Digest
    config: BenchmarkConfig
    config_sha256: Digest
    routing_policy_sha256: Digest | None
    context_builder_policy_sha256: Digest | None
    cases: tuple[RunCase, ...]
    artifacts: dict[str, Digest]
    correction_rules: dict[str, str]
    comparison_rule: Literal["inconclusive_until_reviewed_protocol"] = (
        "inconclusive_until_reviewed_protocol"
    )
    real_execution_enabled: Literal[False] = False


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args]).decode().strip()


def clean_commit(repo: Path) -> str:
    if git(repo, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("Dirty working tree: commit changes before preparation")
    commit = git(repo, "rev-parse", "HEAD")
    # Bind the code actually loaded, not merely an unrelated clean checkout.
    for name in ("benchmark.py", "baseline.py", "models.py"):
        committed = subprocess.check_output(
            ["git", "-C", str(repo), "show", f"{commit}:src/devhub/{name}"]
        )
        loaded = Path(__file__).with_name(name).read_bytes().replace(b"\r\n", b"\n")
        if committed.replace(b"\r\n", b"\n") != loaded:
            raise ValueError("Loaded harness does not match implementation commit")
    return commit


def write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)


def write_sealed(path: Path, raw: bytes) -> None:
    write_new(path, raw)
    write_new(path.with_suffix(path.suffix + ".sha256"), digest(raw).encode())


def read_sealed(path: Path) -> bytes:
    raw = path.read_bytes()
    if digest(raw) != path.with_suffix(path.suffix + ".sha256").read_text():
        raise ValueError("Artifact integrity failure")
    return raw


def checked_path(root: Path, relative: str) -> Path:
    path = root / relative
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Artifact path escapes run")
    return path


def build_packets(
    repo: Path,
    config: BenchmarkConfig,
    run_id: str,
    commit: str,
) -> tuple[list[RunCase], dict[str, bytes]]:
    cases = verified_cases(repo / "benchmarks")
    config_sha = digest(canonical(config.model_dump(mode="json")))
    records: list[Record] = []
    run_cases: list[RunCase] = []
    packets: dict[str, bytes] = {}
    for case in cases:
        fixture = json.loads((repo / "benchmarks" / case["fixture"]).read_bytes())
        run_case = RunCase(
            fixture_id=case["id"],
            task_class=fixture["task_class"],
            fixture_sha256=case["fixture_sha256"],
            oracle_sha256=case["oracle_sha256"],
        )
        run_cases.append(run_case)
        for arm in ("A", "B"):
            record = Record(
                run_id=run_id,
                fixture_id=case["id"],
                arm=arm,
                fixture_sha256=case["fixture_sha256"],
                oracle_sha256=case["oracle_sha256"],
                implementation_commit=commit,
                config_sha256=config_sha,
                reason="Prepared only; no executor invoked.",
            )
            records.append(record)
            prefix = f"executors/{case['id']}/{arm}"
            # Exactly the same task/input for both arms. No oracle or opposite output.
            packets[f"{prefix}/input.txt"] = fixture["input"].encode()
            packets[f"{prefix}/task.txt"] = fixture["prompt"].encode()
            instructions = config.shared_instructions
            instructions += "\n" + (
                config.arm_a_instructions if arm == "A" else config.arm_b_instructions
            )
            packets[f"{prefix}/instructions.txt"] = instructions.encode()
    # Keep evaluator metadata out of executor directories.
    for record in records:
        packets[f"records/{record.fixture_id}/{record.arm}/prepared.json"] = canonical(
            record.model_dump(mode="json")
        )
    return run_cases, packets


def prepare(repo: Path, config: BenchmarkConfig, destination: Path, run_id: str) -> Manifest:
    commit = clean_commit(repo)
    run_cases, packets = build_packets(repo, config, run_id, commit)
    config_sha = digest(canonical(config.model_dump(mode="json")))
    manifest = Manifest(
        run_id=run_id,
        implementation_commit=commit,
        baseline_manifest_sha256=SEED_MANIFEST_SHA256,
        config=config,
        config_sha256=config_sha,
        routing_policy_sha256=policy_hash(config.routing_policy),
        context_builder_policy_sha256=policy_hash(config.context_builder_policy),
        cases=tuple(run_cases),
        artifacts={k: digest(v) for k, v in packets.items()},
        correction_rules=CORRECTION_RULES,
    )
    if destination.resolve().is_relative_to(repo.resolve()):
        raise ValueError("Run storage must be outside the source/evaluator repository")
    destination.mkdir(parents=True, exist_ok=False)
    for name, raw in packets.items():
        write_new(destination / name, raw)
    write_sealed(destination / "manifest.json", canonical(manifest.model_dump(mode="json")))
    return manifest


def verify(repo: Path, root: Path, config: BenchmarkConfig) -> Manifest:
    if root.is_symlink() or any(p.is_symlink() for p in root.rglob("*")):
        raise ValueError("Symlink artifacts are not isolated")
    manifest = Manifest.model_validate_json(read_sealed(root / "manifest.json"))
    if clean_commit(repo) != manifest.implementation_commit:
        raise ValueError("Implementation changed: new run required")
    if config != manifest.config or digest(canonical(config.model_dump(mode="json"))) != (
        manifest.config_sha256
    ):
        raise ValueError("Configuration changed: new run required")
    if (
        manifest.baseline_manifest_sha256 != SEED_MANIFEST_SHA256
        or manifest.routing_policy_sha256 != policy_hash(config.routing_policy)
        or manifest.context_builder_policy_sha256 != policy_hash(config.context_builder_policy)
        or manifest.correction_rules != CORRECTION_RULES
    ):
        raise ValueError("Manifest binding mismatch")
    run_cases, packets = build_packets(
        repo, config, manifest.run_id, manifest.implementation_commit
    )
    if tuple(run_cases) != manifest.cases:
        raise ValueError("Case binding mismatch")
    if manifest.artifacts != {name: digest(raw) for name, raw in packets.items()}:
        raise ValueError("Derived packet binding mismatch")
    for name, expected in manifest.artifacts.items():
        if digest(checked_path(root, name).read_bytes()) != expected:
            raise ValueError("Artifact integrity failure")
    expected_names = set(manifest.artifacts) | {"manifest.json", "manifest.json.sha256"}
    for case in manifest.cases:
        for arm in ("A", "B"):
            prefix = f"records/{case.fixture_id}/{arm}"
            prepared = Record.model_validate_json((root / prefix / "prepared.json").read_bytes())
            final_path = root / prefix / "final.json"
            if final_path.exists():
                final = Record.model_validate_json(read_sealed(final_path))
                for field in (
                    "run_id",
                    "fixture_id",
                    "fixture_sha256",
                    "oracle_sha256",
                    "arm",
                    "implementation_commit",
                    "config_sha256",
                ):
                    if getattr(final, field) != getattr(prepared, field):
                        raise ValueError("Result binding mismatch")
                expected_names |= {f"{prefix}/final.json", f"{prefix}/final.json.sha256"}
                if final.output_sha256 is not None:
                    output_name = f"{prefix}/output.txt"
                    if digest(checked_path(root, output_name).read_bytes()) != final.output_sha256:
                        raise ValueError("Output integrity failure")
                    expected_names.add(output_name)
    actual_names = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    if expected_names != actual_names:
        raise ValueError("Unexpected/missing artifact (possible executor contamination)")
    return manifest


class SyntheticCapture:
    """Offline test utility, not an executor. Cannot record actual provider metrics."""

    def __init__(self) -> None:
        self.started_at = datetime.now(UTC)
        self.started_ns = time.perf_counter_ns()
        self.ended_at: datetime | None = None
        self.duration_ns: int | None = None
        self.output: bytes | None = None

    def finish(self, output: bytes) -> None:
        if self.output is not None:
            raise ValueError("Capture already finished")
        self.output = output
        self.duration_ns = time.perf_counter_ns() - self.started_ns
        self.ended_at = datetime.now(UTC)


def freeze_synthetic(
    repo: Path,
    root: Path,
    config: BenchmarkConfig,
    fixture_id: str,
    arm: Arm,
    capture: SyntheticCapture,
) -> Record:
    manifest = verify(repo, root, config)
    if fixture_id not in {c.fixture_id for c in manifest.cases} or arm not in ("A", "B"):
        raise ValueError("Unknown fixture/arm")
    if capture.output is None or capture.ended_at is None:
        raise ValueError("Unfinished capture")
    prefix = root / "records" / fixture_id / arm
    prepared = Record.model_validate_json((prefix / "prepared.json").read_bytes())
    final = Record.model_validate(
        {
            **prepared.model_dump(),
            "status": "synthetic",
            "measurement_source": "offline_stub",
            "reason": "Offline storage contract exercise; not a benchmark observation.",
            "started_at": capture.started_at,
            "ended_at": capture.ended_at,
            "duration_ns": capture.duration_ns,
            "output_sha256": digest(capture.output),
        }
    )
    if (prefix / "final.json").exists():
        raise FileExistsError("Arm already finalized")
    write_new(prefix / "output.txt", capture.output)
    write_sealed(prefix / "final.json", canonical(final.model_dump(mode="json")))
    return final


def mark_not_run(
    repo: Path,
    root: Path,
    config: BenchmarkConfig,
    fixture_id: str,
    arm: Arm,
    reason: str,
) -> Record:
    """Append a terminal technical skip without assigning zero usage or elapsed time."""
    manifest = verify(repo, root, config)
    if fixture_id not in {c.fixture_id for c in manifest.cases} or arm not in ("A", "B"):
        raise ValueError("Unknown fixture/arm")
    prefix = root / "records" / fixture_id / arm
    prepared = Record.model_validate_json((prefix / "prepared.json").read_bytes())
    final = Record.model_validate({**prepared.model_dump(), "reason": reason})
    write_sealed(prefix / "final.json", canonical(final.model_dump(mode="json")))
    return final


def reviewer_packet(
    repo: Path,
    root: Path,
    config: BenchmarkConfig,
    fixture_id: str,
) -> dict[str, JsonValue]:
    """Reviewer-only API. Never returns oracle until BOTH outputs are frozen/verified."""
    manifest = verify(repo, root, config)
    if fixture_id not in {c.fixture_id for c in manifest.cases}:
        raise ValueError("Unknown fixture")
    outputs: dict[str, JsonValue] = {}
    for arm in ("A", "B"):
        prefix = root / "records" / fixture_id / arm
        if not (prefix / "final.json").exists():
            raise ValueError("Both arms must be frozen before review")
        record = Record.model_validate_json(read_sealed(prefix / "final.json"))
        if record.output_sha256 is None:
            raise ValueError("Both outputs required for paired review")
        outputs[arm] = (prefix / "output.txt").read_text(encoding="utf-8")
    case = next(c for c in verified_cases(repo / "benchmarks") if c["id"] == fixture_id)
    oracle: JsonValue = json.loads((repo / "benchmarks" / case["oracle"]).read_bytes())
    return {
        "oracle": oracle,
        "outputs": outputs,
        "comparison": "inconclusive",
        "reason": "Synthetic harness exercise, not actual task performance.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "verify"])
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--run-id")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    config = BenchmarkConfig.model_validate_json(args.config.read_bytes())
    if args.action == "prepare":
        if args.run_id is None:
            parser.error("prepare requires --run-id")
        manifest = prepare(repo, config, args.run, args.run_id)
    else:
        manifest = verify(repo, args.run, config)
    print(f"Verified {len(manifest.cases)} frozen pairs; real execution disabled.")


if __name__ == "__main__":
    main()
