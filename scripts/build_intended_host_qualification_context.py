"""Build one real Stage 3G qualification context from reviewed immutable inputs."""

import argparse
import json
from pathlib import Path
from typing import Annotated, Literal, cast

from pydantic import Field, JsonValue

from devhub.baseline import SEED_MANIFEST_SHA256
from devhub.benchmark import canonical, clean_commit, digest, write_new
from devhub.experiment import ExperimentProtocol
from devhub.experiment import plan as build_plan
from devhub.experiment_tool_gate import policy_hash
from devhub.ledger import MIGRATIONS, LedgerIdentityCoreV1, ledger_identity_sha256
from devhub.models import Contract
from devhub.qualification import (
    ArmExpectedV1,
    ArmsExpectedV1,
    BenchmarkExpectedV1,
    CodexBuildArtifactObservationV1,
    CodexExpectedV1,
    Digest,
    EnvironmentInstanceId,
    EvaluatorExpectedV1,
    GitCommit,
    ImageId,
    ImplementationExpectedV1,
    LedgerExpectedV1,
    OllamaExpectedV1,
    QualificationContextPayloadV1,
    QualificationContextV1,
    RuntimeExpectedV1,
    canonical_context,
)
from devhub.runtime_artifact import PythonRuntimeArtifactEvidenceV1, python_runtime_expected


class EnvironmentIdentityInputV1(Contract):
    schema_version: Literal[1]
    environment_instance_id: EnvironmentInstanceId


class RuntimeImageBuildEvidenceV1(Contract):
    schema_version: Literal[1]
    kind: Literal["runtime_image_build"]
    image_id: ImageId
    runtime_lock_sha256: Digest
    dockerfile_sha256: Digest
    codex_source_archive_sha256: Digest
    codex_binary_sha256: Digest
    codex_version: Annotated[str, Field(min_length=1, max_length=128)]
    codex_source_commit: GitCommit
    candidate_b_base_patch_sha256: Digest
    host_integration_patch_sha256: Digest
    combined_patchset_sha256: Digest
    source_artifact: CodexBuildArtifactObservationV1
    base_image: Annotated[str, Field(min_length=1, max_length=256)]
    real_codex_executions: Literal[0]
    provider_sends: Literal[0]


class EvaluatorImageBuildEvidenceV1(Contract):
    kind: Literal["evaluator_image_build"]
    image_id: ImageId
    wheel_hashes: dict[str, Digest]
    recipe_sha256: Digest
    base_image: Annotated[str, Field(min_length=1, max_length=256)]
    real_codex_executions: Literal[0]
    provider_sends: Literal[0]


def _regular(path: Path, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symlink file")
    return path.read_bytes()


def _require_implementation_head(repo: Path, artifact: PythonRuntimeArtifactEvidenceV1) -> str:
    implementation_commit = clean_commit(repo)
    if implementation_commit != artifact.implementation_commit:
        raise ValueError("Runtime artifact is not built from the exact clean repository HEAD")
    return implementation_commit


def _require_exact_plan(
    repo: Path, protocol: ExperimentProtocol, reviewed_plan: dict[str, object]
) -> None:
    expected = build_plan(repo, protocol, str(reviewed_plan.get("run_id", "")))
    if reviewed_plan != expected:
        raise ValueError("Reviewed plan does not match implementation/protocol authority")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--runtime-artifact", type=Path, required=True)
    parser.add_argument("--runtime-build", type=Path, required=True)
    parser.add_argument("--evaluator-build", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--ledger-identity", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Exclusive output required")
    repo = Path(__file__).resolve().parents[1]
    try:
        environment = EnvironmentIdentityInputV1.model_validate_json(
            _regular(args.environment, "Environment identity")
        )
        artifact = PythonRuntimeArtifactEvidenceV1.model_validate_json(
            _regular(args.runtime_artifact, "Python runtime artifact")
        )
        runtime_raw = _regular(args.runtime_build, "Runtime image evidence")
        runtime = RuntimeImageBuildEvidenceV1.model_validate_json(runtime_raw)
        evaluator_raw = _regular(args.evaluator_build, "Evaluator image evidence")
        evaluator = EvaluatorImageBuildEvidenceV1.model_validate_json(evaluator_raw)
        protocol = ExperimentProtocol.model_validate_json(_regular(args.protocol, "Protocol"))
        plan_raw = _regular(args.plan, "Reviewed plan")
        reviewed_plan = json.loads(plan_raw)
        if not isinstance(reviewed_plan, dict):
            raise ValueError("Reviewed plan must be a JSON object")
        ledger = LedgerIdentityCoreV1.model_validate_json(
            _regular(args.ledger_identity, "Ledger identity")
        )
        _require_implementation_head(repo, artifact)
        _require_exact_plan(repo, protocol, reviewed_plan)
    except (ValueError, OSError, json.JSONDecodeError) as error:
        parser.error(str(error))
    plan_value = cast(JsonValue, reviewed_plan)
    plan_sha = digest(canonical(plan_value))
    sessions_sha = digest(canonical(cast(JsonValue, reviewed_plan["sessions"])))
    payload = QualificationContextPayloadV1(
        environment_instance_id=environment.environment_instance_id,
        implementation=ImplementationExpectedV1(
            devhub_commit=artifact.implementation_commit,
            python_runtime=python_runtime_expected(artifact),
        ),
        codex=CodexExpectedV1(
            source_commit=runtime.codex_source_commit,
            source_archive_sha256=runtime.codex_source_archive_sha256,
            executable_version=runtime.codex_version,
            executable_sha256=runtime.codex_binary_sha256,
            candidate_b_base_patch_sha256=runtime.candidate_b_base_patch_sha256,
            host_integration_patch_sha256=runtime.host_integration_patch_sha256,
            combined_patchset_sha256=runtime.combined_patchset_sha256,
        ),
        benchmark=BenchmarkExpectedV1(
            protocol_sha256=protocol.hashes()["protocol"],
            config_sha256=protocol.hashes()["codex_config"],
            plan_sha256=plan_sha,
            session_bindings_sha256=sessions_sha,
            fixture_oracle_manifest_sha256=SEED_MANIFEST_SHA256,
        ),
        runtime_expected=RuntimeExpectedV1(
            image_id=runtime.image_id,
            image_metadata_sha256=digest(runtime_raw),
            bootstrap_sha256=digest((Path(__file__).with_name("benchmark_guest.py")).read_bytes()),
            approved_host_manifest_sha256=digest(
                (
                    Path(__file__).parents[1] / "benchmarks/stage3g-host-manifest-v2.json"
                ).read_bytes()
            ),
        ),
        ledger_expected=LedgerExpectedV1(
            identity=ledger,
            identity_sha256=ledger_identity_sha256(ledger),
            domain_schema_version=len(MIGRATIONS),
        ),
        evaluator_expected=EvaluatorExpectedV1(
            image_id=evaluator.image_id,
            artifact_sha256=digest(evaluator_raw),
            runner_sha256=digest((Path(__file__).with_name("benchmark_evaluator.py")).read_bytes()),
        ),
        ollama_expected=OllamaExpectedV1(),
        arms_expected=ArmsExpectedV1(
            arm_a=ArmExpectedV1(arm="A", tool_ceiling=(), approved_delegate_policy_sha256=None),
            arm_b=ArmExpectedV1(
                arm="B",
                tool_ceiling=("mcp__devhub_delegate.devhub_delegate",),
                approved_delegate_policy_sha256=policy_hash(),
            ),
        ),
    )
    context = QualificationContextV1.create(payload)
    write_new(args.output, canonical_context(context))
    print(json.dumps({"qualification_context_id": context.qualification_context_id}))


if __name__ == "__main__":
    main()
