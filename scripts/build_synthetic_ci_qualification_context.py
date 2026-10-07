"""Build a deliberately non-final CI context for qualification-mechanics checks."""

import argparse
import json
from pathlib import Path

from devhub.baseline import SEED_MANIFEST_SHA256
from devhub.benchmark import digest, write_new
from devhub.experiment import ExperimentProtocol
from devhub.experiment_tool_gate import policy_hash
from devhub.ledger import MIGRATIONS, LedgerIdentityCoreV1, ledger_identity_sha256
from devhub.qualification import (
    ArmExpectedV1,
    ArmsExpectedV1,
    BenchmarkExpectedV1,
    CodexExpectedV1,
    EvaluatorExpectedV1,
    ImplementationExpectedV1,
    LedgerExpectedV1,
    OllamaExpectedV1,
    QualificationContextPayloadV1,
    QualificationContextV1,
    RuntimeExpectedV1,
    canonical_context,
)
from devhub.runtime_artifact import PythonRuntimeArtifactEvidenceV1, python_runtime_expected


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--runtime-artifact", type=Path, required=True)
    parser.add_argument("--runtime-build", type=Path, required=True)
    parser.add_argument("--evaluator-build", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    environment = json.loads(args.environment.read_bytes())["environment_instance_id"]
    artifact = PythonRuntimeArtifactEvidenceV1.model_validate_json(
        args.runtime_artifact.read_bytes()
    )
    runtime_raw = args.runtime_build.read_bytes()
    runtime = json.loads(runtime_raw)
    evaluator_raw = args.evaluator_build.read_bytes()
    evaluator = json.loads(evaluator_raw)
    protocol = ExperimentProtocol.model_validate_json(args.protocol.read_bytes())
    synthetic = digest(b"synthetic-ci-mechanics-only-not-build-009")
    ledger = LedgerIdentityCoreV1(
        instance_id=environment,
        authority_scope_kind="qualification",
        authority_scope_id="synthetic-ci-mechanics",
    )
    payload = QualificationContextPayloadV1(
        environment_instance_id=environment,
        implementation=ImplementationExpectedV1(
            devhub_commit=artifact.implementation_commit,
            python_runtime=python_runtime_expected(artifact),
        ),
        codex=CodexExpectedV1(
            source_commit="0" * 40,
            source_archive_sha256=runtime["codex_archive_sha256"],
            executable_version=runtime["codex_version"],
            executable_sha256=runtime["codex_binary_sha256"],
            candidate_b_base_patch_sha256=synthetic,
            host_integration_patch_sha256=synthetic,
            combined_patchset_sha256=synthetic,
        ),
        benchmark=BenchmarkExpectedV1(
            protocol_sha256=protocol.hashes()["protocol"],
            config_sha256=protocol.hashes()["codex_config"],
            plan_sha256=synthetic,
            session_bindings_sha256=synthetic,
            fixture_oracle_manifest_sha256=SEED_MANIFEST_SHA256,
        ),
        runtime_expected=RuntimeExpectedV1(
            image_id=runtime["image_id"],
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
            image_id=evaluator["image_id"],
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
    print(
        json.dumps(
            {
                "qualification_context_id": context.qualification_context_id,
                "execution_ready": False,
                "scope": "synthetic_ci_mechanics_only",
            }
        )
    )


if __name__ == "__main__":
    main()
