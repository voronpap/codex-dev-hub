"""Assemble a non-ready CI mechanics manifest; never qualifies an intended host."""

import argparse
import json
from pathlib import Path

from devhub.benchmark import digest, write_new
from devhub.qualification import (
    ArtifactReferenceV1,
    ObservedArtifactHashesV2,
    QualificationGatesV2,
    QualificationManifestPayloadV2,
    QualificationManifestV2,
    QualificationReceiptSetV2,
    ReceiptReferenceV1,
    canonical_manifest,
    load_context,
    verify_manifest_tree,
)

CI_RECEIPTS = {
    "isolation": "isolation.json",
    "effects_boundary": "effects.json",
    "codex_executable": "codex-executable.json",
    "evaluator": "evaluator-proof/qualification-receipt.json",
    "python_runtime": "python-runtime.json",
    "host_process_visibility": "host-process-visibility.json",
    "runtime_config_probe": "runtime-checks.json",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    context = load_context(args.context)
    context_raw = args.context.read_bytes()
    references = {}
    gate_values: dict[str, bool] = {
        "context_integrity": True,
        "artifact_integrity": True,
        "same_environment": True,
    }
    for kind, relative in CI_RECEIPTS.items():
        path = root / relative
        if not path.is_file():
            continue
        raw = path.read_bytes()
        receipt = json.loads(raw)
        references[kind] = ReceiptReferenceV1(
            receipt_kind=kind, relative_path=relative, sha256=digest(raw)
        )
        gate_values[kind] = receipt.get("qualification_passed") is True
    receipts = QualificationReceiptSetV2.model_validate(references)
    expected = context.payload
    payload = QualificationManifestPayloadV2.create(
        qualification_context_id=context.qualification_context_id,
        environment_instance_id=expected.environment_instance_id,
        context=ArtifactReferenceV1(
            relative_path=args.context.resolve(strict=True).relative_to(root).as_posix(),
            sha256=digest(context_raw),
        ),
        receipts=receipts,
        observed_artifacts=ObservedArtifactHashesV2(
            qualification_context_sha256=digest(context_raw),
            devhub_wheel_sha256=expected.implementation.python_runtime.wheel_sha256,
            dependency_lock_sha256=(expected.implementation.python_runtime.dependency_lock_sha256),
            python_executable_sha256=(
                expected.implementation.python_runtime.python_executable_sha256
            ),
            python_runtime_environment_id=(
                expected.implementation.python_runtime.runtime_environment_id
            ),
            codex_executable_sha256=expected.codex.executable_sha256,
            runtime_image_metadata_sha256=expected.runtime_expected.image_metadata_sha256,
            evaluator_artifact_sha256=expected.evaluator_expected.artifact_sha256,
            ledger_identity_sha256=expected.ledger_expected.identity_sha256,
            ollama_model_digest=expected.ollama_expected.digest,
        ),
        gates=QualificationGatesV2(**gate_values),
    )
    if payload.execution_ready:
        raise ValueError("Synthetic CI mechanics must not qualify the intended host")
    manifest = QualificationManifestV2.create(payload)
    write_new(args.output, canonical_manifest(manifest))
    verify_manifest_tree(
        args.output, manifest.qualification_manifest_id, require_execution_ready=False
    )
    print(
        json.dumps(
            {
                "qualification_manifest_id": manifest.qualification_manifest_id,
                "execution_ready": False,
                "scope": "synthetic_ci_mechanics_only",
            }
        )
    )


if __name__ == "__main__":
    main()
