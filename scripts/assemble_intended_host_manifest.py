"""Assemble and verify the complete same-environment Stage 3G manifest."""

import argparse
import json
import os
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

RECEIPTS = {
    "isolation": "isolation.json",
    "effects_boundary": "effects.json",
    "auth_egress": "auth-egress.json",
    "ollama_metadata": "ollama-metadata.json",
    "ledger_identity": "ledger-identity.json",
    "codex_executable": "codex-executable.json",
    "host_process_visibility": "host-process-visibility.json",
    "evaluator": "evaluator-proof/qualification-receipt.json",
    "python_runtime": "python-runtime.json",
    "runtime_config_probe": "runtime-checks.json",
}


def _publish_verified_manifest(output: Path, manifest: QualificationManifestV2) -> None:
    """Install a manifest only after its complete temporary tree verifies."""

    temporary = output.with_name(output.name + ".tmp")
    if output.exists() or output.is_symlink():
        raise FileExistsError("Exclusive output required")
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError("Stale temporary manifest output exists")
    try:
        write_new(temporary, canonical_manifest(manifest))
        verify_manifest_tree(temporary, manifest.qualification_manifest_id)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Exclusive output required")
    root = args.root.resolve(strict=True)
    context_path = args.context.resolve(strict=True)
    if not context_path.is_relative_to(root):
        parser.error("Context must be contained by the manifest root")
    context = load_context(context_path)
    context_raw = context_path.read_bytes()
    references: dict[str, ReceiptReferenceV1] = {}
    gate_values: dict[str, bool] = {
        "context_integrity": True,
        "artifact_integrity": True,
        "same_environment": True,
    }
    for kind, relative in RECEIPTS.items():
        path = root.joinpath(*Path(relative).parts)
        if path.is_symlink() or not path.is_file():
            parser.error(f"Required intended-host receipt is missing: {kind}")
        raw = path.read_bytes()
        data = json.loads(raw)
        references[kind] = ReceiptReferenceV1(
            receipt_kind=kind, relative_path=relative, sha256=digest(raw)
        )
        gate_values[kind] = data.get("qualification_passed") is True
    expected = context.payload
    payload = QualificationManifestPayloadV2.create(
        qualification_context_id=context.qualification_context_id,
        environment_instance_id=expected.environment_instance_id,
        context=ArtifactReferenceV1(
            relative_path=context_path.relative_to(root).as_posix(),
            sha256=digest(context_raw),
        ),
        receipts=QualificationReceiptSetV2.model_validate(references),
        observed_artifacts=ObservedArtifactHashesV2(
            qualification_context_sha256=digest(context_raw),
            devhub_wheel_sha256=expected.implementation.python_runtime.wheel_sha256,
            dependency_lock_sha256=expected.implementation.python_runtime.dependency_lock_sha256,
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
    if not payload.execution_ready:
        parser.error("Complete intended-host evidence did not derive execution_ready=true")
    manifest = QualificationManifestV2.create(payload)
    try:
        _publish_verified_manifest(args.output, manifest)
    except FileExistsError as error:
        parser.error(str(error))
    print(
        json.dumps(
            {
                "qualification_manifest_id": manifest.qualification_manifest_id,
                "execution_ready": True,
            }
        )
    )


if __name__ == "__main__":
    main()
