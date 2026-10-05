"""Build and verify the final immutable Stage 3G qualification manifest."""

import argparse
import json
import os
from pathlib import Path

from devhub.benchmark import write_new
from devhub.qualification import (
    ArtifactReferenceV1,
    ObservedArtifactHashesV2,
    QualificationGatesV2,
    QualificationManifestPayloadV2,
    QualificationManifestV2,
    QualificationReceiptSetV2,
    canonical_manifest,
    verify_manifest_tree,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Manifest output must be new")
    supplied = json.loads(args.payload.read_bytes())
    if not isinstance(supplied, dict):
        parser.error("Manifest payload must be an object")
    allowed = {
        "schema_version",
        "qualification_context_id",
        "environment_instance_id",
        "context",
        "receipts",
        "observed_artifacts",
        "gates",
        "execution_ready",
    }
    if set(supplied) - allowed:
        parser.error("Unknown manifest payload field")
    if supplied.get("schema_version") != 2:
        parser.error("Manifest payload schema_version must be 2")
    payload = QualificationManifestPayloadV2.create(
        qualification_context_id=supplied["qualification_context_id"],
        environment_instance_id=supplied["environment_instance_id"],
        context=ArtifactReferenceV1.model_validate(supplied["context"]),
        receipts=QualificationReceiptSetV2.model_validate(supplied["receipts"]),
        observed_artifacts=ObservedArtifactHashesV2.model_validate(supplied["observed_artifacts"]),
        gates=QualificationGatesV2.model_validate(supplied["gates"]),
    )
    if "execution_ready" in supplied and supplied["execution_ready"] is not payload.execution_ready:
        parser.error("Supplied execution_ready differs from mechanically derived state")
    manifest = QualificationManifestV2.create(payload)
    temporary = args.output.with_name(args.output.name + ".tmp")
    try:
        write_new(temporary, canonical_manifest(manifest))
        verify_manifest_tree(
            temporary,
            manifest.qualification_manifest_id,
            require_execution_ready=payload.execution_ready,
        )
        os.replace(temporary, args.output)
    finally:
        temporary.unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "qualification_manifest_id": manifest.qualification_manifest_id,
                "execution_ready": payload.execution_ready,
            }
        )
    )


if __name__ == "__main__":
    main()
