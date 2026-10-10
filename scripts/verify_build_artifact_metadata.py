"""Verify live GitHub metadata for the retained Build-020 artifact."""

import argparse
import json
from pathlib import Path
from typing import Any, cast

from devhub.benchmark import canonical, write_new
from devhub.qualification import CodexBuildArtifactObservationV1

EXPECTED_ARCHIVE_URL = (
    "https://api.github.com/repos/voronpap/codex-dev-hub/actions/artifacts/11659714382/zip"
)


def verify_artifact_metadata(metadata: dict[str, Any], lock: dict[str, Any]) -> dict[str, Any]:
    qualified = lock.get("qualified_codex_build")
    if not isinstance(qualified, dict):
        raise ValueError("Qualified Codex build identity is missing from runtime lock")
    qualified = cast(dict[str, Any], qualified)
    expected = CodexBuildArtifactObservationV1.model_validate(
        {
            "workflow_run_id": qualified.get("workflow_run_id"),
            "artifact_id": qualified.get("artifact_id"),
            "artifact_name": qualified.get("artifact_name"),
            "artifact_zip_sha256": qualified.get("artifact_zip_sha256"),
            "build_evidence_sha256": qualified.get("build_evidence_sha256"),
        }
    )
    workflow_run = metadata.get("workflow_run")
    if not isinstance(workflow_run, dict):
        raise ValueError("Live artifact metadata has no workflow run identity")
    if (
        metadata.get("id") != expected.artifact_id
        or metadata.get("name") != expected.artifact_name
        or workflow_run.get("id") != expected.workflow_run_id
        or metadata.get("expired") is not False
        or metadata.get("archive_download_url") != EXPECTED_ARCHIVE_URL
    ):
        raise ValueError("Live artifact metadata differs from reviewed Build-020 identity")
    return {
        "schema_version": 1,
        "artifact_id": expected.artifact_id,
        "artifact_name": expected.artifact_name,
        "workflow_run_id": expected.workflow_run_id,
        "expired": False,
        "archive_download_url": EXPECTED_ARCHIVE_URL,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    metadata = json.loads(args.metadata.read_bytes())
    lock = json.loads(args.lock.read_bytes())
    if not isinstance(metadata, dict) or not isinstance(lock, dict):
        raise ValueError("Artifact metadata and runtime lock must be JSON objects")
    raw = canonical(verify_artifact_metadata(metadata, lock))
    write_new(args.output, raw)
    print(raw.decode())


if __name__ == "__main__":
    main()
