import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_build_artifact_metadata", ROOT / "scripts/verify_build_artifact_metadata.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def inputs() -> tuple[dict, dict]:
    lock = json.loads((ROOT / "benchmarks/runtime-lock.json").read_bytes())
    qualified = lock["qualified_codex_build"]
    metadata = {
        "id": qualified["artifact_id"],
        "name": qualified["artifact_name"],
        "expired": False,
        "workflow_run": {"id": qualified["workflow_run_id"]},
        "archive_download_url": MODULE.EXPECTED_ARCHIVE_URL,
    }
    return metadata, lock


def test_live_artifact_metadata_matches_runtime_lock() -> None:
    metadata, lock = inputs()
    verified = MODULE.verify_artifact_metadata(metadata, lock)
    assert verified["artifact_id"] == 11659714382
    assert verified["workflow_run_id"] == 38024891950


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("id", 1),
        ("name", "wrong"),
        ("expired", True),
        ("archive_download_url", "https://example.invalid/artifact.zip"),
    ],
)
def test_live_artifact_metadata_rejects_wrong_identity(field, value) -> None:
    metadata, lock = inputs()
    metadata[field] = value
    with pytest.raises(ValueError, match="differs from reviewed"):
        MODULE.verify_artifact_metadata(metadata, lock)


def test_live_artifact_metadata_rejects_wrong_workflow_run() -> None:
    metadata, lock = inputs()
    metadata["workflow_run"]["id"] = 1
    with pytest.raises(ValueError, match="differs from reviewed"):
        MODULE.verify_artifact_metadata(metadata, lock)
