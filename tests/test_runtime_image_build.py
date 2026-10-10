import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_benchmark_runtime", ROOT / "scripts/build_benchmark_runtime.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def qualified_inputs(root: Path):
    binary = b"retained build-020 binary"
    binary_path = root / "codex"
    binary_path.write_bytes(binary)
    binary_sha256 = hashlib.sha256(binary).hexdigest()
    qualified = {
        "workflow_run_id": 38024891950,
        "artifact_id": 11659714382,
        "artifact_name": "stage3g-build020-production-host-proof",
        "artifact_zip_sha256": "c03fbe7596a95c2b667348db879c205c83d5cd74b3f9e1d2b4d2d5ab79546979",
        "binary_relative_path": "binary/codex",
        "binary_sha256": binary_sha256,
        "source_commit": "4607249e430dac1c961df4dc615beae88e33cec8",
        "source_archive_sha256": "d9478b4d5bb98d4f6eaa6f57dc51b759f0fc70ebd29614f6b1edf7979564ebd2",
        "candidate_b_base_patch_sha256": (
            "d2e27068ca8020f014c7cd3bea2cc73181b1b892d8e6869814680d2076eb3e36"
        ),
        "host_integration_patch_sha256": (
            "f22369f10ed45d04a740205fca0cb7111ddb56d3b1bdbee603dfcfdfdd7de9ad"
        ),
        "combined_patchset_sha256": (
            "e63b68840ecec005703fc61fa1e26aba988c5a9e44a956efedbfbdea96d10c59"
        ),
    }
    evidence = {
        "build_id": "build-020",
        "compilation": "PASS",
        "process_proof": "PASS",
        "source_commit": qualified["source_commit"],
        "source_archive_sha256": qualified["source_archive_sha256"],
        "candidate_b_base_patch_sha256": qualified["candidate_b_base_patch_sha256"],
        "host_integration_patch_sha256": qualified["host_integration_patch_sha256"],
        "combined_production_patchset_sha256": qualified["combined_patchset_sha256"],
        "executable": {"sha256": binary_sha256},
    }
    evidence_path = root / "evidence.json"
    evidence_path.write_text(json.dumps(evidence))
    return binary_path, evidence_path, {"qualified_codex_build": qualified}, binary


def test_runtime_image_accepts_only_retained_reviewed_binary(tmp_path):
    binary_path, evidence_path, lock, expected = qualified_inputs(tmp_path)
    binary, qualified = MODULE.load_qualified_binary(binary_path, evidence_path, lock)
    assert binary == expected
    assert qualified["artifact_id"] == 11659714382


@pytest.mark.parametrize("mutation", ["binary", "evidence", "lock"])
def test_runtime_image_rejects_identity_substitution(tmp_path, mutation):
    binary_path, evidence_path, lock, _ = qualified_inputs(tmp_path)
    if mutation == "binary":
        binary_path.write_bytes(b"other")
    elif mutation == "evidence":
        evidence = json.loads(evidence_path.read_text())
        evidence["process_proof"] = "FAIL"
        evidence_path.write_text(json.dumps(evidence))
    else:
        lock["qualified_codex_build"]["artifact_id"] = 0
    with pytest.raises(ValueError):
        MODULE.load_qualified_binary(binary_path, evidence_path, lock)
