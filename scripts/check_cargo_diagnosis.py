"""Fail closed if proof-lock evidence claims anything beyond manifest-required local versions."""

import hashlib
import json
from pathlib import Path

from derive_router_build_lock import DERIVED, ORIGINAL
from record_router_proof import classify

ROOT = Path(__file__).resolve().parents[1] / "docs/evidence/stage3g-cargo-lock"


def validate(receipt, diffs, bindings):
    assert receipt["root_cause"] == "STALE_UPSTREAM_LOCK"
    assert receipt["safe_build_path"] == "LOCK_B"
    assert receipt["original_source_unchanged"] is True
    assert receipt["injection_is_cause"] is False
    assert receipt["original_lock_sha256"] == ORIGINAL
    assert receipt["accepted_derived_lock_sha256"] == DERIVED
    assert receipt["regenerated_candidate_accepted"] is False
    assert receipt["real_codex_executions"] == receipt["provider_sends"] == 0
    for label in ("base-metadata", "base-build", "injected-build"):
        assert receipt["commands"][label]["exit_code"] == 101
        assert receipt["commands"][label]["timed_out"] is False
    diff = diffs["minimal_derived_proof_lock"]
    assert diff["original_sha256"] == ORIGINAL and diff["candidate_sha256"] == DERIVED
    assert not diff["packages_added"] and not diff["packages_removed"]
    assert diff["lock_version_changed"] is False
    assert diff["top_level_other"]["old"] == diff["top_level_other"]["new"]
    assert diff["change_counts"] == {
        "versions_changed": 152,
        "git_revisions_changed": 0,
        "sources_changed": 0,
        "checksums_changed": 0,
        "dependency_edges_changed": 0,
    }
    by_name = {b["package"]: b for b in bindings}
    assert len(by_name) == len(bindings) == len(diff["packages_changed"]) == 152
    assert {c["package"] for c in diff["packages_changed"]} == set(by_name)
    for change in diff["packages_changed"]:
        binding = by_name[change["package"]]
        assert change["old_identity"]["source"] is None
        assert change["fields"] == {"version": {"old": "0.0.0", "new": "0.155.0-alpha.9.2"}}
        assert change["requiring_manifest"] == binding["manifest"]
        assert change["reason"] == binding["reason"]


def main():
    validate(
        *(
            json.loads((ROOT / name).read_bytes())
            for name in (
                "cargo-lock-diagnosis.json",
                "cargo-lock-structural-diff.json",
                "manifest-bindings.json",
            )
        )
    )
    print("LOCK_B: 152 manifest-required local versions; external graph unchanged")
    validate_router(ROOT)
    print("Actual pinned router: ROUTER_BLOCKED_BOTH; execution_ready=false")


def validate_router(root):
    result = json.loads((root / "router-proof.json").read_bytes())
    assert result["classification"] == classify(result["receipt"]) == "ROUTER_BLOCKED_BOTH"
    assert result["execution_ready"] is False
    assert result["real_codex_executions"] == result["provider_sends"] == 0
    for metric in ("semantic_acceptance", "quality_benchmark", "delegation_value", "savings"):
        assert result[metric] is None
    for suffix in ("stdout", "stderr"):
        raw = (root / f"router-test.{suffix}").read_bytes()
        assert hashlib.sha256(raw).hexdigest() == result["raw_artifact_hashes"][f"test.{suffix}"]
    lines = (root / "router-test.stdout").read_text(encoding="utf-8").splitlines()
    proof = [
        json.loads(line.split("=", 1)[1])
        for line in lines
        if line.startswith("DEVHUB_ROUTER_PROOF=")
    ]
    assert proof == [result["receipt"]["proof"]]
    current_test_hash = hashlib.sha256(
        (ROOT.parents[2] / "scripts/full_router_test.rs").read_bytes()
    ).hexdigest()
    assert current_test_hash == result["receipt"]["test_sha256"]
    a, b = result["A"], result["B"]
    assert a["tool_mode"] == b["tool_mode"] == "code_mode_only"
    assert b["registered_tools"] == ["mcp__devhub_delegatedevhub_delegate"]
    assert b["code_mode_map"] == {
        "mcp__devhub_delegate__devhub_delegate": {
            "name": "devhub_delegate",
            "namespace": "mcp__devhub_delegate",
        }
    }
    assert result["origin_verified"] is False


if __name__ == "__main__":
    main()
