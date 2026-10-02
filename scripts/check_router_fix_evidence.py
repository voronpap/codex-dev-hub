"""Record and check compiled candidate proof; never equate it with runtime qualification."""

import argparse
import hashlib
import json
from pathlib import Path

from build_full_router_proof import COMMIT
from check_mutation_audit import verify_sources
from derive_router_build_lock import DERIVED

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO / "docs/evidence/stage3g-router-fix"
ADVERSARIAL = (
    "wrong_origin_first_rejected",
    "raw_name_mismatch_rejected",
    "spoofed_channel_rejected",
    "namespace_alias_rejected",
    "forged_runtime_rejected",
    "bypassed_guard_collision_finalization_failed",
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_proof(receipt):
    if (
        receipt.get("actual_pinned_router_code") is not True
        or receipt.get("build_exit_code") != 0
        or receipt.get("test_exit_code") != 0
    ):
        return "UNKNOWN"
    proof = receipt["proof"]
    assert proof["classification"] == "ROUTER_FIX_FEASIBLE"
    assert proof["actual_pinned_router_code"] is True and proof["method_slice_only"] is False
    assert proof["production_modified"] is False and proof["execution_ready"] is False
    assert proof["real_codex_executions"] == proof["provider_sends"] == 0
    assert all(proof[name] is True for name in ADVERSARIAL)
    a, b = proof["arms"]
    assert a["arm"] == "A" and b["arm"] == "B"
    for arm in (a, b):
        assert arm["tool_mode"] == "code_mode_only"
        assert arm["code_mode_map"] == {}
        assert arm["hosted_specs_exposed"] == []
        assert arm["origin_seal_passed"] is True
    assert a["registered_tools"] == [] and a["visible_specs"] == []
    assert a["namespace_functions"] == {}
    assert b["registered_tools"] == ["mcp__devhub_delegatedevhub_delegate"]
    assert b["namespace_functions"] == {"mcp__devhub_delegate": ["devhub_delegate"]}
    assert len(b["visible_specs"]) == 1
    return "ROUTER_FIX_FEASIBLE"


def record(artifacts, run_id):
    receipt = json.loads((artifacts / "result.json").read_bytes())
    assert receipt["source_commit"] == COMMIT
    assert receipt["proof_build_lock_sha256"] == DERIVED
    assert receipt["test_sha256"] == sha((REPO / "scripts/router_fix_test.rs").read_bytes())
    assert receipt["metadata_sha256"] == sha(
        (REPO / "docs/evidence/stage3g-full-router/metadata.json").read_bytes()
    )
    result = {
        "classification": validate_proof(receipt),
        "receipt": receipt,
        "run_url": f"https://github.com/voronpap/codex-dev-hub/actions/runs/{run_id}",
        "rust_build_count": 1,
        "build_duration_seconds": receipt["build_duration_seconds"],
        "execution_ready": False,
        "production_integration_proven": False,
        "v3_created": False,
        "metadata_refreshes": 0,
        "real_codex_executions": 0,
        "provider_sends": 0,
        "semantic_acceptance": None,
        "quality_benchmark": None,
        "delegation_value": None,
        "savings": None,
        "codex_internal_retries": None,
        "raw_artifact_hashes": {
            p.name: sha(p.read_bytes()) for p in sorted(artifacts.iterdir()) if p.is_file()
        },
    }
    for name in ("test.stdout", "test.stderr"):
        if (artifacts / name).exists():
            with (ROOT / name).open("xb") as stream:
                stream.write((artifacts / name).read_bytes())
    with (ROOT / "result.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


def validate_record(root=ROOT):
    result = json.loads((root / "result.json").read_bytes())
    receipt = result["receipt"]
    assert result["classification"] == validate_proof(receipt)
    assert result["execution_ready"] is False and result["production_integration_proven"] is False
    assert result["v3_created"] is False
    assert result["real_codex_executions"] == result["provider_sends"] == 0
    assert receipt["source_commit"] == COMMIT and receipt["proof_build_lock_sha256"] == DERIVED
    assert receipt["test_sha256"] == sha((REPO / "scripts/router_fix_test.rs").read_bytes())
    if receipt["actual_pinned_router_code"] is True:
        for name in ("test.stdout", "test.stderr"):
            assert sha((root / name).read_bytes()) == result["raw_artifact_hashes"][name]
        records = [
            json.loads(line.split("=", 1)[1])
            for line in (root / "test.stdout").read_text(encoding="utf-8").splitlines()
            if line.startswith("DEVHUB_ROUTER_PROOF=")
        ]
        assert records == [receipt["proof"]]
    return result["classification"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--run-id", type=int)
    parser.add_argument("--verify-upstream", action="store_true")
    args = parser.parse_args()
    if args.artifacts:
        assert args.run_id
        record(args.artifacts, args.run_id)
    if args.verify_upstream:
        print(
            "Verified source files:",
            verify_sources(json.loads((ROOT / "source-bindings.json").read_bytes())),
        )
    print(validate_record())


if __name__ == "__main__":
    main()
