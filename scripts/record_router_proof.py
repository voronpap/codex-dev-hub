"""Classify actual proof receipts only; a successful test may prove a blocked router."""

import argparse
import hashlib
import json
from pathlib import Path

from build_full_router_proof import COMMIT
from derive_router_build_lock import DERIVED, ORIGINAL


def classify(receipt):
    if (
        receipt.get("actual_pinned_router_code") is not True
        or receipt.get("build_exit_code") != 0
        or receipt.get("test_exit_code") != 0
    ):
        return "UNKNOWN"
    proof = receipt["proof"]
    assert proof["actual_pinned_router_code"] is True and proof["method_slice_only"] is False
    assert proof["real_codex_executions"] == proof["provider_sends"] == 0
    a, b = proof["arms"]
    assert a["arm"] == "A" and b["arm"] == "B"
    assert not any(
        a[k] for k in ("registered_tools", "visible_specs", "code_mode_map", "hosted_specs_exposed")
    )
    hidden = not b["visible_specs"] and bool(b["registered_tools"])
    collision = (
        proof["origin_bound_by_allowed_tools"] is False
        and proof["collision_result"]
        == "wrong origin first survives; duplicate rejected and collision recorded"
    )
    if hidden and collision:
        return "ROUTER_BLOCKED_BOTH"
    if hidden:
        return "ROUTER_BLOCKED_TOOL_MODE"
    if collision:
        return "ROUTER_BLOCKED_COLLISION"
    # No automatic feasibility from an unfamiliar output shape or name-only match.
    return "UNKNOWN"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = json.loads((args.artifacts / "result.json").read_bytes())
    assert receipt["source_commit"] == COMMIT
    assert receipt["original_lock_sha256"] == ORIGINAL
    assert receipt["proof_build_lock_sha256"] == DERIVED
    result = {
        "classification": classify(receipt),
        "receipt": receipt,
        "run_url": args.run_url,
        "execution_ready": False,
        "raw_artifact_hashes": {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(args.artifacts.iterdir())
            if p.is_file()
        },
        "A": None,
        "B": None,
        "origin_verified": None,
        "collision_result": None,
        "rehearsal": "not_run",
        "benchmark": "not_run",
        "v3_created": False,
        "real_codex_executions": 0,
        "provider_sends": 0,
        "semantic_acceptance": None,
        "quality_benchmark": None,
        "delegation_value": None,
        "savings": None,
        "codex_internal_retries": None,
    }
    if receipt.get("actual_pinned_router_code") is True:
        result["A"], result["B"] = receipt["proof"]["arms"]
        result["origin_verified"] = receipt["proof"]["origin_bound_by_allowed_tools"]
        result["collision_result"] = receipt["proof"]["collision_result"]
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
