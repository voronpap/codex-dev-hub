"""Fail closed on missing canonical surfaces or unsupported readiness claims."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def validate(review, inventory):
    assert review["qualification_policy_v2_sha256"] is None
    assert review["execution_ready"] is False
    assert review["protocol_changed"] is False and review["config_changed"] is False
    assert review["real_codex_executions"] == review["provider_sends"] == 0
    assert review["codex_internal_retries"] is None
    expected = {r["tool_name"]: r for r in inventory["canonical_tool_inventory"]}
    assert len(review["matrix"]) == len(expected)
    assert {r["tool"] for r in review["matrix"]} == expected.keys()
    for row in review["matrix"]:
        previous = expected[row["tool"]]
        assert row["source_refs"] == previous["source_refs"]
        absent = previous["absent"]
        assert row["registered"] is (False if absent is True else True if absent is False else None)
        for key in (
            "invocable",
            "protected_state_read_possible",
            "protected_state_write_possible",
            "external_process_possible",
            "network_expansion_possible",
            "persistent_effect_possible",
        ):
            assert row[key] is (False if absent is True else None)
    assert review["critical_unknowns"]
    policy = ROOT / "src/devhub/experiment_tool_gate.py"
    assert (
        hashlib.sha256(policy.read_bytes()).hexdigest()
        == review["historical_qualification_policy_sha256"]
    )


if __name__ == "__main__":
    validate(
        json.loads((ROOT / "docs/evidence/stage3g-effects-boundary/review.json").read_bytes()),
        json.loads((ROOT / "docs/evidence/stage3g-mutation-audit/inventory.json").read_bytes()),
    )
    print("Effects review consistent; replacement policy NOT qualified")
