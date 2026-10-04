"""Synthetic validator cases are not published as actual router proof."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location(
    "check_router_fix_evidence", SCRIPTS / "check_router_fix_evidence.py"
)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def synthetic_receipt():
    a = {
        "arm": "A",
        "tool_mode": "code_mode_only",
        "registered_tools": [],
        "visible_specs": [],
        "namespace_functions": {},
        "code_mode_map": {},
        "hosted_specs_exposed": [],
        "origin_seal_passed": True,
    }
    b = {
        **a,
        "arm": "B",
        "registered_tools": ["mcp__devhub_delegatedevhub_delegate"],
        "visible_specs": [
            {
                "type": "namespace",
                "name": "mcp__devhub_delegate",
                "tools": [{"type": "function", "name": "devhub_delegate"}],
            }
        ],
        "namespace_functions": {"mcp__devhub_delegate": ["devhub_delegate"]},
    }
    return {
        "actual_pinned_router_code": True,
        "build_exit_code": 0,
        "test_exit_code": 0,
        "proof": {
            "classification": "ROUTER_FIX_FEASIBLE",
            "actual_pinned_router_code": True,
            "method_slice_only": False,
            "production_modified": False,
            "execution_ready": False,
            "real_codex_executions": 0,
            "provider_sends": 0,
            "arms": [a, b],
            **dict.fromkeys(module.ADVERSARIAL, True),
        },
    }


def test_unexecuted_build_is_unknown():
    assert module.validate_proof({"build_exit_code": 0}) == "UNKNOWN"
    receipt = synthetic_receipt()
    receipt["test_exit_code"] = 1
    assert module.validate_proof(receipt) == "UNKNOWN"


@pytest.mark.parametrize("case", ["a_tool", "b_extra", "nested", "mode", "origin", "runtime"])
def test_candidate_fail_closed(case):
    receipt = synthetic_receipt()
    assert module.validate_proof(receipt) == "ROUTER_FIX_FEASIBLE"
    proof = receipt["proof"]
    if case == "a_tool":
        proof["arms"][0]["registered_tools"] = ["shell"]
    elif case == "b_extra":
        proof["arms"][1]["namespace_functions"]["mcp__devhub_delegate"].append("diagnostic")
    elif case == "nested":
        proof["arms"][1]["code_mode_map"] = {"exec": "exec"}
    elif case == "mode":
        proof["arms"][1]["tool_mode"] = "direct"
    elif case == "origin":
        proof["wrong_origin_first_rejected"] = False
    else:
        proof["execution_ready"] = True
    with pytest.raises(AssertionError):
        module.validate_proof(receipt)


def test_exact_source_excerpts_present():
    bindings = json.loads((module.ROOT / "source-bindings.json").read_bytes())
    assert len(bindings) == 15
    for source in bindings.values():
        assert len(source["excerpt"].split("\n")) == source["end"] - source["start"] + 1
        assert len(source["file_sha256"]) == 64
    assert "DirectModelOnly" in bindings["tool_exposure"]["excerpt"]
    assert "direct_only_tool_namespaces" in bindings["direct_only_override_visibility"]["excerpt"]


def test_actual_receipt_and_frozen_bytes():
    assert module.validate_record() == "ROUTER_FIX_FEASIBLE"


def test_visible_schema_cannot_disagree_with_names():
    receipt = synthetic_receipt()
    receipt["proof"]["arms"][1]["visible_specs"][0]["tools"].append(
        {"type": "function", "name": "shell"}
    )
    with pytest.raises(AssertionError):
        module.validate_proof(receipt)
