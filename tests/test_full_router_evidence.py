import importlib.util
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path("scripts").resolve()))
spec = importlib.util.spec_from_file_location(
    "full_router_audit", "scripts/check_full_router_evidence.py"
)
assert spec and spec.loader
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
sys.path.pop(0)


def records():
    return [
        json.loads((audit.ROOT / name).read_bytes()) for name in ("metadata.json", "result.json")
    ]


def test_observed_mode_does_not_promote_uncompiled_router():
    audit.validate(*records())


@pytest.mark.parametrize("fault", ["mode", "full_proof", "classification", "origin"])
def test_missing_runtime_proof_stays_unknown(fault):
    metadata, result = records()
    if fault == "mode":
        result["derived_effective_tool_mode"] = "Direct"
    elif fault == "full_proof":
        result["actual_pinned_router_code"] = True
    elif fault == "classification":
        result["classification"] = "ROUTER_FEASIBLE"
    else:
        result["B"]["origin_verified"] = True
    with pytest.raises(AssertionError):
        audit.validate(metadata, result)
