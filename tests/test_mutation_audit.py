import copy
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("audit", Path("scripts/check_mutation_audit.py"))
assert spec and spec.loader
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def records():
    return [
        json.loads((audit.EVIDENCE / name).read_bytes())
        for name in ("inventory.json", "model-metadata.json", "source-bindings.json")
    ]


def test_frozen_inventory_and_metadata_agree():
    audit.validate(*records())


@pytest.mark.parametrize("fault", ["omission", "false_absence", "wrong_default", "inference"])
def test_audit_rejects_unjustified_claims(fault):
    inventory, metadata, bindings = copy.deepcopy(records())
    if fault == "omission":
        inventory["canonical_tool_inventory"] = [
            row
            for row in inventory["canonical_tool_inventory"]
            if row["tool_name"] != "notes.write_file"
        ]
    elif fault == "false_absence":
        inventory["apply_patch_absent"] = True
    elif fault == "wrong_default":
        metadata["service_default_model_id"] = "unobserved-model"
    else:
        metadata["inference_requests"] = 1
    with pytest.raises(AssertionError):
        audit.validate(inventory, metadata, bindings)
