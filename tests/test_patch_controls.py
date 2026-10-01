import importlib.util
import json
import sys
from pathlib import Path

import pytest

# Import the offline evidence validator, not any executor/runtime.
sys.path.insert(0, str(Path("scripts").resolve()))
spec = importlib.util.spec_from_file_location("patch_audit", "scripts/check_patch_controls.py")
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.path.pop(0)


def records():
    return [
        json.loads((module.ROOT / name).read_bytes())
        for name in ("controls.json", "schema-search.json", "source-bindings.json")
    ]


def test_control_evidence_distinguishes_internal_host_and_cli():
    module.validate(*records())


@pytest.mark.parametrize("fault", ["readonly_absence", "host_is_cli", "mutated_policy"])
def test_reject_unsupported_disable_claim(fault):
    controls, schema, bindings = records()
    if fault == "readonly_absence":
        c = next(
            c
            for c in controls["supported_disable_controls"]
            if c["mechanism"].startswith("read-only")
        )
        c["apply_patch_registered_after_control"] = False
    elif fault == "host_is_cli":
        controls["supported_model_independent_disable_in_frozen_cli"] = True
    else:
        controls["protocol_config_changed"] = True
    with pytest.raises(AssertionError):
        module.validate(controls, schema, bindings)
