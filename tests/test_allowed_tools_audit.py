import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path("scripts").resolve()))
spec = importlib.util.spec_from_file_location("allowed_audit", "scripts/check_allowed_tools.py")
assert spec and spec.loader
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
sys.path.pop(0)


def records():
    return [
        json.loads((audit.EVIDENCE / name).read_bytes())
        for name in ("source-bindings.json", "review.json")
    ]


def test_pinned_method_slices_and_review():
    bindings, review = records()
    audit.validate(bindings, review)
    code = audit.rust_source(bindings)
    for name in (
        "with_allowed_tools",
        "register_trusted_with_exposure",
        "prepend_trusted",
        "register_external_with_exposure",
    ):
        assert audit.block(bindings["registry"]["excerpt"], f"pub(crate) fn {name}") in code


def test_compiled_receipt_binds_current_method_slices():
    bindings, _ = records()
    proof = json.loads((audit.EVIDENCE / "synthetic-proof.json").read_bytes())
    assert (
        hashlib.sha256(audit.rust_source(bindings).encode()).hexdigest()
        == proof["generated_rust_sha256"]
    )
    assert proof["full_core_registry_proof"] is None
    assert proof["host_wrapper_compiled"] is False


@pytest.mark.parametrize("fault", ["plain_name", "host_a", "full_proof", "ready", "v3"])
def test_slice_proof_cannot_promote_host_readiness(fault):
    bindings, review = records()
    if fault == "plain_name":
        review["canonical_b"]["namespace"] = None
    elif fault == "host_a":
        review["classification"] = "HOST_A"
    elif fault == "full_proof":
        review["full_core_registry_proof"] = True
    elif fault == "ready":
        review["execution_ready"] = True
    else:
        review["v3_created"] = True
    with pytest.raises(AssertionError):
        audit.validate(bindings, review)
