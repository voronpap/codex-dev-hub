import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


def load(name):
    spec = importlib.util.spec_from_file_location(name, f"scripts/{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def records():
    root = Path("docs/evidence")
    return (
        json.loads((root / "stage3g-effects-boundary/review.json").read_bytes()),
        json.loads((root / "stage3g-mutation-audit/inventory.json").read_bytes()),
    )


def test_review_covers_every_canonical_surface():
    load("check_effects_review").validate(*records())


def test_frozen_evidence_bytes_match_manifest():
    root = Path("docs/evidence/stage3g-effects-boundary")
    manifest = json.loads((root / "results.json").read_bytes())
    for name, expected in manifest["artifacts_sha256"].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == expected


@pytest.mark.parametrize("fault", ["missing", "remote_safe", "ready", "new_policy"])
def test_critical_unknown_cannot_become_approval(fault):
    review, inventory = records()
    if fault == "missing":
        review["matrix"].pop()
    elif fault == "remote_safe":
        next(r for r in review["matrix"] if r["tool"] == "notes.write_file")[
            "persistent_effect_possible"
        ] = False
    elif fault == "ready":
        review["execution_ready"] = True
    else:
        review["qualification_policy_v2_sha256"] = "0" * 64
    with pytest.raises(AssertionError):
        load("check_effects_review").validate(review, inventory)


def test_probe_rejects_successful_protected_mutation():
    report = {
        "protected": {
            "/control/session.json": {
                "unchanged": True,
                "operations": {"overwrite": {"denied": False}},
            }
        },
        "hidden_host_paths": {},
        "task_files_initially_absent": {},
        "writable_tmpfs": {},
        "system_files": {},
    }
    assert not load("probe_effects_boundary").validate(report)


def test_probe_separates_absent_task_files_from_writable_packet_tmpfs():
    probe = load("probe_effects_boundary")
    denied = {"denied": True, "errno": 13}
    absent = {"denied": True, "errno": 2}
    report = {
        "protected": {
            path: {
                "unchanged": True,
                "operations": {operation: denied for operation in ("overwrite", "append")},
            }
            for path in probe.PROTECTED_PATHS
        },
        "hidden_host_paths": {
            path: {"stat": absent, "create": denied} for path in probe.HIDDEN_HOST_PATHS
        },
        # No create result exists for task files: creating them after TASK_ACCEPTED is valid.
        "task_files_initially_absent": {path: {"stat": absent} for path in probe.TASK_FILES},
        "writable_tmpfs": {path: True for path in probe.WRITABLE_TMPFS},
        "system_files": {path: denied for path in ("/etc/hosts", "/etc/hostname")},
    }
    assert probe.validate(report)
    assert report["writable_tmpfs"]["/packet"] is True
