import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prepare", ROOT / "scripts/prepare_baseline.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


def test_manifest_has_twelve_frozen_cases_in_six_classes():
    cases = prepare.verified_cases(ROOT / "benchmarks")
    assert len(cases) == 12
    classes = [
        json.loads((ROOT / "benchmarks" / c["fixture"]).read_text())["task_class"] for c in cases
    ]
    assert len(set(classes)) == 6
    assert all(classes.count(name) == 2 for name in classes)


def test_preparation_excludes_oracles_and_does_not_invent_measurements(tmp_path):
    destination = tmp_path / "A"
    prepare.prepare(ROOT / "benchmarks", "review-02", "A", destination)
    assert {p.name for p in destination.iterdir()} == {"input.txt", "task.txt", "measurement.json"}
    result = json.loads((destination / "measurement.json").read_text())
    assert result["state"] == "not_run"
    assert result["codex_input_tokens"] is None
    assert result["paid_cost_microusd"] is None
    assert result["delegation_value"] is None
    with pytest.raises(FileExistsError):
        prepare.prepare(ROOT / "benchmarks", "review-02", "A", destination)


def test_tampered_fixture_or_oracle_is_rejected(tmp_path):
    target = tmp_path / "benchmarks"
    shutil.copytree(ROOT / "benchmarks", target)
    (target / "oracles/review-02.json").write_text("{}")
    with pytest.raises(ValueError, match="integrity"):
        prepare.verified_cases(target)
