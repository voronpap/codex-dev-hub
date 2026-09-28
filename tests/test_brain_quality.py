import importlib.util
import json
from contextlib import nullcontext
from pathlib import Path


def test_labeled_lexical_retrieval_quality():
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "evaluate_brain", root / "scripts/evaluate_brain.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixture = root / "benchmarks/retrieval/stage3a.json"
    data = json.loads(fixture.read_text(encoding="utf-8"))
    report = module.evaluate(fixture)
    assert report["recall_at_3"] >= data["acceptance"]["recall_at_3_min"]
    assert report["top1_accuracy"] >= data["acceptance"]["top1_accuracy_min"]
    assert report["mrr_at_3"] >= data["acceptance"]["mrr_at_3_min"]
    assert report["negative_hits"] == 0
    assert report["queries"][0]["returned_paths"][0] == "src/controller.py"
    assert report["queries"][9]["first_relevant_rank"] == 1
    assert report == json.loads((root / "docs/evidence/stage3a-retrieval.json").read_text())


def test_evaluation_accepts_noncanonical_temp_root(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "evaluate_brain", root / "scripts/evaluate_brain.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    (tmp_path / "alias").mkdir()
    (tmp_path / "actual").mkdir()
    alias = tmp_path / "alias" / ".." / "actual"
    monkeypatch.setattr(module.tempfile, "TemporaryDirectory", lambda **kwargs: nullcontext(alias))
    fixture = tmp_path / "seed.json"
    fixture.write_text(
        json.dumps(
            {
                "corpus": {"guide.md": "quota admission"},
                "queries": [{"id": "q", "query": "quota", "relevant": ["guide.md"]}],
                "negative_queries": [],
            }
        ),
        encoding="utf-8",
    )
    report = module.evaluate(fixture)
    assert report["top1_accuracy"] == 1.0
