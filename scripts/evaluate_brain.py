"""Reproduce the Stage 3A lexical quality seed in disposable local Git/SQLite state."""

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from devhub.brain import ProjectBrain
from devhub.brain_models import SearchQuery, sha256


def evaluate(fixture: Path) -> dict[str, Any]:
    raw = fixture.read_bytes()
    data = json.loads(raw)
    with tempfile.TemporaryDirectory(prefix="devhub-retrieval-") as temporary:
        root = Path(temporary) / "repo"
        root.mkdir()

        def git(*args: str) -> None:
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    f"core.hooksPath={root / 'no-hooks'}",
                    *args,
                ],
                check=True,
                capture_output=True,
            )

        git("init", "-q", "--initial-branch=main")
        for relative, content in data["corpus"].items():
            path = root / relative
            if not path.resolve().is_relative_to(root):
                raise ValueError("fixture source escapes temporary repository")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
        git("add", ".")
        git(
            "-c",
            "user.name=BrainFixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "retrieval fixture",
        )
        brain = ProjectBrain(Path(temporary) / "brain", {"fixture": root})
        scope = brain.scope("fixture")
        snapshot = brain.index(scope, approved_paths=tuple(data["corpus"]), expected_snapshot=None)
        rows = []
        for case in data["queries"]:
            result = brain.search(
                scope,
                snapshot_id=snapshot.snapshot_id,
                query=SearchQuery(text=case["query"], limit=3),
            )
            paths = [hit.path for hit in result.hits]
            relevant = set(case["relevant"])
            ranks = [index + 1 for index, path in enumerate(paths) if path in relevant]
            rows.append(
                {
                    "id": case["id"],
                    "returned_paths": paths,
                    "first_relevant_rank": min(ranks) if ranks else None,
                    "recall_at_3": len(set(paths) & relevant) / len(relevant),
                }
            )
        negative_hits = sum(
            len(
                brain.search(
                    scope, snapshot_id=snapshot.snapshot_id, query=SearchQuery(text=query, limit=3)
                ).hits
            )
            for query in data["negative_queries"]
        )
    total = len(rows)
    return {
        "schema_version": 1,
        "fixture_sha256": sha256(raw),
        "synthetic": True,
        "documents": len(data["corpus"]),
        "positive_queries": total,
        "negative_queries": len(data["negative_queries"]),
        "negative_hits": negative_hits,
        "top1_accuracy": sum(row["first_relevant_rank"] == 1 for row in rows) / total,
        "recall_at_3": sum(row["recall_at_3"] for row in rows) / total,
        "mrr_at_3": sum(
            1 / row["first_relevant_rank"] if row["first_relevant_rank"] else 0 for row in rows
        )
        / total,
        "queries": rows,
        "limitation": "Small synthetic lexical seed; no semantic recall or delegation-value claim.",
        "codex_tokens": None,
        "savings": None,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, default=Path("benchmarks/retrieval/stage3a.json"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.fixture), indent=2, ensure_ascii=False))
