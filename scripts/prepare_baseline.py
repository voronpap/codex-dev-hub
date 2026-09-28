"""Verify frozen fixture hashes and prepare an isolated, unmeasured A/B packet.

No inference, scoring, code execution or network access occurs here.
"""

import argparse
import hashlib
import json
from pathlib import Path


def verified_cases(root: Path) -> list[dict]:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    seen = set()
    cases = manifest["cases"]
    for case in cases:
        if case["id"] in seen:
            raise ValueError("Duplicate fixture ID")
        seen.add(case["id"])
        for kind in ("fixture", "oracle"):
            path = (root / case[kind]).resolve()
            if not path.is_relative_to(root.resolve()):
                raise ValueError("Fixture path escapes benchmark root")
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != case[f"{kind}_sha256"]:
                raise ValueError(f"Fixture integrity failure: {case['id']}")
    return cases


def prepare(root: Path, fixture_id: str, arm: str, destination: Path) -> None:
    cases = verified_cases(root)
    case = next((item for item in cases if item["id"] == fixture_id), None)
    if case is None:
        raise ValueError("Unknown fixture")
    fixture = json.loads((root / case["fixture"]).read_text(encoding="utf-8"))
    # Never reuse a previous run or copy reviewer-only oracles into the task packet.
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "input.txt").write_text(fixture["input"], encoding="utf-8")
    (destination / "task.txt").write_text(fixture["prompt"], encoding="utf-8")
    result = {
        "schema_version": 1,
        "fixture_id": fixture_id,
        "fixture_sha256": case["fixture_sha256"],
        "arm": arm,
        "state": "not_run",
        "measurement_source": "unavailable",
        "missing_reason": "Prepared packet only; no benchmark session executed.",
        "codex_model": None,
        "codex_version": None,
        "codex_input_tokens": None,
        "codex_output_tokens": None,
        "codex_context_peak": None,
        "delegated_tokens": None,
        "free_quota_consumed": None,
        "paid_cost_microusd": None,
        "elapsed_ms": None,
        "retries": None,
        "human_corrections": None,
        "human_minutes": None,
        "codex_redo": None,
        "quality_score": None,
        "tests_passed": None,
        "delegation_value": None,
    }
    (destination / "measurement.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--fixture")
    parser.add_argument("--arm", choices=["A", "B"], default="A")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1] / "benchmarks"
    if args.verify:
        print(f"Verified {len(verified_cases(root))} frozen baseline fixtures.")
    elif args.fixture and args.output:
        prepare(root, args.fixture, args.arm, args.output)
        print("Prepared unmeasured baseline packet; no model was called.")
    else:
        parser.error("Use --verify or --fixture ID --output NEW_DIRECTORY")


if __name__ == "__main__":
    main()
