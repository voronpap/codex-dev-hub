"""Synthetic/non-benchmark evaluator proof. Never loads the frozen twelve fixtures."""

import argparse
import json
from pathlib import Path

from devhub.experiment_evaluate import evaluate_bytes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    runner = Path(__file__).with_name("benchmark_evaluator.py").resolve()
    raw = b"from solution import add\ndef test_add():\n    assert add(2, 3) == 5\n"
    result = evaluate_bytes(
        raw,
        b"def add(a,b): return a-b\n",
        b"def add(a,b): return a+b\n",
        args.image_id,
        runner,
        args.output,
        review_barrier_passed=True,
    )
    if not result["tests_pass"]:
        raise ValueError("Synthetic evaluator proof failed")
    print(
        json.dumps(
            {
                "kind": "synthetic_evaluator_proof",
                "tests_pass": True,
                "image_id": args.image_id,
                "real_codex_executions": 0,
                "provider_sends": 0,
            }
        )
    )


if __name__ == "__main__":
    main()
