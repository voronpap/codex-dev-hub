"""Synthetic/non-benchmark evaluator proof. Never loads the frozen twelve fixtures."""

import argparse
import json
from pathlib import Path

from devhub.benchmark import canonical, digest, write_new
from devhub.experiment_evaluate import evaluate_bytes
from devhub.qualification import load_context, receipt_header


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    args = parser.parse_args()
    context = load_context(args.context)
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
    receipt = {
        **receipt_header(context, "evaluator"),
        "kind": "synthetic_evaluator_proof",
        "qualification_passed": True,
        "tests_pass": True,
        "image_id": args.image_id,
        "artifact_sha256": context.payload.evaluator_expected.artifact_sha256,
        "result_sha256": digest((args.output / "result.json").read_bytes()),
        "runner_sha256": result["runner_sha256"],
        "real_codex_executions": 0,
        "provider_sends": 0,
    }
    write_new(args.output / "qualification-receipt.json", canonical(receipt))
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
