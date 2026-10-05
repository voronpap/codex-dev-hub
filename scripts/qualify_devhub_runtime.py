"""Verify the context-bound immutable DevFabric Python runtime without inference."""

import argparse
import json
from pathlib import Path

from devhub.benchmark import canonical, write_new
from devhub.qualification import QualificationReceiptHeaderV1, load_context
from devhub.runtime_artifact import verify_runtime_against_expected


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--interpreter", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    context = load_context(args.context)
    header = QualificationReceiptHeaderV1(
        receipt_kind="python_runtime",
        qualification_context_id=context.qualification_context_id,
        environment_instance_id=context.payload.environment_instance_id,
    )
    receipt = verify_runtime_against_expected(
        args.interpreter,
        args.wheel,
        args.lock,
        context.payload.implementation.python_runtime,
        header,
    )
    write_new(args.output, canonical(receipt.model_dump(mode="json")))
    print(json.dumps(receipt.model_dump(mode="json"), sort_keys=True))


if __name__ == "__main__":
    main()
