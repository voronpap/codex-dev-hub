"""Build an acyclic Stage 3G qualification context from a strict payload."""

import argparse
import json
from pathlib import Path

from devhub.benchmark import write_new
from devhub.qualification import (
    QualificationContextPayloadV1,
    QualificationContextV1,
    canonical_context,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.payload.is_symlink() or not args.payload.is_file():
        parser.error("Payload must be a regular file")
    payload = QualificationContextPayloadV1.model_validate_json(args.payload.read_bytes())
    context = QualificationContextV1.create(payload)
    write_new(args.output, canonical_context(context))
    print(json.dumps({"qualification_context_id": context.qualification_context_id}))


if __name__ == "__main__":
    main()
