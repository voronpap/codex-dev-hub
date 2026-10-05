"""Generate and persist one opaque qualification-environment identifier."""

import argparse
import json
from pathlib import Path

from devhub.benchmark import canonical, write_new
from devhub.qualification import generate_environment_instance_id


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    value = generate_environment_instance_id()
    write_new(args.output, canonical({"schema_version": 1, "environment_instance_id": value}))
    print(json.dumps({"environment_instance_id": value}))


if __name__ == "__main__":
    main()
