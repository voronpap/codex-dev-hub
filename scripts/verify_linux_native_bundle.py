"""Verify one published native Linux release before any packaged command is used."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from devhub.linux_bundle import verify_linux_native_release


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args()
    receipt = verify_linux_native_release(args.release, args.destination)
    print(json.dumps(receipt.model_dump(mode="json"), sort_keys=True))


if __name__ == "__main__":
    main()
