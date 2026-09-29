"""Frozen Stage 1 input verification shared by packet preparation and the harness."""

import hashlib
import json
from pathlib import Path
from typing import TypedDict, cast

SEED_MANIFEST_SHA256 = "0c0eaccdb5109ff80dea115a75f0965b6948585cedb2e71351094de748ce3e5c"


class Case(TypedDict):
    id: str
    fixture: str
    fixture_sha256: str
    oracle: str
    oracle_sha256: str


def verified_cases(root: Path) -> list[Case]:
    raw = (root / "manifest.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != SEED_MANIFEST_SHA256:
        raise ValueError("Frozen seed manifest integrity failure")
    cases = cast(list[Case], json.loads(raw)["cases"])
    for case in cases:
        for kind, expected in (
            (case["fixture"], case["fixture_sha256"]),
            (case["oracle"], case["oracle_sha256"]),
        ):
            path = root / kind
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                raise ValueError("Fixture path escapes benchmark root")
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError(f"Fixture integrity failure: {case['id']}")
    return cases
