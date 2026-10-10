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


def seed_cases(root: Path) -> list[Case]:
    """Verify the frozen manifest without reading fixture or oracle payloads."""

    raw = (root / "manifest.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != SEED_MANIFEST_SHA256:
        raise ValueError("Frozen seed manifest integrity failure")
    return cast(list[Case], json.loads(raw)["cases"])


def verified_fixture_payloads(root: Path) -> list[tuple[Case, dict[str, object]]]:
    """Read only frozen task fixtures; rehearsal collision checks never read oracles."""

    cases = seed_cases(root)
    result: list[tuple[Case, dict[str, object]]] = []
    for case in cases:
        path = root / case["fixture"]
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("Fixture path escapes benchmark root")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != case["fixture_sha256"]:
            raise ValueError(f"Fixture integrity failure: {case['id']}")
        loaded = json.loads(raw)
        if not isinstance(loaded, dict):
            raise ValueError(f"Fixture payload is not an object: {case['id']}")
        result.append((case, cast(dict[str, object], loaded)))
    return result


def verified_cases(root: Path) -> list[Case]:
    cases = seed_cases(root)
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
