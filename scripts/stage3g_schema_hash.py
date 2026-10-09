"""Canonical JSON schema identity helpers for Stage 3G proof tooling."""

import hashlib
import json
from pathlib import Path
from typing import NamedTuple


class SchemaIdentity(NamedTuple):
    value: object
    raw_file_sha256: str
    canonical_schema_sha256: str


def canonical_schema_bytes(value: object) -> bytes:
    """Return the reviewed compact UTF-8 JSON representation of a schema."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_schema_sha256(value: object) -> str:
    return hashlib.sha256(canonical_schema_bytes(value)).hexdigest()


def read_schema_identity(path: Path, *, expected_canonical_sha256: str) -> SchemaIdentity:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("schema file must contain valid UTF-8 JSON") from error
    canonical_sha256 = canonical_schema_sha256(value)
    if canonical_sha256 != expected_canonical_sha256:
        raise ValueError("canonical JSON schema identity changed")
    return SchemaIdentity(
        value=value,
        raw_file_sha256=hashlib.sha256(raw).hexdigest(),
        canonical_schema_sha256=canonical_sha256,
    )
