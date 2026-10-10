import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path("scripts/stage3g_schema_hash.py")
SPEC = importlib.util.spec_from_file_location("stage3g_schema_hash", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_formatting_does_not_change_canonical_schema_identity(tmp_path: Path) -> None:
    value = {"type": "object", "properties": {"value": {"type": "string"}}}
    pretty = tmp_path / "pretty.json"
    compact = tmp_path / "compact.json"
    pretty.write_text(json.dumps(value, indent=2), encoding="utf-8")
    compact.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")

    expected = MODULE.canonical_schema_sha256(value)
    pretty_identity = MODULE.read_schema_identity(pretty, expected_canonical_sha256=expected)
    compact_identity = MODULE.read_schema_identity(compact, expected_canonical_sha256=expected)

    assert pretty_identity.raw_file_sha256 != compact_identity.raw_file_sha256
    assert pretty_identity.canonical_schema_sha256 == compact_identity.canonical_schema_sha256


def test_key_order_and_whitespace_do_not_change_canonical_hash() -> None:
    first = json.loads('{"b": 2, "a": {"y": 1, "x": 0}}')
    second = json.loads('{\n  "a": {"x": 0, "y": 1},\n  "b": 2\n}')

    assert MODULE.canonical_schema_sha256(first) == MODULE.canonical_schema_sha256(second)


def test_semantic_schema_change_is_rejected(tmp_path: Path) -> None:
    original = {"type": "string", "maxLength": 64}
    changed = {"type": "string", "maxLength": 65}
    path = tmp_path / "schema.json"
    path.write_text(json.dumps(changed), encoding="utf-8")

    with pytest.raises(ValueError, match="canonical JSON schema identity changed"):
        MODULE.read_schema_identity(
            path,
            expected_canonical_sha256=MODULE.canonical_schema_sha256(original),
        )


def test_invalid_json_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "schema.json"
    raw = b'{"type": "object"'
    path.write_bytes(raw)

    with pytest.raises(ValueError, match="valid UTF-8 JSON"):
        MODULE.read_schema_identity(
            path,
            expected_canonical_sha256=hashlib.sha256(raw).hexdigest(),
        )
