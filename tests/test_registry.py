import sqlite3

import pytest
from test_controller import setup_core

from devhub.controller import Denied
from devhub.ledger import MIGRATIONS, Ledger
from devhub.registry import CapabilityRecord, CapabilityRegistry


def record(**changes):
    return CapabilityRecord.model_validate(
        dict(
            resource="fake-a",
            provider="fake",
            model="text",
            endpoint="chat",
            plan="free",
            kind="free",
            locality="cloud",
            supports_text=True,
            context_tokens=100,
            max_output_tokens=50,
            healthy=True,
            task_classes=("summary",),
            observed_ms=0,
            valid_until_ms=1000,
            evidence="fixture",
        )
        | changes
    )


def test_evidence_roundtrip_revision_and_policy_binding(tmp_path):
    core = setup_core(tmp_path)
    registry = CapabilityRegistry(core.ledger)
    original = record()
    registry.put(original)
    assert CapabilityRegistry(Ledger(core.ledger.path)).records() == (original,)
    updated = record(supports_json=True)
    assert updated.revision != original.revision
    registry.put(updated)
    assert registry.records() == (updated,)
    with pytest.raises(Denied, match="mismatch"):
        registry.put(record(kind="paid"))
    with pytest.raises(Denied, match="mismatch"):
        registry.put(record(resource="absent"))


def test_upgrade_v1_preserves_counters(tmp_path):
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as connection:
        for statement in MIGRATIONS[0]:
            connection.execute(statement)
        connection.execute("PRAGMA user_version=1")
        connection.execute("INSERT INTO buckets VALUES ('pool', '{}', 3, 2)")
    with Ledger(path).transaction() as connection:
        assert tuple(connection.execute("SELECT used, held FROM buckets").fetchone()) == (3, 2)
        assert connection.execute("SELECT * FROM capabilities").fetchall() == []
