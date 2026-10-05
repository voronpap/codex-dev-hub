import pytest
from ledger_support import identity
from test_controller import setup_core

from devhub import ledger as ledger_module
from devhub.controller import Denied
from devhub.ledger import Ledger
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
    assert CapabilityRegistry(Ledger(core.ledger.path, identity())).records() == (original,)
    updated = record(supports_json=True)
    assert updated.revision != original.revision
    registry.put(updated)
    assert registry.records() == (updated,)
    with pytest.raises(Denied, match="mismatch"):
        registry.put(record(kind="paid"))
    with pytest.raises(Denied, match="mismatch"):
        registry.put(record(resource="absent"))


def test_upgrade_v1_preserves_counters(tmp_path, monkeypatch):
    path = tmp_path / "old.db"
    with monkeypatch.context() as context:
        context.setattr(ledger_module, "MIGRATIONS", ledger_module.MIGRATIONS[:1])
        old = Ledger.initialize(path, identity())
    with old.transaction() as connection:
        connection.execute("INSERT INTO buckets VALUES ('pool', '{}', 3, 2)")
    with Ledger(path, identity()).transaction() as connection:
        assert tuple(connection.execute("SELECT used, held FROM buckets").fetchone()) == (3, 2)
        assert connection.execute("SELECT * FROM capabilities").fetchall() == []
