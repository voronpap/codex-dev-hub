"""Persisted, expiring capability evidence for synthetic resources only."""

import hashlib
from typing import Annotated, Literal

from pydantic import Field, model_validator

from devhub.controller import Denied
from devhub.ledger import Ledger
from devhub.models import Contract, Identifier
from devhub.resources import Positive, ResourcePolicy, Timestamp


class CapabilityRecord(Contract):
    resource: Identifier
    provider: Identifier
    model: Identifier
    endpoint: Identifier
    plan: Identifier
    kind: Literal["free", "local", "paid"]
    locality: Literal["local", "cloud"]
    synthetic: Literal[True] = True
    supports_text: bool | None = None
    supports_json: bool | None = None
    context_tokens: Positive | None = None
    max_output_tokens: Positive | None = None
    healthy: bool | None = None
    task_classes: Annotated[tuple[Identifier, ...], Field(max_length=32)] = ()
    observed_ms: Timestamp
    valid_until_ms: Timestamp
    evidence: Identifier

    @model_validator(mode="after")
    def valid_evidence(self) -> "CapabilityRecord":
        if self.valid_until_ms <= self.observed_ms:
            raise ValueError("evidence must expire after observation")
        if self.kind == "local" and self.locality != "local":
            raise ValueError("local resources cannot use cloud endpoints")
        if len(set(self.task_classes)) != len(self.task_classes):
            raise ValueError("duplicate task class")
        return self

    @property
    def revision(self) -> str:
        return hashlib.sha256(self.model_dump_json().encode()).hexdigest()


class CapabilityRegistry:
    def __init__(self, ledger: Ledger) -> None:
        self.ledger = ledger

    def put(self, record: CapabilityRecord) -> None:
        """Operator-verified synthetic evidence, never an untrusted model claim."""
        with self.ledger.transaction() as connection:
            row = connection.execute(
                "SELECT spec FROM policies WHERE id=?", (record.resource,)
            ).fetchone()
            if row is None or ResourcePolicy.model_validate_json(row[0]).kind != record.kind:
                raise Denied("capability_policy_mismatch")
            connection.execute(
                """INSERT INTO capabilities VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET revision=excluded.revision, spec=excluded.spec""",
                (record.resource, record.revision, record.model_dump_json()),
            )

    def records(self) -> tuple[CapabilityRecord, ...]:
        with self.ledger.transaction() as connection:
            return tuple(
                CapabilityRecord.model_validate_json(row[0])
                for row in connection.execute("SELECT spec FROM capabilities ORDER BY id")
            )
