"""Transactional, local outbox. Export retries never perform accounting again."""

import sqlite3
import time
from typing import Literal
from uuid import uuid4

from devhub.ledger import Ledger
from devhub.models import Contract, Identifier
from devhub.resources import Count, ResourcePolicy, Timestamp

Transition = Literal["reserved", "dispatched", "unknown_usage", "settled", "released"]


class AllocationSnapshot(Contract):
    bucket: Identifier
    reserved: Count
    actual: Count | None


class AccountingEvent(Contract):
    id: Identifier
    project: Identifier
    task: Identifier
    reservation: Identifier
    resource: Identifier
    transition: Transition
    recorded_ms: Timestamp
    synthetic: bool = True
    allocations: tuple[AllocationSnapshot, ...]


def record_event(connection: sqlite3.Connection, ticket: str, transition: Transition) -> None:
    """Called inside the same transaction as the state/counter change."""
    row = connection.execute("SELECT * FROM reservations WHERE id=?", (ticket,)).fetchone()
    event = AccountingEvent(
        id=uuid4().hex,
        project=row["project"],
        task=row["task"],
        reservation=ticket,
        resource=row["resource"],
        synthetic=ResourcePolicy.model_validate_json(row["policy"]).synthetic,
        transition=transition,
        recorded_ms=time.time_ns() // 1_000_000,
        allocations=tuple(
            AllocationSnapshot(
                bucket=item["bucket"], reserved=item["amount"], actual=item["actual"]
            )
            for item in connection.execute(
                "SELECT * FROM allocations WHERE reservation=? ORDER BY bucket",
                (ticket,),
            )
        ),
    )
    connection.execute(
        "INSERT INTO events(id, project, reservation, payload) VALUES (?, ?, ?, ?)",
        (event.id, event.project, ticket, event.model_dump_json()),
    )


class EventOutbox:
    def __init__(self, ledger: Ledger) -> None:
        self.ledger = ledger

    def pending(self, *, project: str, limit: int = 100) -> tuple[AccountingEvent, ...]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self.ledger.transaction() as connection:
            return tuple(
                AccountingEvent.model_validate_json(row[0])
                for row in connection.execute(
                    """SELECT payload FROM events WHERE project=? AND acknowledged=0
                ORDER BY sequence LIMIT ?""",
                    (project, limit),
                )
            )

    def acknowledge(self, *, project: str, event_id: str) -> None:
        """Acknowledge only after consumer commits. Consumer deduplicates by event ID."""
        with self.ledger.transaction() as connection:
            cursor = connection.execute(
                "UPDATE events SET acknowledged=1 WHERE id=? AND project=?",
                (event_id, project),
            )
            if cursor.rowcount != 1:
                raise ValueError("unknown project event")
