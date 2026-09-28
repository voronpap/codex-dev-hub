"""Atomic reservations. No network calls, automatic retries or inferred usage."""

import hashlib
import sqlite3
from typing import cast
from uuid import uuid4

from devhub.ledger import Ledger
from devhub.resources import Admission, Bucket, ResourcePolicy, SpendApproval, Ticket


class Denied(RuntimeError):
    """Stable reason code; does not echo request contents."""


def fingerprint(request: Admission) -> str:
    return hashlib.sha256(request.model_dump_json().encode()).hexdigest()


class ResourceController:
    def __init__(self, ledger: Ledger, *, allow_paid_simulation: bool = False) -> None:
        self.ledger = ledger
        self.allow_paid_simulation = allow_paid_simulation

    def register_bucket(self, bucket: Bucket) -> None:
        with self.ledger.transaction() as connection:
            row = connection.execute("SELECT spec FROM buckets WHERE id=?", (bucket.id,)).fetchone()
            if row is not None and row[0] != bucket.model_dump_json():
                raise Denied("immutable_bucket")
            for other_row in connection.execute(
                "SELECT spec FROM buckets WHERE id<>?", (bucket.id,)
            ):
                other = Bucket.model_validate_json(other_row[0])
                if (other.pool, other.unit, other.scope, other.project, other.task) == (
                    bucket.pool,
                    bucket.unit,
                    bucket.scope,
                    bucket.project,
                    bucket.task,
                ) and max(other.starts_ms, bucket.starts_ms) < min(
                    other.ends_ms or 9_000_000_000_000_000,
                    bucket.ends_ms or 9_000_000_000_000_000,
                ):
                    raise Denied("overlapping_pool_window")
            connection.execute(
                "INSERT OR IGNORE INTO buckets(id, spec) VALUES (?, ?)",
                (bucket.id, bucket.model_dump_json()),
            )

    def register_policy(self, policy: ResourcePolicy) -> None:
        with self.ledger.transaction() as connection:
            for bucket in policy.buckets:
                if (
                    connection.execute("SELECT 1 FROM buckets WHERE id=?", (bucket,)).fetchone()
                    is None
                ):
                    raise Denied("missing_bucket")
            row = connection.execute(
                "SELECT spec FROM policies WHERE id=?", (policy.id,)
            ).fetchone()
            if row is not None and row[0] != policy.model_dump_json():
                raise Denied("immutable_policy")
            connection.execute(
                "INSERT OR IGNORE INTO policies(id, spec) VALUES (?, ?)",
                (policy.id, policy.model_dump_json()),
            )

    def reserve(
        self,
        request: Admission,
        *,
        now_ms: int,
        approval: SpendApproval | None = None,
        capability_revision: str | None = None,
        attempt_limit: int = 3,
    ) -> Ticket:
        with self.ledger.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM reservations WHERE project=? AND request_key=?",
                (request.project, request.key),
            ).fetchone()
            if existing is not None:
                if existing["fingerprint"] != fingerprint(request):
                    raise Denied("idempotency_conflict")
                return Ticket(id=existing["id"], state=existing["state"])
            if not now_ms < request.expires_ms <= now_ms + 120_000:
                raise Denied("invalid_lease")
            if type(attempt_limit) is not int or not 1 <= attempt_limit <= 3:
                raise Denied("invalid_attempt_limit")
            attempts = connection.execute(
                "SELECT COUNT(*) FROM reservations WHERE project=? AND task=?",
                (request.project, request.task),
            ).fetchone()[0]
            if attempts >= attempt_limit:
                raise Denied("attempt_limit")
            if capability_revision is not None:
                self._check_capability(
                    connection, request.resource, capability_revision, now_ms, request.expires_ms
                )
            row = connection.execute(
                "SELECT spec FROM policies WHERE id=?", (request.resource,)
            ).fetchone()
            if row is None:
                raise Denied("unknown_resource")
            policy = ResourcePolicy.model_validate_json(row[0])
            cost = 0
            if policy.kind == "paid":
                if not self.allow_paid_simulation:
                    raise Denied("paid_disabled")
                if policy.price is None or policy.price.valid_until_ms < request.expires_ms:
                    raise Denied("unknown_price")
                cost = policy.price.ceiling(request.input_tokens, request.max_output_tokens)
                if approval is None or (
                    (approval.project, approval.task, approval.resource)
                    != (request.project, request.task, request.resource)
                    or approval.max_microusd < cost
                    or approval.expires_ms < request.expires_ms
                ):
                    raise Denied("approval_required")
            amounts = {
                "requests": 1,
                "input_tokens": request.input_tokens,
                "output_tokens": request.max_output_tokens,
                "total_tokens": request.input_tokens + request.max_output_tokens,
                "microusd": cost,
            }
            allocations: list[tuple[str, int]] = []
            budget_scopes = set()
            for bucket_id in policy.buckets:
                counter = connection.execute(
                    "SELECT * FROM buckets WHERE id=?", (bucket_id,)
                ).fetchone()
                bucket = Bucket.model_validate_json(counter["spec"])
                if (
                    bucket.capacity is None
                    or bucket.ends_ms is None
                    or not bucket.starts_ms <= now_ms < bucket.ends_ms
                    or request.expires_ms > bucket.ends_ms
                ):
                    raise Denied("unknown_or_expired_window")
                if (bucket.project is not None and bucket.project != request.project) or (
                    bucket.task is not None and bucket.task != request.task
                ):
                    raise Denied("scope_mismatch")
                amount = amounts[bucket.unit]
                if (
                    counter["used"] + counter["held"] + amount
                    > bucket.capacity - bucket.reserve_floor
                ):
                    raise Denied("capacity_exhausted")
                allocations.append((bucket.id, amount))
                if bucket.unit == "microusd":
                    budget_scopes.add(bucket.scope)
            if policy.kind == "paid" and not {"task", "project", "global"} <= budget_scopes:
                raise Denied("missing_budget_scope")
            ticket = Ticket(id=uuid4().hex, state="reserved")
            connection.execute(
                """INSERT INTO reservations
                (id, project, task, request_key, fingerprint, resource, policy, state,
                 created_ms, expires_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ticket.id,
                    request.project,
                    request.task,
                    request.key,
                    fingerprint(request),
                    request.resource,
                    policy.model_dump_json(),
                    ticket.state,
                    now_ms,
                    request.expires_ms,
                ),
            )
            for bucket_id, amount in allocations:
                connection.execute(
                    "INSERT INTO allocations VALUES (?, ?, ?, NULL)",
                    (ticket.id, bucket_id, amount),
                )
                connection.execute("UPDATE buckets SET held=held+? WHERE id=?", (amount, bucket_id))
            connection.execute(
                "UPDATE reservations SET capability_revision=? WHERE id=?",
                (capability_revision, ticket.id),
            )
            return ticket

    @staticmethod
    def _check_capability(
        connection: sqlite3.Connection, resource: str, revision: str, now_ms: int, expires_ms: int
    ) -> None:
        from devhub.registry import CapabilityRecord

        row = connection.execute("SELECT * FROM capabilities WHERE id=?", (resource,)).fetchone()
        if row is None or row["revision"] != revision:
            raise Denied("capability_changed")
        record = CapabilityRecord.model_validate_json(row["spec"])
        if not record.observed_ms <= now_ms < record.valid_until_ms or (
            record.valid_until_ms < expires_ms
        ):
            raise Denied("stale_capability")

    @staticmethod
    def _owned(connection: sqlite3.Connection, ticket: str, project: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM reservations WHERE id=? AND project=?", (ticket, project)
        ).fetchone()
        if row is None:
            raise Denied("unknown_reservation")
        return cast(sqlite3.Row, row)

    def dispatch(self, ticket: str, request: Admission, *, now_ms: int) -> None:
        """Durably mark before any transport call. An uncertain marker means no retry."""
        with self.ledger.transaction() as connection:
            row = self._owned(connection, ticket, request.project)
            if row["fingerprint"] != fingerprint(request):
                raise Denied("request_mismatch")
            if row["state"] != "reserved" or not row["created_ms"] <= now_ms < row["expires_ms"]:
                raise Denied("not_dispatchable")
            if row["capability_revision"] is not None:
                self._check_capability(
                    connection,
                    row["resource"],
                    row["capability_revision"],
                    now_ms,
                    row["expires_ms"],
                )
            connection.execute("UPDATE reservations SET state='dispatched' WHERE id=?", (ticket,))

    def release(self, ticket: str, *, project: str) -> None:
        with self.ledger.transaction() as connection:
            row = self._owned(connection, ticket, project)
            if row["state"] == "released":
                return
            if row["state"] != "reserved":
                raise Denied("cannot_release_dispatched")
            for item in connection.execute(
                "SELECT * FROM allocations WHERE reservation=?", (ticket,)
            ).fetchall():
                connection.execute(
                    "UPDATE buckets SET held=held-? WHERE id=?", (item["amount"], item["bucket"])
                )
            connection.execute("UPDATE reservations SET state='released' WHERE id=?", (ticket,))

    def unknown(self, ticket: str, *, project: str) -> None:
        with self.ledger.transaction() as connection:
            row = self._owned(connection, ticket, project)
            if row["state"] not in {"dispatched", "unknown_usage"}:
                raise Denied("not_dispatched")
            connection.execute(
                "UPDATE reservations SET state='unknown_usage' WHERE id=?", (ticket,)
            )

    def settle(self, ticket: str, *, project: str, actual: dict[str, int]) -> None:
        """Only complete, trusted measurements reconcile a liability. Missing means unknown."""
        with self.ledger.transaction() as connection:
            row = self._owned(connection, ticket, project)
            items = connection.execute(
                "SELECT * FROM allocations WHERE reservation=?", (ticket,)
            ).fetchall()
            if set(actual) != {item["bucket"] for item in items} or any(
                type(value) is not int or not 0 <= value <= 1_000_000_000_000
                for value in actual.values()
            ):
                raise Denied("incomplete_usage")
            if row["state"] == "settled":
                if any(item["actual"] != actual[item["bucket"]] for item in items):
                    raise Denied("settlement_conflict")
                return
            if row["state"] not in {"dispatched", "unknown_usage"}:
                raise Denied("not_dispatched")
            for item in items:
                connection.execute(
                    "UPDATE buckets SET held=held-?, used=used+? WHERE id=?",
                    (item["amount"], actual[item["bucket"]], item["bucket"]),
                )
                connection.execute(
                    "UPDATE allocations SET actual=? WHERE reservation=? AND bucket=?",
                    (actual[item["bucket"]], ticket, item["bucket"]),
                )
            connection.execute("UPDATE reservations SET state='settled' WHERE id=?", (ticket,))
