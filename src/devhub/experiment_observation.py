"""Fail-closed Stage 3G B-arm delegation observation.

The MCP bridge supplies transport facts.  The resource ledger supplies accounting
authority.  A successful observation is derived from both; callers cannot submit a
success flag.
"""

from __future__ import annotations

from typing import Annotated, Literal, cast

from pydantic import Field, JsonValue, computed_field

from devhub.benchmark import Digest, canonical, digest
from devhub.delegate import DelegationResult
from devhub.events import AccountingEvent
from devhub.ledger import Ledger
from devhub.models import Contract, Identifier
from devhub.resources import Bucket, ResourcePolicy, Unit

DELEGATION_RESULT_SCHEMA_SHA256 = digest(
    canonical(cast(JsonValue, DelegationResult.model_json_schema()))
)

ResponseKind = Literal[
    "none",
    "mcp_error",
    "missing_structured_content",
    "malformed_structured_content",
    "structured_result",
]


class ValidatedRequestIdentityV2(Contract):
    session_id: Identifier
    project: Identifier
    task_id: Identifier
    request_key: Identifier


class ProviderResourceModelIdentityV1(Contract):
    provider: str = Field(min_length=1, max_length=64)
    resource: Identifier
    model: str = Field(min_length=1, max_length=256)
    ollama_version: str = Field(min_length=1, max_length=64)
    model_digest: Digest


class AuthoritativeAllocationV2(Contract):
    bucket: Identifier
    unit: Unit
    reserved: Annotated[int, Field(ge=0)]
    actual: Annotated[int, Field(ge=0)] | None


class AuthoritativeReservationSnapshotV2(Contract):
    reservation_id: Identifier
    project: Identifier
    task_id: Identifier
    request_key: Identifier
    resource: Identifier
    state: Literal["reserved", "dispatched", "unknown_usage", "settled", "released"]
    policy_kind: Literal["free", "local", "paid"]
    synthetic: bool
    allocations: tuple[AuthoritativeAllocationV2, ...]


class BArmDelegationObservationV2(Contract):
    """Mechanically derived B-arm result; semantic acceptance remains separate."""

    kind: Literal["b_arm_delegation_observation_v2"] = "b_arm_delegation_observation_v2"
    observation_version: Literal[2] = 2
    session_id: Identifier
    call_count: Annotated[int, Field(ge=0, le=64)]
    validated_request_identity: ValidatedRequestIdentityV2 | None = None
    response_kind: ResponseKind = "none"
    handoff_schema_sha256: Digest | None = None
    handoff: DelegationResult | None = None
    reservation_id: Identifier | None = None
    authoritative_reservation_snapshot: AuthoritativeReservationSnapshotV2 | None = None
    authoritative_accounting_events: tuple[AccountingEvent, ...] = ()
    expected_provider_resource_model: ProviderResourceModelIdentityV1
    observed_provider_resource_model: ProviderResourceModelIdentityV1 | None = None
    semantic_acceptance: None = None

    def _exact_accounting_chain(self) -> bool:
        snapshot = self.authoritative_reservation_snapshot
        events = self.authoritative_accounting_events
        if snapshot is None or snapshot.state != "settled":
            return False
        if tuple(event.transition for event in events) != ("reserved", "dispatched", "settled"):
            return False
        if any(
            (event.project, event.task, event.reservation, event.resource)
            != (snapshot.project, snapshot.task_id, snapshot.reservation_id, snapshot.resource)
            or event.synthetic != snapshot.synthetic
            for event in events
        ):
            return False
        expected_reserved = {item.bucket: (item.reserved, None) for item in snapshot.allocations}
        expected_settled = {
            item.bucket: (item.reserved, item.actual) for item in snapshot.allocations
        }
        event_allocations = tuple(
            {item.bucket: (item.reserved, item.actual) for item in event.allocations}
            for event in events
        )
        return (
            bool(expected_settled)
            and event_allocations == (expected_reserved, expected_reserved, expected_settled)
            and all(item.actual is not None for item in snapshot.allocations)
        )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def accounting_complete(self) -> bool:
        return self._exact_accounting_chain()

    @computed_field  # type: ignore[prop-decorator]
    @property
    def provider_execution_observed(self) -> bool | None:
        transitions = tuple(event.transition for event in self.authoritative_accounting_events)
        if self.accounting_complete:
            return True
        if "dispatched" in transitions or "unknown_usage" in transitions:
            return None
        return False

    def _failure_reason(self) -> str | None:
        if self.call_count != 1:
            return "delegate_call_count_not_one"
        request = self.validated_request_identity
        if request is None:
            return "request_identity_missing"
        if (
            request.session_id != self.session_id
            or request.project != self.session_id
            or request.task_id != self.session_id
            or request.request_key != self.session_id
        ):
            return "request_identity_mismatch"
        if self.response_kind != "structured_result":
            return f"response_{self.response_kind}"
        if self.handoff_schema_sha256 != DELEGATION_RESULT_SCHEMA_SHA256:
            return "handoff_schema_mismatch"
        handoff = self.handoff
        if handoff is None:
            return "handoff_missing"
        if handoff.status != "completed":
            return "handoff_not_completed"
        if handoff.accounting_reference is None:
            return "accounting_reference_missing"
        if self.reservation_id != handoff.accounting_reference:
            return "accounting_reference_mismatch"
        snapshot = self.authoritative_reservation_snapshot
        if snapshot is None:
            return "reservation_not_found"
        if (
            snapshot.reservation_id != self.reservation_id
            or snapshot.project != self.session_id
            or snapshot.task_id != self.session_id
            or snapshot.request_key != self.session_id
        ):
            return "reservation_identity_mismatch"
        if snapshot.policy_kind != "local" or snapshot.synthetic:
            return "reservation_policy_mismatch"
        if not self.accounting_complete:
            return "accounting_incomplete"
        if self.observed_provider_resource_model != self.expected_provider_resource_model:
            return "provider_resource_model_mismatch"
        if (
            handoff.provider != self.expected_provider_resource_model.provider
            or handoff.model != self.expected_provider_resource_model.model
        ):
            return "handoff_provider_or_model_mismatch"
        if handoff.execution != "completed" or handoff.accounting != "settled":
            return "handoff_execution_or_accounting_incomplete"
        units = {item.unit: item.actual for item in snapshot.allocations}
        if (
            len(snapshot.allocations) != 4
            or set(units) != {"requests", "input_tokens", "output_tokens", "total_tokens"}
            or handoff.actual_input_tokens is None
            or handoff.actual_output_tokens is None
            or units.get("input_tokens") != handoff.actual_input_tokens
            or units.get("output_tokens") != handoff.actual_output_tokens
            or units.get("total_tokens")
            != handoff.actual_input_tokens + handoff.actual_output_tokens
            or units.get("requests") != 1
        ):
            return "usage_mismatch_or_incomplete"
        if handoff.output_validation != "passed":
            return "output_validation_failed"
        if handoff.citations_validation != "passed":
            return "citations_validation_failed"
        if handoff.retries != 0:
            return "retry_observed"
        if handoff.fallback is not False:
            return "fallback_observed"
        return None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def delegation_success(self) -> bool:
        return self._failure_reason() is None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def failure_reason(self) -> str | None:
        return self._failure_reason()


def _authoritative_snapshot(
    ledger: Ledger, reservation_id: str
) -> tuple[AuthoritativeReservationSnapshotV2 | None, tuple[AccountingEvent, ...]]:
    with ledger.transaction() as connection:
        row = connection.execute(
            "SELECT * FROM reservations WHERE id=?", (reservation_id,)
        ).fetchone()
        if row is None:
            return None, ()
        policy = ResourcePolicy.model_validate_json(row["policy"])
        allocations = tuple(
            AuthoritativeAllocationV2(
                bucket=item["bucket"],
                unit=Bucket.model_validate_json(item["spec"]).unit,
                reserved=item["amount"],
                actual=item["actual"],
            )
            for item in connection.execute(
                """SELECT allocations.*, buckets.spec
                   FROM allocations JOIN buckets ON buckets.id=allocations.bucket
                   WHERE reservation=? ORDER BY allocations.bucket""",
                (reservation_id,),
            )
        )
        snapshot = AuthoritativeReservationSnapshotV2(
            reservation_id=row["id"],
            project=row["project"],
            task_id=row["task"],
            request_key=row["request_key"],
            resource=row["resource"],
            state=row["state"],
            policy_kind=policy.kind,
            synthetic=policy.synthetic,
            allocations=allocations,
        )
        events = tuple(
            AccountingEvent.model_validate_json(item["payload"])
            for item in connection.execute(
                "SELECT payload FROM events WHERE reservation=? ORDER BY sequence",
                (reservation_id,),
            )
        )
    return snapshot, events


def observe_b_arm_delegation(
    ledger: Ledger,
    *,
    session_id: str,
    call_count: int,
    request_identity: ValidatedRequestIdentityV2 | None,
    response_kind: ResponseKind,
    handoff_schema_sha256: str | None,
    handoff: DelegationResult | None,
    expected_provider_resource_model: ProviderResourceModelIdentityV1,
    observed_ollama_version: str,
    observed_model: str,
    observed_model_digest: str,
) -> BArmDelegationObservationV2:
    """Join bridge facts to the exact authoritative reservation and full event history."""

    reservation_id = handoff.accounting_reference if handoff is not None else None
    snapshot: AuthoritativeReservationSnapshotV2 | None = None
    events: tuple[AccountingEvent, ...] = ()
    if reservation_id is not None:
        snapshot, events = _authoritative_snapshot(ledger, reservation_id)
    observed_identity = None
    if handoff is not None and snapshot is not None and handoff.provider and handoff.model:
        observed_identity = ProviderResourceModelIdentityV1(
            provider=handoff.provider,
            resource=snapshot.resource,
            model=observed_model,
            ollama_version=observed_ollama_version,
            model_digest=observed_model_digest,
        )
    return BArmDelegationObservationV2(
        session_id=session_id,
        call_count=call_count,
        validated_request_identity=request_identity,
        response_kind=response_kind,
        handoff_schema_sha256=handoff_schema_sha256,
        handoff=handoff,
        reservation_id=reservation_id,
        authoritative_reservation_snapshot=snapshot,
        authoritative_accounting_events=events,
        expected_provider_resource_model=expected_provider_resource_model,
        observed_provider_resource_model=observed_identity,
    )
