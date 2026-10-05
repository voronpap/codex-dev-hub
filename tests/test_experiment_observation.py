"""Offline AUD-003 observation tests. No Codex, provider, or model execution."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from ledger_support import identity, initialized_ledger
from pydantic import ValidationError

from devhub.controller import ResourceController
from devhub.delegate import DelegationResult
from devhub.events import record_event
from devhub.experiment_bridge import MCPGate
from devhub.experiment_launch import DelegationObservation, delegation_complete_for_arm
from devhub.experiment_observation import (
    DELEGATION_RESULT_SCHEMA_SHA256,
    BArmDelegationObservationV2,
    ProviderResourceModelIdentityV1,
    ValidatedRequestIdentityV2,
    observe_b_arm_delegation,
)
from devhub.ledger import Ledger
from devhub.local import local_resource_id
from devhub.ollama import OllamaConfig
from devhub.qualification import (
    STAGE3G_OLLAMA_DIGEST,
    STAGE3G_OLLAMA_MODEL,
    STAGE3G_OLLAMA_VERSION,
)
from devhub.resources import Admission, Bucket, ResourcePolicy, Ticket

SESSION = "stage3g-session"
OLLAMA_CONFIG = OllamaConfig(
    endpoint="http://127.0.0.1:11434",
    model=STAGE3G_OLLAMA_MODEL,
    model_digest=STAGE3G_OLLAMA_DIGEST,
    version=STAGE3G_OLLAMA_VERSION,
    context_tokens=8192,
    max_output_tokens=256,
    safety_tokens=128,
    timeout_seconds=90,
)
RESOURCE = local_resource_id(OLLAMA_CONFIG)


@dataclass(frozen=True)
class AccountingScenario:
    ledger: Ledger
    core: ResourceController
    ticket: Ticket
    admission: Admission
    buckets: dict[str, str]


def expected_identity(**updates: str) -> ProviderResourceModelIdentityV1:
    values = {
        "provider": "ollama",
        "resource": RESOURCE,
        "model": STAGE3G_OLLAMA_MODEL,
        "ollama_version": STAGE3G_OLLAMA_VERSION,
        "model_digest": STAGE3G_OLLAMA_DIGEST,
    }
    values.update(updates)
    return ProviderResourceModelIdentityV1.model_validate(values)


def request_identity(**updates: str) -> ValidatedRequestIdentityV2:
    values = {
        "session_id": SESSION,
        "project": SESSION,
        "task_id": SESSION,
        "request_key": SESSION,
    }
    values.update(updates)
    return ValidatedRequestIdentityV2.model_validate(values)


def accounting(tmp_path: Path, *, project: str = SESSION) -> AccountingScenario:
    ledger = initialized_ledger(tmp_path / "ledger.db", identity(project))
    core = ResourceController(ledger, allow_local_execution=True)
    buckets: dict[str, str] = {}
    for unit in ("requests", "input_tokens", "output_tokens", "total_tokens"):
        bucket_id = f"b-{unit.replace('_', '-')}"
        buckets[unit] = bucket_id
        core.register_bucket(
            Bucket(
                id=bucket_id,
                pool=bucket_id,
                unit=unit,
                starts_ms=0,
                ends_ms=1000,
                capacity=1000,
            )
        )
    core.register_policy(
        ResourcePolicy(
            id=RESOURCE,
            kind="local",
            synthetic=False,
            buckets=tuple(buckets.values()),
        )
    )
    admission = Admission(
        project=project,
        task=project,
        key=project,
        resource=RESOURCE,
        payload_sha256="a" * 64,
        input_tokens=10,
        max_output_tokens=20,
        expires_ms=100,
    )
    ticket = core.reserve(admission, now_ms=1)
    return AccountingScenario(ledger, core, ticket, admission, buckets)


def settle(item: AccountingScenario) -> None:
    item.core.dispatch(item.ticket.id, item.admission, now_ms=2)
    item.core.settle(
        item.ticket.id,
        project=item.admission.project,
        actual={
            item.buckets["requests"]: 1,
            item.buckets["input_tokens"]: 10,
            item.buckets["output_tokens"]: 5,
            item.buckets["total_tokens"]: 15,
        },
    )


def handoff(reservation: str, **updates: object) -> DelegationResult:
    values: dict[str, object] = {
        "status": "completed",
        "reason": "completed",
        "provider": "ollama",
        "model": STAGE3G_OLLAMA_MODEL,
        "actual_input_tokens": 10,
        "actual_output_tokens": 5,
        "accounting_reference": reservation,
        "execution": "completed",
        "accounting": "settled",
        "output_validation": "passed",
        "citations_validation": "passed",
        "retries": 0,
        "fallback": False,
    }
    values.update(updates)
    return DelegationResult.model_validate(values)


def observe(
    item: AccountingScenario,
    *,
    call_count: int = 1,
    request: ValidatedRequestIdentityV2 | None = None,
    response_kind: str = "structured_result",
    result: DelegationResult | None = None,
    schema_hash: str | None = DELEGATION_RESULT_SCHEMA_SHA256,
    expected: ProviderResourceModelIdentityV1 | None = None,
    observed_version: str = STAGE3G_OLLAMA_VERSION,
    observed_model: str = STAGE3G_OLLAMA_MODEL,
    observed_digest: str = STAGE3G_OLLAMA_DIGEST,
) -> BArmDelegationObservationV2:
    return observe_b_arm_delegation(
        item.ledger,
        session_id=SESSION,
        call_count=call_count,
        request_identity=request_identity() if request is None else request,
        response_kind=response_kind,  # type: ignore[arg-type]
        handoff_schema_sha256=schema_hash,
        handoff=handoff(item.ticket.id) if result is None else result,
        expected_provider_resource_model=expected or expected_identity(),
        observed_ollama_version=observed_version,
        observed_model=observed_model,
        observed_model_digest=observed_digest,
    )


def test_fully_valid_b_arm_observation_uses_authoritative_ledger(tmp_path: Path) -> None:
    item = accounting(tmp_path)
    settle(item)

    result = observe(item)

    assert result.delegation_success is True
    assert result.failure_reason is None
    assert result.accounting_complete is True
    assert result.provider_execution_observed is True
    assert tuple(event.transition for event in result.authoritative_accounting_events) == (
        "reserved",
        "dispatched",
        "settled",
    )
    assert result.authoritative_reservation_snapshot is not None
    assert result.authoritative_reservation_snapshot.request_key == SESSION


def test_expected_resource_uses_local_runtime_derivation() -> None:
    assert RESOURCE.startswith("ollama-")
    assert len(RESOURCE) == len("ollama-") + 32


@pytest.mark.parametrize("call_count", [0, 2])
def test_call_count_must_be_exactly_one(tmp_path: Path, call_count: int) -> None:
    item = accounting(tmp_path)
    settle(item)
    assert observe(item, call_count=call_count).delegation_success is False


@pytest.mark.parametrize(
    "response_kind",
    ["mcp_error", "missing_structured_content", "malformed_structured_content"],
)
def test_invalid_mcp_response_never_succeeds(tmp_path: Path, response_kind: str) -> None:
    item = accounting(tmp_path)
    settle(item)
    result = observe(
        item,
        response_kind=response_kind,
        result=handoff(item.ticket.id),
        schema_hash=None,
    )
    assert result.delegation_success is False
    assert result.failure_reason == f"response_{response_kind}"


@pytest.mark.parametrize("field", ["session_id", "project", "task_id", "request_key"])
def test_request_and_session_identity_must_match(tmp_path: Path, field: str) -> None:
    item = accounting(tmp_path)
    settle(item)
    assert observe(item, request=request_identity(**{field: "other"})).delegation_success is False


def test_missing_request_identity_is_fail_closed(tmp_path: Path) -> None:
    item = accounting(tmp_path)
    settle(item)
    result = observe_b_arm_delegation(
        item.ledger,
        session_id=SESSION,
        call_count=1,
        request_identity=None,
        response_kind="structured_result",
        handoff_schema_sha256=DELEGATION_RESULT_SCHEMA_SHA256,
        handoff=handoff(item.ticket.id),
        expected_provider_resource_model=expected_identity(),
        observed_ollama_version=STAGE3G_OLLAMA_VERSION,
        observed_model=STAGE3G_OLLAMA_MODEL,
        observed_model_digest=STAGE3G_OLLAMA_DIGEST,
    )
    assert result.failure_reason == "request_identity_missing"


def test_missing_or_nonexistent_accounting_reference_fails(tmp_path: Path) -> None:
    item = accounting(tmp_path)
    settle(item)
    missing = handoff(item.ticket.id).model_copy(update={"accounting_reference": None})
    assert observe(item, result=missing).failure_reason == "accounting_reference_missing"
    unknown = handoff("f" * 32)
    assert observe(item, result=unknown).failure_reason == "reservation_not_found"


def test_reservation_belonging_to_another_session_fails(tmp_path: Path) -> None:
    item = accounting(tmp_path, project="other-session")
    settle(item)
    result = observe(item, result=handoff(item.ticket.id))
    assert result.failure_reason == "reservation_identity_mismatch"


def test_reserved_only_and_released_are_incomplete(tmp_path: Path) -> None:
    reserved = accounting(tmp_path / "reserved")
    assert observe(reserved).accounting_complete is False
    released = accounting(tmp_path / "released")
    released.core.release(released.ticket.id, project=SESSION)
    result = observe(released)
    assert result.accounting_complete is False
    assert result.delegation_success is False


def test_unknown_usage_is_ambiguous_and_never_complete(tmp_path: Path) -> None:
    item = accounting(tmp_path)
    item.core.dispatch(item.ticket.id, item.admission, now_ms=2)
    item.core.unknown(item.ticket.id, project=SESSION)
    result = observe(item)
    assert result.provider_execution_observed is None
    assert result.accounting_complete is False
    assert result.delegation_success is False


def test_duplicate_dispatch_event_is_rejected(tmp_path: Path) -> None:
    item = accounting(tmp_path)
    settle(item)
    with item.ledger.transaction() as connection:
        record_event(connection, item.ticket.id, "dispatched")
    result = observe(item)
    assert result.accounting_complete is False
    assert result.delegation_success is False


def test_settled_with_incomplete_usage_is_rejected(tmp_path: Path) -> None:
    item = accounting(tmp_path)
    settle(item)
    with item.ledger.transaction() as connection:
        connection.execute(
            "UPDATE allocations SET actual=NULL WHERE reservation=? AND bucket=?",
            (item.ticket.id, item.buckets["output_tokens"]),
        )
    result = observe(item)
    assert result.accounting_complete is False
    assert result.delegation_success is False


@pytest.mark.parametrize(
    "change",
    [
        {"observed_version": "0.35.0"},
        {"observed_model": "other-model"},
        {"observed_digest": "b" * 64},
    ],
)
def test_qualified_runtime_identity_must_match(tmp_path: Path, change: dict[str, str]) -> None:
    item = accounting(tmp_path)
    settle(item)
    assert observe(item, **change).delegation_success is False


def test_expected_resource_identity_must_match_authoritative_reservation(tmp_path: Path) -> None:
    item = accounting(tmp_path)
    settle(item)
    result = observe(item, expected=expected_identity(resource="ollama-other"))
    assert result.failure_reason == "provider_resource_model_mismatch"


@pytest.mark.parametrize(
    "change",
    [
        {"provider": "other"},
        {"model": "other-model"},
        {"actual_input_tokens": 11},
        {"actual_output_tokens": 6},
        {"output_validation": "failed"},
        {"citations_validation": "failed"},
    ],
)
def test_handoff_identity_usage_and_validation_must_match(
    tmp_path: Path, change: dict[str, object]
) -> None:
    item = accounting(tmp_path)
    settle(item)
    assert observe(item, result=handoff(item.ticket.id, **change)).delegation_success is False


@pytest.mark.parametrize("field,value", [("retries", 1), ("fallback", True)])
def test_retry_or_fallback_cannot_count_as_success(
    tmp_path: Path, field: str, value: object
) -> None:
    item = accounting(tmp_path)
    settle(item)
    invalid = handoff(item.ticket.id).model_copy(update={field: value})
    assert observe(item, result=invalid).delegation_success is False


def test_bridge_claim_cannot_override_disagreeing_ledger(tmp_path: Path) -> None:
    item = accounting(tmp_path)
    claimed = handoff(item.ticket.id)
    result = observe(item, result=claimed)
    assert claimed.accounting == "settled"
    assert result.authoritative_reservation_snapshot is not None
    assert result.authoritative_reservation_snapshot.state == "reserved"
    assert result.delegation_success is False


def test_success_fields_are_derived_not_caller_controlled(tmp_path: Path) -> None:
    item = accounting(tmp_path)
    settle(item)
    raw = observe(item).model_dump(mode="json")
    raw["delegation_success"] = False
    with pytest.raises(ValidationError):
        BArmDelegationObservationV2.model_validate(raw)


def test_arm_b_cannot_use_legacy_call_count_observation(tmp_path: Path) -> None:
    item = accounting(tmp_path)
    settle(item)
    strict = observe(item)
    legacy = DelegationObservation(delegate_called=True, count=1, handoff=strict.handoff)
    assert delegation_complete_for_arm("A", legacy) is True
    assert delegation_complete_for_arm("B", legacy) is False
    assert delegation_complete_for_arm("B", strict) is True


def test_bridge_classifies_missing_malformed_and_error_responses() -> None:
    def call(gate: MCPGate) -> None:
        gate.request(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/call",
                    "params": {
                        "name": "devhub_delegate",
                        "arguments": {
                            "schema_version": 1,
                            "project": SESSION,
                            "task_id": SESSION,
                            "request_key": SESSION,
                            "instructions": "synthetic",
                            "acceptance_criteria": ["synthetic"],
                            "query": "synthetic",
                            "privacy": "local_only",
                            "allow_cloud": False,
                            "require_citations": True,
                        },
                    },
                }
            ).encode()
        )

    cases = (
        ({"jsonrpc": "2.0", "id": 7, "error": {"code": -1}}, "mcp_error"),
        (
            {"jsonrpc": "2.0", "id": 7, "result": {"isError": "true"}},
            "malformed_structured_content",
        ),
        ({"jsonrpc": "2.0", "id": 7, "result": {"content": []}}, "missing_structured_content"),
        (
            {"jsonrpc": "2.0", "id": 7, "result": {"structuredContent": {"bad": True}}},
            "malformed_structured_content",
        ),
    )
    for response, expected in cases:
        gate = MCPGate(SESSION)
        call(gate)
        gate.response(json.dumps(response).encode())
        assert gate.response_kind == expected
        assert gate.handoff is None


def test_bridge_rejects_multiple_responses_for_one_call() -> None:
    gate = MCPGate(SESSION)
    gate.request(
        json.dumps(
            {
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "devhub_delegate",
                    "arguments": {
                        "schema_version": 1,
                        "project": SESSION,
                        "task_id": SESSION,
                        "request_key": SESSION,
                        "instructions": "synthetic",
                        "acceptance_criteria": ["synthetic"],
                        "query": "synthetic",
                        "privacy": "local_only",
                        "allow_cloud": False,
                        "require_citations": True,
                    },
                },
            }
        ).encode()
    )
    response = json.dumps({"id": 7, "error": {"code": -1}}).encode()
    gate.response(response)
    with pytest.raises(ValueError, match="Multiple"):
        gate.response(response)
    assert gate.violation is True


def test_strict_handoff_schema_rejects_retry_and_fallback() -> None:
    with pytest.raises(ValidationError):
        handoff("a" * 32, retries=1)
    with pytest.raises(ValidationError):
        handoff("a" * 32, fallback=True)
