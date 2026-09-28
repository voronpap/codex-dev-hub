"""Deterministic, offline eligibility and admission; never executes a provider."""

from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import Field, model_validator

from devhub.controller import Denied, ResourceController
from devhub.models import Contract, Identifier
from devhub.registry import CapabilityRecord, CapabilityRegistry
from devhub.resources import Admission, Count, Positive, SpendApproval, Ticket, Timestamp


class RouteRequest(Contract):
    project: Identifier
    task: Identifier
    key: Identifier
    payload_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    input_tokens: Count
    max_output_tokens: Positive
    expires_ms: Timestamp
    task_class: Identifier
    privacy: Literal["local_only", "cloud_allowed"] = "local_only"
    requires_json: bool = False


class RoutingPolicy(Contract):
    """Trusted task-class policy. Provider implementation order is irrelevant."""

    kind_order: tuple[Literal["free", "local", "paid"], ...] = ("free", "local", "paid")
    preferred_resources: tuple[Identifier, ...] = ()
    max_attempts: Annotated[int, Field(ge=1, le=3)] = 3

    @model_validator(mode="after")
    def unique_order(self) -> "RoutingPolicy":
        if set(self.kind_order) != {"free", "local", "paid"} or len(self.kind_order) != 3:
            raise ValueError("kind order must be a permutation")
        if len(set(self.preferred_resources)) != len(self.preferred_resources):
            raise ValueError("duplicate resource preference")
        return self


@dataclass(frozen=True)
class Decision:
    resource: str
    reason: str


@dataclass(frozen=True)
class RouteResult:
    ticket: Ticket | None
    admission: Admission | None
    decisions: tuple[Decision, ...]


def exclusion(record: CapabilityRecord, request: RouteRequest, now_ms: int) -> str | None:
    if not record.observed_ms <= now_ms < record.valid_until_ms or (
        record.valid_until_ms < request.expires_ms
    ):
        return "stale_capability"
    if request.privacy == "local_only" and record.locality != "local":
        return "privacy_denied"
    if record.healthy is not True:
        return "health_unknown_or_unavailable"
    if record.supports_text is not True or (
        request.requires_json and record.supports_json is not True
    ):
        return "capability_unknown_or_unsupported"
    if request.task_class not in record.task_classes:
        return "unqualified_task_class"
    if (
        record.context_tokens is None
        or record.max_output_tokens is None
        or (
            request.input_tokens + request.max_output_tokens > record.context_tokens
            or request.max_output_tokens > record.max_output_tokens
        )
    ):
        return "context_or_output_limit"
    return None


class Router:
    def __init__(self, core: ResourceController) -> None:
        self.core = core
        self.registry = CapabilityRegistry(core.ledger)

    def route(
        self,
        request: RouteRequest,
        *,
        now_ms: int,
        policy: RoutingPolicy | None = None,
        approval: SpendApproval | None = None,
    ) -> RouteResult:
        policy = policy or RoutingPolicy()
        preference = {name: rank for rank, name in enumerate(policy.preferred_resources)}
        records = sorted(
            self.registry.records(),
            key=lambda record: (
                policy.kind_order.index(record.kind),
                preference.get(record.resource, len(preference)),
                record.resource,
            ),
        )
        decisions: list[Decision] = []
        ticket = None
        admission = None
        for record in records:
            reason = exclusion(record, request, now_ms)
            if reason is not None:
                decisions.append(Decision(record.resource, reason))
                continue
            if ticket is not None:
                decisions.append(Decision(record.resource, "not_selected"))
                continue
            candidate = Admission.model_validate(
                request.model_dump(exclude={"task_class", "privacy", "requires_json"})
                | {"resource": record.resource}
            )
            try:
                ticket = self.core.reserve(
                    candidate,
                    now_ms=now_ms,
                    approval=approval,
                    capability_revision=record.revision,
                    attempt_limit=policy.max_attempts,
                )
                admission = candidate
                decisions.append(Decision(record.resource, "selected"))
            except Denied as error:
                decisions.append(Decision(record.resource, str(error)))
        return RouteResult(ticket, admission, tuple(decisions))
