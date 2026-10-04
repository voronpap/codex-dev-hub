"""Derived observability only; no ledger, provider, policy or benchmark writes."""

from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field, model_validator

from devhub.models import Contract

if TYPE_CHECKING:
    from devhub.delegate import DelegationResult

Count = Annotated[int, Field(ge=0)]
Ref = Annotated[str, Field(min_length=1, max_length=512)]
FooterMode = Literal["off", "compact", "verbose"]


class TokenUsage(Contract):
    input_tokens: Count | None = None
    output_tokens: Count | None = None
    cached_input_tokens: Count | None = None
    # Cached input is a subset, never added again to input + output.
    evidence_ref: Ref
    comparison_key: Ref
    metric: Literal["codex_input_plus_output"] = "codex_input_plus_output"

    @property
    def total(self) -> int | None:
        if self.input_tokens is None or self.output_tokens is None:
            return None
        return self.input_tokens + self.output_tokens

    @model_validator(mode="after")
    def cached_subset(self) -> "TokenUsage":
        if (
            self.cached_input_tokens is not None
            and self.input_tokens is not None
            and self.cached_input_tokens > self.input_tokens
        ):
            raise ValueError("cached input must be a subset of input")
        return self


class Baseline(Contract):
    kind: Literal["exact", "estimated"]
    tokens: Count
    metric: Literal["codex_input_plus_output"] = "codex_input_plus_output"
    comparison_key: Ref
    evidence_ref: Ref
    source: Literal["paired_benchmark", "accepted_historical_pair", "reviewed_estimator"]
    estimator_version: Ref | None = None
    source_data_ref: Ref | None = None
    limitations: Ref | None = None

    @model_validator(mode="after")
    def provenance(self) -> "Baseline":
        if self.kind == "exact" and self.source == "reviewed_estimator":
            raise ValueError("estimator cannot establish exact baseline")
        if self.kind == "estimated" and (
            self.source != "reviewed_estimator"
            or not self.estimator_version
            or not self.source_data_ref
            or not self.limitations
        ):
            raise ValueError("estimated baseline requires reviewed estimator provenance")
        return self


class Savings(Contract):
    kind: Literal["exact", "estimated"]
    percent: Annotated[float, Field(allow_inf_nan=False, le=100)]
    metric: Literal["codex_input_plus_output_reduction"] = "codex_input_plus_output_reduction"
    baseline_ref: Ref
    actual_ref: Ref


class ApiCost(Contract):
    kind: Literal["measured", "estimated"]
    microusd: Count
    evidence_ref: Ref


class RouteStep(Contract):
    provider: str
    model: str | None = None


class UsageSummaryV1(Contract):
    scope: Literal["delegation_task"] = "delegation_task"
    route: tuple[RouteStep, ...] = ()
    route_complete: bool = False
    codex_usage: TokenUsage | None = None
    delegated_input: Count | None = None
    delegated_output: Count | None = None
    delegated_total: Count | None = None
    baseline: Baseline | None = None
    savings: Savings | None = None
    latency_ms: Count | None = None
    latency_scope: Literal["delegation_result"] = "delegation_result"
    provider_api_cost: ApiCost | None = None
    semantic_acceptance: bool | None = None
    output_validation: Literal["passed", "failed", "not_checked"] = "not_checked"
    citations_validation: Literal["passed", "failed", "not_checked"] = "not_checked"
    accounting: str
    evidence_refs: tuple[str, ...] = ()


def derive_usage(
    result: "DelegationResult",
    *,
    codex_usage: TokenUsage | None = None,
    baseline: Baseline | None = None,
    provider_api_cost: ApiCost | None = None,
) -> UsageSummaryV1:
    """Trusted producers supply reviewed evidence; MCP callers cannot supply it.

    comparison_key binds task/protocol/token convention, not just task class.
    This adapter does not authenticate arbitrary external evidence references.
    """
    savings = None
    if (
        codex_usage is not None
        and baseline is not None
        and codex_usage.total is not None
        and baseline.tokens > 0
        and baseline.metric == codex_usage.metric
        and baseline.comparison_key == codex_usage.comparison_key
    ):
        savings = Savings(
            kind=baseline.kind,
            percent=100.0 * (1 - codex_usage.total / baseline.tokens),
            baseline_ref=baseline.evidence_ref,
            actual_ref=codex_usage.evidence_ref,
        )
    observed_send = result.execution != "not_sent" and result.provider is not None
    route = (
        (RouteStep(provider=result.provider, model=result.model),)
        if observed_send and result.provider is not None
        else ()
    )
    # Local API charge only, after actual complete accounted usage. Never total cost.
    if (
        provider_api_cost is None
        and result.provider == "ollama"
        and observed_send
        and result.accounting == "settled"
        and result.accounting_reference is not None
        and result.actual_input_tokens is not None
        and result.actual_output_tokens is not None
    ):
        provider_api_cost = ApiCost(
            kind="measured", microusd=0, evidence_ref="accounting:" + result.accounting_reference
        )
    total = None
    if result.actual_input_tokens is not None and result.actual_output_tokens is not None:
        total = result.actual_input_tokens + result.actual_output_tokens
    return UsageSummaryV1(
        route=route,
        route_complete=False,
        codex_usage=codex_usage,
        delegated_input=result.actual_input_tokens,
        delegated_output=result.actual_output_tokens,
        delegated_total=total,
        baseline=baseline,
        savings=savings,
        latency_ms=result.latency_ms,
        provider_api_cost=provider_api_cost,
        semantic_acceptance=result.semantic_acceptance,
        output_validation=result.output_validation,
        citations_validation=result.citations_validation,
        accounting=result.accounting,
        evidence_refs=tuple(x for x in (result.accounting_reference, result.package_hash) if x),
    )
