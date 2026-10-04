"""Derived observability only; no ledger, provider, policy or benchmark writes."""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from devhub.models import Contract

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
