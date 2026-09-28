"""Offline admission contracts; trusted configuration, never model-supplied policy."""

from typing import Annotated, Literal

from pydantic import Field, model_validator

from devhub.models import Contract, Identifier

Count = Annotated[int, Field(ge=0, le=1_000_000_000_000)]
Positive = Annotated[int, Field(ge=1, le=1_000_000_000_000)]
Timestamp = Annotated[int, Field(ge=0, le=9_000_000_000_000_000)]
Unit = Literal["requests", "input_tokens", "output_tokens", "total_tokens", "microusd"]


class Bucket(Contract):
    id: Identifier
    pool: Identifier
    unit: Unit
    scope: Literal["account", "global", "project", "task"] = "account"
    project: Identifier | None = None
    task: Identifier | None = None
    starts_ms: Timestamp
    ends_ms: Timestamp | None
    capacity: Count | None
    reserve_floor: Count = 0

    @model_validator(mode="after")
    def valid_window(self) -> "Bucket":
        if self.ends_ms is not None and self.ends_ms <= self.starts_ms:
            raise ValueError("window must have positive duration")
        if (self.scope in {"project", "task"}) != (self.project is not None):
            raise ValueError("project scope binding required")
        if (self.scope == "task") != (self.task is not None):
            raise ValueError("task scope binding required")
        return self


class Price(Contract):
    """Verified upper rates, integer micro-USD per million tokens plus fixed fee."""

    input_per_million: Count
    output_per_million: Count
    fixed_microusd: Count = 0
    valid_until_ms: Timestamp

    def ceiling(self, inputs: int, outputs: int) -> int:
        # Round each dimension up; never use binary floating point for budgets.
        return (
            (inputs * self.input_per_million + 999_999) // 1_000_000
            + (outputs * self.output_per_million + 999_999) // 1_000_000
            + self.fixed_microusd
        )


class ResourcePolicy(Contract):
    id: Identifier
    kind: Literal["free", "local", "paid"]
    synthetic: bool = True
    live_account: Identifier | None = None
    quota_scope: Identifier | None = None
    single_probe: bool = False
    buckets: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=32)]
    price: Price | None = None

    @model_validator(mode="after")
    def unique_buckets(self) -> "ResourcePolicy":
        if (
            not self.synthetic
            and self.kind != "local"
            and not (
                self.kind == "free" and self.single_probe and self.live_account and self.quota_scope
            )
        ):
            raise ValueError("live cloud requires a bounded free probe policy")
        if self.synthetic and (self.single_probe or self.live_account or self.quota_scope):
            raise ValueError("synthetic policies cannot authorize cloud execution")
        if len(set(self.buckets)) != len(self.buckets):
            raise ValueError("duplicate bucket")
        return self


class Admission(Contract):
    project: Identifier
    task: Identifier
    key: Identifier
    resource: Identifier
    payload_sha256: Annotated[str, Field(pattern="^[0-9a-f]{64}$")]
    input_tokens: Count
    max_output_tokens: Positive
    expires_ms: Timestamp


class SpendApproval(Contract):
    """Trusted operator input for simulation, not an MCP argument or live paid grant."""

    project: Identifier
    task: Identifier
    resource: Identifier
    max_microusd: Count
    expires_ms: Timestamp


class Ticket(Contract):
    id: Identifier
    state: Literal["reserved", "dispatched", "unknown_usage", "settled", "released"]
