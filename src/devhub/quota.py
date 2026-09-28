"""Observed Groq RPD/TPM, never inferred RPM/TPD or unlimited availability."""

import re
import sqlite3
from typing import Annotated, Literal

from pydantic import Field

from devhub.controller import Denied
from devhub.ledger import Ledger
from devhub.models import Contract, Identifier
from devhub.resources import Admission, Count, Timestamp


class ObservedWindow(Contract):
    limit: Count
    remaining: Count
    reset_after_ms: Annotated[int, Field(ge=1, le=172_800_000)]


class QuotaObservation(Contract):
    scope: Identifier
    observed_ms: Timestamp
    source: Literal["models_response", "inference_response"]
    requests_per_day: ObservedWindow | None = None
    tokens_per_minute: ObservedWindow | None = None
    requests_per_minute: None = None
    tokens_per_day: None = None
    retry_after_ms: Annotated[int, Field(ge=0, le=172_800_000)] | None = None
    malformed: bool = False


def duration(value: str) -> int:
    if not re.fullmatch(r"(?:\d+(?:\.\d+)?(?:ms|s|m|h|d))+", value):
        raise ValueError("invalid duration")
    result = sum(
        float(number) * {"ms": 1, "s": 1000, "m": 60000, "h": 3600000, "d": 86400000}[unit]
        for number, unit in re.findall(r"(\d+(?:\.\d+)?)(ms|s|m|h|d)", value)
    )
    if not 0 < result <= 172_800_000:
        raise ValueError("invalid duration")
    return max(1, int(result))


def observe(
    headers: dict[str, str],
    *,
    scope: str,
    now_ms: int,
    source: Literal["models_response", "inference_response"],
) -> QuotaObservation:
    normalized = {key.lower(): value for key, value in headers.items()}
    values: dict[str, ObservedWindow | None] = {}
    malformed = False
    for suffix, name in (("requests", "requests_per_day"), ("tokens", "tokens_per_minute")):
        fields = [
            normalized.get(f"x-ratelimit-{part}-{suffix}")
            for part in ("limit", "remaining", "reset")
        ]
        values[name] = None
        if all(value is None for value in fields):
            continue
        try:
            limit, remaining, reset = fields
            if limit is None or remaining is None or reset is None:
                raise ValueError("partial headers")
            if (
                not re.fullmatch(r"[0-9]{1,12}", limit)
                or not re.fullmatch(r"[0-9]{1,12}", remaining)
                or int(remaining) > int(limit)
            ):
                raise ValueError("invalid count")
            values[name] = ObservedWindow(
                limit=int(limit), remaining=int(remaining), reset_after_ms=duration(reset)
            )
        except ValueError:
            malformed = True
    retry = None
    if "retry-after" in normalized:
        value = normalized["retry-after"]
        if re.fullmatch(r"[0-9]{1,6}", value) and int(value) <= 172800:
            retry = int(value) * 1000
        else:
            malformed = True
    return QuotaObservation(
        scope=scope,
        observed_ms=now_ms,
        source=source,
        requests_per_day=values["requests_per_day"],
        tokens_per_minute=values["tokens_per_minute"],
        retry_after_ms=retry,
        malformed=malformed,
    )


def save_observation(ledger: Ledger, value: QuotaObservation) -> None:
    with ledger.transaction() as connection:
        old = connection.execute(
            "SELECT spec FROM quota_observations WHERE scope=?", (value.scope,)
        ).fetchone()
        if old is not None:
            previous = QuotaObservation.model_validate_json(old[0])
            if previous.observed_ms > value.observed_ms:
                raise Denied("quota_observation_out_of_order")
            # A header-less probe must not erase a previously observed restriction.
            if (
                value.source == "models_response"
                and not value.malformed
                and (
                    (previous.requests_per_day is not None and value.requests_per_day is None)
                    or (previous.tokens_per_minute is not None and value.tokens_per_minute is None)
                    or (
                        previous.retry_after_ms is not None
                        and value.retry_after_ms is None
                        and value.observed_ms < previous.observed_ms + previous.retry_after_ms
                    )
                    or (
                        previous.malformed
                        and value.requests_per_day is None
                        and value.tokens_per_minute is None
                    )
                )
            ):
                return
        connection.execute(
            "INSERT INTO quota_observations VALUES (?, ?) "
            "ON CONFLICT(scope) DO UPDATE SET spec=excluded.spec",
            (value.scope, value.model_dump_json()),
        )


def check_observation(
    connection: sqlite3.Connection, scope: str | None, request: Admission, now_ms: int
) -> None:
    row = connection.execute(
        "SELECT spec FROM quota_observations WHERE scope=?", (scope,)
    ).fetchone()
    if row is None:
        raise Denied("account_probe_required")
    observation = QuotaObservation.model_validate_json(row[0])
    age = now_ms - observation.observed_ms
    if not 0 <= age <= 60000 or observation.malformed:
        raise Denied("quota_observation_stale_or_invalid")
    if observation.retry_after_ms is not None and age < observation.retry_after_ms:
        raise Denied("provider_cooldown")
    for window, amount in (
        (observation.requests_per_day, 1),
        (observation.tokens_per_minute, request.input_tokens + request.max_output_tokens),
    ):
        if window is not None:
            if age >= window.reset_after_ms:
                raise Denied("quota_window_requires_probe")
            if amount > window.remaining:
                raise Denied("observed_quota_exhausted")
    # Missing dimensions stay unknown. Only the explicit, durable one-shot probe
    # policy permits this bootstrap; it is NOT a general cloud admission policy.
