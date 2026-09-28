"""Trusted Free qualification and durable one-shot counting, not a billing API."""

import sqlite3
from typing import Annotated, Literal

from pydantic import Field, model_validator

from devhub.brain_models import Digest
from devhub.controller import Denied
from devhub.ledger import Ledger
from devhub.models import Contract
from devhub.resources import Admission, Count, Timestamp


class FreeQualification(Contract):
    project_number: Annotated[str, Field(pattern=r"^[0-9]{6,20}$")]
    project_id: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{4,62}$")]
    model: Annotated[str, Field(pattern=r"^[a-zA-Z0-9._-]{1,128}$")]
    country: Literal["Ukraine"]
    tier: Literal["Free", "unknown", "paid"] = "unknown"
    billing: Literal["disabled", "unknown", "enabled"] = "unknown"
    source: Literal["authenticated_ai_studio"]
    observed_ms: Timestamp
    valid_until_ms: Timestamp
    # A reviewed model-specific pricing page, never inferred from models.list.
    pricing_source: Literal["https://ai.google.dev/gemini-api/docs/pricing"]
    standard_text_input_free: bool = False
    standard_text_output_free: bool = False
    count_tokens_free: bool = False
    terms_source: Literal["https://ai.google.dev/gemini-api/terms"]
    public_data_use_accepted: bool = False
    requests_per_minute: Count | None = None
    input_tokens_per_minute: Count | None = None
    requests_per_day: Count | None = None
    # UI historical peaks are NOT current remaining capacity.
    remaining_requests: None = None
    remaining_input_tokens: None = None

    @model_validator(mode="after")
    def short_lived(self) -> "FreeQualification":
        if not 0 < self.valid_until_ms - self.observed_ms <= 3_600_000:
            raise ValueError("qualification lifetime must be at most one hour")
        return self

    def check(self, now_ms: int) -> None:
        if not self.observed_ms <= now_ms < self.valid_until_ms:
            raise Denied("gemini_qualification_expired")
        if not (
            self.tier == "Free"
            and self.billing == "disabled"
            and self.standard_text_input_free
            and self.standard_text_output_free
            and self.count_tokens_free
            and self.public_data_use_accepted
        ):
            raise Denied("gemini_free_not_verified")
        if any(
            value is not None and value == 0
            for value in (
                self.requests_per_minute,
                self.input_tokens_per_minute,
                self.requests_per_day,
            )
        ):
            raise Denied("gemini_quota_exhausted")


def claim_count(
    ledger: Ledger, qualification: FreeQualification, request_hash: Digest, now_ms: int
) -> None:
    qualification.check(now_ms)
    with ledger.transaction() as connection:
        if connection.execute(
            "SELECT 1 FROM gemini_preflights WHERE project=?", (qualification.project_number,)
        ).fetchone():
            raise Denied("gemini_count_permit_consumed")
        connection.execute(
            "INSERT INTO gemini_preflights VALUES (?, ?, ?, NULL)",
            (qualification.project_number, qualification.model_dump_json(), request_hash),
        )


def finish_count(ledger: Ledger, project: str, request_hash: str, tokens: int) -> None:
    with ledger.transaction() as connection:
        changed = connection.execute(
            "UPDATE gemini_preflights SET tokens=? WHERE project=? AND request_hash=? "
            "AND tokens IS NULL",
            (tokens, project, request_hash),
        ).rowcount
        if changed != 1:
            raise Denied("gemini_count_binding_invalid")


def check_gemini(
    connection: sqlite3.Connection, scope: str | None, request: Admission, now_ms: int
) -> None:
    row = connection.execute(
        "SELECT spec,tokens FROM gemini_preflights WHERE project=?", (scope,)
    ).fetchone()
    if row is None or row[1] is None:
        raise Denied("gemini_count_required")
    qualification = FreeQualification.model_validate_json(row[0])
    qualification.check(now_ms)
    if row[1] != request.input_tokens:
        raise Denied("gemini_count_binding_invalid")
    limit = qualification.input_tokens_per_minute
    if limit is not None and request.input_tokens > limit:
        raise Denied("gemini_input_quota_exhausted")
    # Unknown remaining quota stays unknown. Only one explicit probe is admitted.
