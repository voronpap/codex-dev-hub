"""Trusted operator issuance for one follow-up; never issued by MCP or catalog import."""

import sqlite3
from typing import Annotated, Literal

from pydantic import Field, model_validator

from devhub.brain_models import Digest
from devhub.controller import Denied
from devhub.gemini_gate import FreeQualification
from devhub.ledger import Ledger
from devhub.models import Contract, Identifier
from devhub.resources import Admission, Timestamp


class FollowupPermit(Contract):
    id: Annotated[str, Field(pattern=r"^gemini-followup-[A-Za-z0-9_-]{1,48}$")]
    project: Identifier
    task: Identifier
    request_key: Identifier
    qualification: FreeQualification
    request_hash: Digest
    operator_review: Digest
    operator_approved: Literal[True]
    issued_ms: Timestamp
    expires_ms: Timestamp

    @model_validator(mode="after")
    def bounded(self) -> "FollowupPermit":
        if not 0 < self.expires_ms - self.issued_ms <= 900_000:
            raise ValueError("follow-up lifetime must be at most fifteen minutes")
        if not (
            self.qualification.observed_ms <= self.issued_ms
            and self.expires_ms <= self.qualification.valid_until_ms
        ):
            raise ValueError("permit must fit qualification lifetime")
        return self

    def check(self, now_ms: int) -> None:
        self.qualification.check(now_ms)
        if not self.issued_ms <= now_ms < self.expires_ms:
            raise Denied("gemini_followup_expired")


def issue_permit(ledger: Ledger, permit: FollowupPermit, now_ms: int) -> None:
    """Call only from the trusted operator boundary after explicit review/approval.

    This function is deliberately not exposed through MCP or runtime config loading.
    It grants one follow-up to a failed legacy count in the SAME ledger, not an
    unlimited series of permits. Old claims are neither updated nor deleted.
    """
    permit.check(now_ms)
    project_number = permit.qualification.project_number
    with ledger.transaction() as connection:
        previous = connection.execute(
            "SELECT spec,tokens FROM gemini_preflights WHERE project=?", (project_number,)
        ).fetchone()
        if previous is None or previous[1] is not None:
            raise Denied("gemini_failed_legacy_count_required")
        old = FreeQualification.model_validate_json(previous[0])
        if old.project_id != permit.qualification.project_id:
            raise Denied("gemini_followup_account_mismatch")
        if connection.execute(
            "SELECT 1 FROM gemini_followup_permits WHERE id=? OR project_number=?",
            (permit.id, project_number),
        ).fetchone():
            raise Denied("gemini_followup_already_issued")
        connection.execute(
            "INSERT INTO gemini_followup_permits VALUES (?, ?, ?, NULL, NULL)",
            (permit.id, project_number, permit.model_dump_json()),
        )


def claim_permit(
    ledger: Ledger,
    permit_id: str,
    qualification: FreeQualification,
    request_hash: str,
    project: str,
    task: str,
    request_key: str,
    now_ms: int,
) -> None:
    with ledger.transaction() as connection:
        row = connection.execute(
            "SELECT spec,claimed_ms FROM gemini_followup_permits WHERE id=?", (permit_id,)
        ).fetchone()
        if row is None:
            raise Denied("gemini_followup_not_issued")
        permit = FollowupPermit.model_validate_json(row[0])
        permit.check(now_ms)
        if (
            permit.qualification != qualification
            or permit.request_hash != request_hash
            or (permit.project, permit.task, permit.request_key) != (project, task, request_key)
        ):
            raise Denied("gemini_followup_binding_invalid")
        if row[1] is not None:
            raise Denied("gemini_count_permit_consumed")
        connection.execute(
            "UPDATE gemini_followup_permits SET claimed_ms=? WHERE id=?", (now_ms, permit_id)
        )


def finish_permit(ledger: Ledger, permit_id: str, request_hash: str, tokens: int) -> None:
    with ledger.transaction() as connection:
        row = connection.execute(
            "SELECT spec FROM gemini_followup_permits WHERE id=?", (permit_id,)
        ).fetchone()
        if row is None or FollowupPermit.model_validate_json(row[0]).request_hash != request_hash:
            raise Denied("gemini_count_binding_invalid")
        if type(tokens) is not int or tokens <= 0:
            raise Denied("gemini_count_binding_invalid")
        changed = connection.execute(
            "UPDATE gemini_followup_permits SET tokens=? WHERE id=? "
            "AND claimed_ms IS NOT NULL AND tokens IS NULL",
            (tokens, permit_id),
        ).rowcount
        if changed != 1:
            raise Denied("gemini_count_binding_invalid")


def check_permit(
    connection: sqlite3.Connection, permit_id: str, request: Admission, now_ms: int
) -> None:
    row = connection.execute(
        "SELECT spec,tokens FROM gemini_followup_permits WHERE id=?", (permit_id,)
    ).fetchone()
    if row is None or row[1] is None:
        raise Denied("gemini_count_required")
    permit = FollowupPermit.model_validate_json(row[0])
    permit.check(now_ms)
    if (request.project, request.task, request.key) != (
        permit.project,
        permit.task,
        permit.request_key,
    ) or row[1] != request.input_tokens:
        raise Denied("gemini_count_binding_invalid")
    limit = permit.qualification.input_tokens_per_minute
    if limit is not None and request.input_tokens > limit:
        raise Denied("gemini_input_quota_exhausted")
