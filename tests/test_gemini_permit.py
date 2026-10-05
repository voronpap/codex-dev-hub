import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from ledger_support import identity, initialized_ledger
from test_gemini import qualification
from test_groq import CANARY, cloud  # noqa: F401

from devhub.brain_models import sha256
from devhub.cloud import CloudRuntime, GeminiCloudConfig
from devhub.cloud_types import HTTPResult
from devhub.controller import Denied
from devhub.gemini import GeminiConfig, GeminiError
from devhub.gemini_gate import claim_count
from devhub.gemini_permit import FollowupPermit, claim_permit, finish_permit, issue_permit
from devhub.ledger import Ledger
from devhub.local import now_ms


def permit(qual, **changes):
    return FollowupPermit(
        **(
            dict(
                id="gemini-followup-test",
                project="p",
                task="probe",
                request_key="one",
                qualification=qual,
                request_hash="a" * 64,
                operator_review="b" * 64,
                operator_approved=True,
                issued_ms=now_ms(),
                expires_ms=now_ms() + 120000,
            )
            | changes
        )
    )


def test_issue_requires_same_ledger_failed_history_and_never_reissues(tmp_path):
    ledger = initialized_ledger(tmp_path / "ledger.db")
    qual = qualification()
    grant = permit(qual)
    with pytest.raises(Denied, match="legacy_count_required"):
        issue_permit(ledger, grant, now_ms())
    claim_count(ledger, qual, "c" * 64, now_ms())
    with ledger.transaction() as connection:
        before = tuple(connection.execute("SELECT * FROM gemini_preflights").fetchone())
    issue_permit(ledger, grant, now_ms())
    with pytest.raises(Denied, match="already_issued"):
        issue_permit(ledger, grant.model_copy(update={"id": "gemini-followup-third"}), now_ms())
    with ledger.transaction() as connection:
        assert tuple(connection.execute("SELECT * FROM gemini_preflights").fetchone()) == before


def test_followup_count_concurrency_restart_and_exact_binding(tmp_path):
    path = tmp_path / "ledger.db"
    ledger = initialized_ledger(path)
    qual = qualification()
    grant = permit(qual)
    claim_count(ledger, qual, "c" * 64, now_ms())
    issue_permit(ledger, grant, now_ms())
    for args in [
        (qual, "d" * 64, "p", "probe", "one"),
        (qual, "a" * 64, "other", "probe", "one"),
        (qual.model_copy(update={"model": "another"}), "a" * 64, "p", "probe", "one"),
    ]:
        with pytest.raises(Denied, match="binding_invalid"):
            claim_permit(ledger, grant.id, *args, now_ms())
    barrier = Barrier(4)

    def contender(_):
        own = Ledger(path, identity())
        barrier.wait()
        try:
            claim_permit(own, grant.id, qual, "a" * 64, "p", "probe", "one", now_ms())
            return True
        except Denied:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(contender, range(4))) == 1
    with pytest.raises(Denied, match="consumed"):
        claim_permit(
            Ledger(path, identity()),
            grant.id,
            qual,
            "a" * 64,
            "p",
            "probe",
            "one",
            now_ms(),
        )
    with pytest.raises(Denied, match="binding_invalid"):
        finish_permit(ledger, grant.id, "d" * 64, 100)


def test_migration_preserves_failed_claim_and_does_not_issue_grant(tmp_path, monkeypatch):
    from devhub import ledger as module

    path = tmp_path / "upgrade.db"
    with monkeypatch.context() as context:
        context.setattr(module, "MIGRATIONS", module.MIGRATIONS[:5])
        old = Ledger.initialize(path, identity())
        claim_count(old, qualification(), "c" * 64, now_ms())
        with old.transaction() as connection:
            before = tuple(connection.execute("SELECT * FROM gemini_preflights").fetchone())
    upgraded = Ledger(path, identity())
    with upgraded.transaction() as connection:
        assert tuple(connection.execute("SELECT * FROM gemini_preflights").fetchone()) == before
        assert connection.execute("SELECT COUNT(*) FROM gemini_followup_permits").fetchone()[0] == 0


def test_expired_or_unapproved_permit_cannot_authorize(tmp_path):
    from pydantic import ValidationError

    qual = qualification()
    with pytest.raises(ValidationError):
        permit(qual, operator_approved=False)
    with pytest.raises(ValidationError):
        permit(qual, expires_ms=now_ms() + 900001)
    grant = permit(qual)
    ledger = initialized_ledger(tmp_path / "ledger.db")
    claim_count(ledger, qual, "c" * 64, now_ms())
    issue_permit(ledger, grant, now_ms())
    with pytest.raises(Denied, match="expired"):
        claim_permit(ledger, grant.id, qual, "a" * 64, "p", "probe", "one", grant.expires_ms)


def test_review_proposal_is_inactive_and_exact_wire_is_reproducible():
    from pydantic import ValidationError

    from devhub.cloud_export import ReleasedPayload, _seal
    from devhub.context import canonical
    from devhub.gemini import GeminiAdapter

    proposal = json.loads(
        (Path(__file__).parent.parent / "docs/evidence/stage3e-followup-proposal.json").read_text(
            encoding="utf-8"
        )
    )
    assert proposal["operator_approved"] is False and proposal["issued_ms"] is None
    with pytest.raises(ValidationError):
        FollowupPermit.model_validate(proposal)
    config = GeminiConfig(
        qualification=qualification(model=proposal["model"]),
        model=proposal["model"],
        profile=proposal["profile"],
        followup_permit_id=proposal["permit_id"],
        single_probe=True,
        probe_expires_ms=now_ms() + 120000,
    )
    text = proposal["released_text"]
    digest = sha256(text.encode())
    body = GeminiAdapter(config).request_body(
        ReleasedPayload(text, digest, "public", _seal(digest, "public"))
    )
    assert body.decode() == proposal["generate_body_utf8"]
    assert sha256(body) == proposal["request_hash"]
    wrapped = canonical(
        {"generateContentRequest": json.loads(body) | {"model": "models/" + proposal["model"]}}
    )
    assert wrapped == proposal["count_body_utf8"]
    assert sha256(wrapped.encode()) == proposal["count_body_sha256"]


@pytest.mark.parametrize("outcome", ["success", "count_404", "count_crash", "send_timeout"])
def test_followup_shared_pipeline_and_failures(cloud, monkeypatch, outcome):  # noqa: F811
    old, task, _, _ = cloud
    qual = qualification()
    grant = permit(qual)
    config = GeminiCloudConfig(
        project=old.config.project,
        root=old.config.root,
        state_root=str(old.state.parent / "followup-state"),
        ledger_identity=identity(instance_id="2123456789abcdef0123456789abcdef"),
        approved_paths=old.config.approved_paths,
        export=old.config.export,
        gemini=GeminiConfig(
            qualification=qual,
            model=qual.model,
            profile="text_json_thinking_minimal",
            followup_permit_id=grant.id,
            single_probe=True,
            probe_expires_ms=grant.expires_ms,
        ),
    )
    initialized_ledger(Path(config.state_root) / "ledger.db", config.ledger_identity)
    runtime = CloudRuntime(config)
    claim_count(runtime.core.ledger, qual, "c" * 64, now_ms())
    original_body = runtime.adapter.request_body

    # Trusted operator issuance simulated offline after seeing the exact exported body.
    # Production run/config loading never calls issue_permit.
    def reviewed_body(payload):
        body = original_body(payload)
        issue_permit(
            runtime.core.ledger, grant.model_copy(update={"request_hash": sha256(body)}), now_ms()
        )
        monkeypatch.setattr(runtime.adapter, "request_body", original_body)
        return body

    monkeypatch.setattr(runtime.adapter, "request_body", reviewed_body)
    calls = []

    def http(path, body=None):
        calls.append((path, body))
        if body is None:
            return HTTPResult(
                200,
                {},
                dict(
                    name="models/example-text",
                    inputTokenLimit=1048576,
                    outputTokenLimit=65536,
                    supportedGenerationMethods=["countTokens", "generateContent"],
                ),
                1,
            )
        assert CANARY not in body.decode()
        with runtime.core.ledger.transaction() as connection:
            row = connection.execute("SELECT claimed_ms FROM gemini_followup_permits").fetchone()
            assert row[0] is not None
            if path.endswith(":countTokens"):
                assert connection.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == 0
            else:
                assert (
                    connection.execute("SELECT state FROM reservations").fetchone()[0]
                    == "dispatched"
                )
        if path.endswith(":countTokens"):
            request = json.loads(body)["generateContentRequest"]
            assert request["generationConfig"]["thinkingConfig"] == {"thinkingLevel": "minimal"}
            if outcome == "count_crash":
                raise SystemExit("simulated process termination")
            return HTTPResult(404 if outcome == "count_404" else 200, {}, {"totalTokens": 100}, 1)
        if outcome == "send_timeout":
            raise GeminiError("send_outcome_unknown")
        return HTTPResult(
            200,
            {},
            dict(
                modelVersion="example-text",
                usageMetadata=dict(
                    promptTokenCount=100,
                    candidatesTokenCount=12,
                    thoughtsTokenCount=2,
                    totalTokenCount=114,
                ),
                candidates=[
                    dict(
                        finishReason="STOP",
                        content=dict(role="model", parts=[dict(text='{"summary":"Blue."}')]),
                    )
                ],
            ),
            1,
        )

    monkeypatch.setattr(runtime.adapter.http, "request", http)
    if outcome == "count_crash":
        with pytest.raises(SystemExit):
            runtime.run(task)
    else:
        result = runtime.run(task)
        assert (
            result.status
            == {"success": "completed", "count_404": "denied", "send_timeout": "unknown_usage"}[
                outcome
            ]
        )
    restarted = CloudRuntime(config)
    monkeypatch.setattr(restarted.adapter.http, "request", http)
    assert restarted.run(task).status == "denied"
    assert sum(path.endswith(":countTokens") for path, _ in calls) == 1
    assert sum(path.endswith(":generateContent") for path, _ in calls) == int(
        outcome in {"success", "send_timeout"}
    )
    with runtime.core.ledger.transaction() as connection:
        assert connection.execute("SELECT tokens FROM gemini_preflights").fetchone()[0] is None
        assert connection.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == int(
            outcome in {"success", "send_timeout"}
        )
