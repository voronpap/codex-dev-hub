import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest
from ledger_support import identity, initialized_ledger
from mcp import Client
from mcp.shared.exceptions import MCPError
from pydantic import ValidationError
from test_groq import CANARY, PUBLIC, cloud  # noqa: F401

from devhub.cloud import CloudRuntime, GeminiCloudConfig
from devhub.cloud_server import create_cloud_server
from devhub.cloud_types import HTTPResult
from devhub.controller import Denied, ResourceController
from devhub.events import EventOutbox
from devhub.gemini import GeminiConfig, GeminiError, GeminiHTTP, complete_usage, safe_headers
from devhub.gemini_gate import FreeQualification, claim_count
from devhub.local import now_ms


def qualification(**updates):
    stamp = now_ms()
    return FreeQualification.model_validate(
        dict(
            project_number="1234567890",
            project_id="synthetic-project",
            model="example-text",
            country="Ukraine",
            tier="Free",
            billing="disabled",
            source="authenticated_ai_studio",
            observed_ms=stamp - 1000,
            valid_until_ms=stamp + 300000,
            pricing_source="https://ai.google.dev/gemini-api/docs/pricing",
            standard_text_input_free=True,
            standard_text_output_free=True,
            count_tokens_free=True,
            terms_source="https://ai.google.dev/gemini-api/terms",
            public_data_use_accepted=True,
            requests_per_minute=10,
            input_tokens_per_minute=250000,
            requests_per_day=20,
        )
        | updates
    )


@pytest.fixture
def gemini_cloud(cloud, monkeypatch):  # noqa: F811
    groq, task, _, _ = cloud
    config = GeminiCloudConfig(
        project=groq.config.project,
        root=groq.config.root,
        state_root=str(groq.state.parent / "gemini-state"),
        ledger_identity=identity(instance_id="1123456789abcdef0123456789abcdef"),
        approved_paths=groq.config.approved_paths,
        export=groq.config.export,
        gemini=GeminiConfig(
            qualification=qualification(),
            model="example-text",
            profile="text_json_thinking_budget_zero",
            single_probe=True,
            probe_expires_ms=now_ms() + 300000,
        ),
    )
    initialized_ledger(Path(config.state_root) / "ledger.db", config.ledger_identity)
    runtime = CloudRuntime(config)
    calls, mode = [], {"value": "valid"}

    def http(path, body=None):
        calls.append((path, body))
        if body is None:
            return HTTPResult(
                200,
                {},
                {
                    "name": "models/example-text",
                    "inputTokenLimit": 1048576,
                    "outputTokenLimit": 65536,
                    "supportedGenerationMethods": ["countTokens", "generateContent"],
                },
                1,
            )
        assert CANARY not in body.decode() and str(Path(config.root)) not in body.decode()
        value = mode["value"]
        if path.endswith(":countTokens"):
            with runtime.core.ledger.transaction() as connection:
                assert (
                    connection.execute("SELECT COUNT(*) FROM gemini_preflights").fetchone()[0] == 1
                )
                assert connection.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == 0
            counted = json.loads(body)["generateContentRequest"]
            assert counted["model"] == "models/example-text"
            assert counted["systemInstruction"] and counted["generationConfig"]
            if value == "count_timeout":
                raise GeminiError("send_outcome_unknown")
            if value in {"count_failure", "count_missing"}:
                return HTTPResult(404 if value == "count_missing" else 429, {}, {}, 1)
            return HTTPResult(200, {}, {"totalTokens": 9000 if value == "too_large" else 100}, 1)
        assert path.endswith(":generateContent")
        with runtime.core.ledger.transaction() as connection:
            assert (
                connection.execute("SELECT state FROM reservations").fetchone()[0] == "dispatched"
            )
            assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2
        counted = json.loads(calls[-2][1])["generateContentRequest"]
        del counted["model"]
        assert counted == json.loads(body)
        if value == "timeout":
            raise GeminiError("send_outcome_unknown")
        if value == "crash":
            raise SystemExit("hard crash")
        if isinstance(value, int):
            return HTTPResult(
                value,
                {},
                {
                    "error": {
                        "message": "NEVER_RETAIN",
                        "details": [
                            {
                                "@type": "type.googleapis.com/google.rpc.RetryInfo",
                                "retryDelay": "12.5s",
                            },
                            {
                                "@type": "type.googleapis.com/google.rpc.QuotaFailure",
                                "violations": [{"subject": CANARY}],
                            },
                        ],
                    }
                },
                5,
            )
        result = {
            "modelVersion": "example-text",
            "usageMetadata": {
                "promptTokenCount": 100,
                "candidatesTokenCount": 12,
                "totalTokenCount": 112,
            },
            "candidates": [
                {
                    "finishReason": "STOP",
                    "content": {
                        "role": "model",
                        "parts": [{"text": '{"summary":"The lighthouse is blue."}'}],
                    },
                }
            ],
        }
        if value == "incomplete":
            del result["usageMetadata"]["candidatesTokenCount"]
        elif value == "thoughts":
            result["usageMetadata"].update(
                thoughtsTokenCount=7, totalTokenCount=119, cachedContentTokenCount=20
            )
        elif value == "bad_json":
            result["candidates"][0]["content"]["parts"][0]["text"] = "{"
        elif value == "blocked":
            result["candidates"][0]["finishReason"] = "SAFETY"
        elif value == "truncated":
            result["candidates"][0]["finishReason"] = "MAX_TOKENS"
        return HTTPResult(200, {}, result, 7)

    monkeypatch.setattr(runtime.adapter.http, "request", http)
    return runtime, task, calls, mode


def transitions(runtime):
    return [e.transition for e in EventOutbox(runtime.core.ledger).pending(project="p")]


def test_shared_path_exact_count_settlement_and_restart(gemini_cloud):
    runtime, task, calls, _ = gemini_cloud
    result = runtime.run(task)
    assert result.status == "completed"
    assert result.model_input_tokens_preflight == result.actual_model_input_tokens == 100
    assert result.offline_context_proxy != 100
    assert result.actual_model_output_tokens == 12
    assert result.provider_usage["thoughtsTokenCount"] is None
    assert result.quota is None and result.observed_rate_headers == {}
    assert result.semantic_acceptance is None
    assert transitions(runtime) == ["reserved", "dispatched", "settled"]
    assert len(calls) == 3
    assert CloudRuntime(runtime.config).run(task).reason == "request_already_attempted"


@pytest.mark.parametrize("setting", ["timeout", "incomplete", 401, 402, 403, 429, 500, 503, 302])
def test_ambiguous_generation_retains_liability(gemini_cloud, setting):
    runtime, task, calls, mode = gemini_cloud
    mode["value"] = setting
    result = runtime.run(task)
    assert result.status == "unknown_usage"
    assert transitions(runtime) == ["reserved", "dispatched", "unknown_usage"]
    assert len(calls) == 3
    assert CANARY not in result.model_dump_json() and "NEVER_RETAIN" not in result.model_dump_json()
    if setting == 429:
        assert result.provider_error == {
            "category": "rate_limit",
            "quota_failure": True,
            "retry_delay_ms": 12500,
        }


@pytest.mark.parametrize("setting", ["bad_json", "blocked", "truncated", "thoughts"])
def test_usage_settled_before_output_validation(gemini_cloud, setting):
    runtime, task, _, mode = gemini_cloud
    mode["value"] = setting
    result = runtime.run(task)
    assert transitions(runtime)[-1] == "settled"
    assert result.status == ("completed" if setting == "thoughts" else "failed")
    assert result.actual_model_output_tokens == (19 if setting == "thoughts" else 12)
    if setting == "thoughts":
        assert result.actual_model_input_tokens == 100  # cache is already included
        assert result.provider_usage["cachedContentTokenCount"] == 20


@pytest.mark.parametrize(
    "setting", ["count_timeout", "count_failure", "count_missing", "too_large"]
)
def test_count_failure_is_durable_without_inference_reservation(gemini_cloud, setting):
    runtime, task, calls, mode = gemini_cloud
    mode["value"] = setting
    result = runtime.run(task)
    assert result.status in {"denied", "context_insufficient"}
    assert len(calls) == 2 and not transitions(runtime)
    if setting == "count_missing":
        assert result.reason == "count_not_found" and result.preflight_http_status == 404
        assert result.preflight_latency_ms == 1 and result.count_response_hash
        assert result.offline_context_proxy > 0 and result.export_hash
    mode["value"] = "valid"
    assert runtime.run(task).reason == "gemini_count_permit_consumed"
    assert len(calls) == 3 and calls[-1][1] is None


def test_canary_rejected_before_any_adapter_content_or_count(gemini_cloud, monkeypatch):
    runtime, task, calls, _ = gemini_cloud
    Path(runtime.config.root, "guide.md").write_text(PUBLIC + CANARY + "\n", encoding="utf-8")
    monkeypatch.setattr(runtime.adapter, "prepare", lambda *_: pytest.fail("private adapter input"))
    assert runtime.run(task).reason == "cloud_source_not_approved"
    assert not calls
    with pytest.raises(Denied, match="cloud_export_required"):
        runtime.adapter.prepare = type(runtime.adapter).prepare.__get__(runtime.adapter)
        runtime.adapter.prepare({"text": CANARY, "privacy": "local_only"})


def test_redaction_before_count_and_local_provenance(gemini_cloud):
    from devhub.brain_models import sha256

    runtime, task, calls, _ = gemini_cloud
    text = PUBLIC + CANARY + "\n"
    Path(runtime.config.root, "guide.md").write_text(text, encoding="utf-8", newline="\n")
    grant = runtime.config.export.releases[0].model_copy(
        update={
            "source_sha256": sha256(text.encode()),
            "selected_sha256": sha256(text.encode()),
            "classification": "redacted",
            "public_lines": (1,),
        }
    )
    runtime.config = runtime.config.model_copy(
        update={"export": runtime.config.export.model_copy(update={"releases": (grant,)})}
    )
    assert runtime.run(task).status == "completed"
    assert all(CANARY not in body.decode() for _, body in calls if body)
    receipt = json.loads(next((runtime.state / "exports").glob("*.json")).read_text())
    assert receipt["provenance"][0]["public_lines"] == [1]


@pytest.mark.parametrize(
    "updates",
    [
        {"billing": "unknown"},
        {"billing": "enabled"},
        {"tier": "unknown"},
        {"tier": "paid"},
        {"standard_text_input_free": False},
        {"standard_text_output_free": False},
        {"count_tokens_free": False},
        {"public_data_use_accepted": False},
        {"requests_per_day": 0},
    ],
)
def test_unknown_paid_or_unapproved_free_fails_closed(updates):
    with pytest.raises(Denied):
        qualification(**updates).check(now_ms())


def test_expired_and_other_model_before_network(gemini_cloud):
    runtime, task, calls, _ = gemini_cloud
    runtime.adapter.config = runtime.adapter.config.model_copy(update={"model": "other"})
    assert runtime.run(task).reason == "gemini_qualification_model_mismatch"
    assert not calls
    with pytest.raises(Denied, match="expired"):
        qualification(observed_ms=0, valid_until_ms=100).check(now_ms())


def test_crash_after_dispatch_recovery_does_not_repeat(gemini_cloud):
    runtime, task, calls, mode = gemini_cloud
    mode["value"] = "crash"
    with pytest.raises(SystemExit):
        runtime.run(task)
    assert (
        ResourceController(runtime.core.ledger).recover(now_ms=now_ms() + 120000)["unknown_usage"]
        == 1
    )
    assert CloudRuntime(runtime.config).run(task).reason == "request_already_attempted"
    assert len(calls) == 3


def test_atomic_count_permit_shared_across_threads(gemini_cloud):
    runtime, _, _, _ = gemini_cloud
    barrier = Barrier(2)

    def claim(_):
        barrier.wait()
        try:
            claim_count(runtime.core.ledger, qualification(), "a" * 64, now_ms())
            return "claimed"
        except Denied as error:
            return str(error)

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(claim, range(2))) == ["claimed", "gemini_count_permit_consumed"]


def test_stale_source_after_count_released_before_generation(gemini_cloud, monkeypatch):
    runtime, task, calls, _ = gemini_cloud
    original = runtime.adapter.prepare

    def change(payload):
        prepared = original(payload)
        Path(runtime.config.root, "guide.md").write_text(PUBLIC + CANARY, encoding="utf-8")
        return prepared

    monkeypatch.setattr(runtime.adapter, "prepare", change)
    assert runtime.run(task).reason == "context_insufficient"
    assert transitions(runtime) == ["reserved", "released"] and len(calls) == 2


def test_immutable_counted_body(gemini_cloud, monkeypatch):
    runtime, task, calls, _ = gemini_cloud
    original = runtime.adapter.send
    monkeypatch.setattr(runtime.adapter, "send", lambda p: original(replace(p, body=p.body + b" ")))
    assert runtime.run(task).status == "unknown_usage" and len(calls) == 2


def test_mcp_strict_boundary(gemini_cloud):
    runtime, task, _, _ = gemini_cloud

    async def call():
        async with Client(create_cloud_server(runtime)) as client:
            args = json.loads(task.model_dump_json())
            with pytest.raises(MCPError):
                await client.call_tool("devhub_cloud_probe", args | {"api_key": "denied"})
            result = await client.call_tool("devhub_cloud_probe", args)
            assert result.structured_content["status"] == "completed"

    asyncio.run(call())


@pytest.mark.parametrize(
    "updates",
    [
        {"promptTokenCount": True},
        {"candidatesTokenCount": None},
        {"totalTokenCount": 99},
        {"thoughtsTokenCount": 2},
        {"cachedContentTokenCount": 101},
        {"toolUsePromptTokenCount": 1},
    ],
)
def test_incomplete_or_inconsistent_usage_never_becomes_zero(updates):
    usage = {"promptTokenCount": 100, "candidatesTokenCount": 12, "totalTokenCount": 112} | updates
    assert (
        complete_usage(
            HTTPResult(200, {}, {"modelVersion": "example-text", "usageMetadata": usage}, 0),
            "example-text",
        )
        is None
    )


@pytest.mark.windows_smoke
def test_transport_no_retries_redirect_proxy_secret_or_rotation(monkeypatch):
    import devhub.gemini as module

    key, calls = ["fake-secret-one"], []
    monkeypatch.setattr(module, "windows_user_key", lambda: key[0])

    class Connection:
        status = 302

        def __init__(self, host, **kwargs):
            assert host == "generativelanguage.googleapis.com"

        def request(self, method, path, body=None, headers=None):
            assert headers["x-goog-api-key"] == key[0] and key[0] not in path
            calls.append(path)

        def getresponse(self):
            return self

        def getheaders(self):
            return [("Location", "https://evil.invalid"), ("retry-after", key[0])]

        def read(self, _):
            return json.dumps({"message": key[0]}).encode()

        def close(self):
            pass

    monkeypatch.setattr(module.http.client, "HTTPSConnection", Connection)
    http = GeminiHTTP("example-text", 1)
    response = http.request("/v1beta/models/example-text")
    assert response.body is None and response.headers == {"retry-after": "invalid"}
    assert key[0] not in repr(response)
    key[0] = "fake-secret-two"
    with pytest.raises(GeminiError, match="credential_changed"):
        http.request("/v1beta/models/example-text:countTokens", b"{}")
    assert len(calls) == 1
    with pytest.raises(GeminiError, match="endpoint_denied"):
        http.request("https://evil.invalid")
    assert safe_headers([("x-ratelimit-remaining-tokens", "999")]) == {}


def test_secret_or_arbitrary_endpoint_not_config(gemini_cloud):
    config = gemini_cloud[0].config.gemini.model_dump()
    for update in (
        {"api_key": "no"},
        {"endpoint": "https://evil.invalid"},
        {"single_probe": False},
    ):
        with pytest.raises(ValidationError):
            GeminiConfig.model_validate(config | update)


def test_gemini_controller_uses_input_tpm_and_rechecks_qualification(gemini_cloud):
    from devhub.gemini_gate import finish_count
    from devhub.resources import Admission

    runtime, _, _, _ = gemini_cloud
    stamp = now_ms()
    proof = qualification(input_tokens_per_minute=100, valid_until_ms=stamp + 10000)
    claim_count(runtime.core.ledger, proof, "a" * 64, stamp)
    finish_count(runtime.core.ledger, proof.project_number, "a" * 64, 100)
    request = Admission(
        project="p",
        task="t",
        key="k",
        resource=runtime.resource,
        payload_sha256="b" * 64,
        input_tokens=100,
        max_output_tokens=96,
        expires_ms=stamp + 20000,
    )
    # 100 input + 96 output fits input TPM=100; Groq combined TPM semantics would fail.
    ticket = runtime.core.reserve(request, now_ms=stamp)
    with pytest.raises(Denied, match="gemini_qualification_expired"):
        runtime.core.dispatch(ticket.id, request, now_ms=proof.valid_until_ms)
    assert transitions(runtime) == ["reserved"]
    with pytest.raises(Denied, match="free_probe_already_consumed"):
        runtime.core.reserve(request.model_copy(update={"key": "another"}), now_ms=stamp)


def test_gemini_count_claim_survives_restart(gemini_cloud):
    runtime, _, _, _ = gemini_cloud
    claim_count(runtime.core.ledger, qualification(), "a" * 64, now_ms())
    restarted = CloudRuntime(runtime.config)
    with pytest.raises(Denied, match="gemini_count_permit_consumed"):
        claim_count(restarted.core.ledger, qualification(), "b" * 64, now_ms())
