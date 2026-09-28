import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from threading import Barrier

import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError
from pydantic import ValidationError
from test_brain import repo

from devhub.brain import ProjectBrain
from devhub.brain_models import sha256
from devhub.cloud import CloudConfig, CloudRuntime
from devhub.cloud_export import ExportPolicy, SourceRelease, task_release_hash
from devhub.cloud_server import create_cloud_server
from devhub.context_models import ContextTask
from devhub.controller import Denied, ResourceController
from devhub.events import EventOutbox
from devhub.groq import GroqConfig, GroqError, GroqHTTP, HTTPResult, safe_headers
from devhub.local import LocalTask, now_ms
from devhub.quota import observe, save_observation
from devhub.resources import Admission

PUBLIC = "The synthetic lighthouse is blue.\n"
CANARY = "PRIVATE_CANARY_NEVER_EXPORT_918f79"


@pytest.fixture
def cloud(tmp_path, monkeypatch):
    root = repo(tmp_path / "repo", {"guide.md": PUBLIC})
    task = LocalTask(
        task_id="probe",
        request_key="one",
        instructions="Summarize the source.",
        acceptance_criteria=("Mention the color.",),
        query="guide.md",
    )
    context_task = ContextTask(
        task_id=task.task_id,
        instructions=task.instructions,
        acceptance_criteria=task.acceptance_criteria,
    )
    scope = ProjectBrain(tmp_path / "scope", {"p": root}).scope("p")
    config = CloudConfig(
        project="p",
        root=str(root),
        state_root=str(tmp_path / "state"),
        approved_paths=("guide.md",),
        groq=GroqConfig(
            account="test-account",
            plan="Free",
            model="example/text-preview",
            profile_documentation="https://console.groq.com/docs/model/example/text-preview",
            supports_json=True,
            reasoning_effort="none",
            single_probe=True,
            probe_expires_ms=now_ms() + 300_000,
        ),
        export=ExportPolicy(
            approval_id="public-fixture",
            scope=scope,
            task_sha256=task_release_hash(context_task),
            releases=(
                SourceRelease(
                    path="guide.md",
                    source_sha256=sha256(PUBLIC.encode()),
                    selected_sha256=sha256(PUBLIC.encode()),
                    classification="public",
                    released_sha256=sha256(PUBLIC.encode()),
                ),
            ),
        ),
    )
    runtime = CloudRuntime(config)
    calls, mode = [], {"value": "valid", "headers": {}}

    def http(path, body=None):
        calls.append((path, body))
        if path == "/openai/v1/models":
            model = "other" if mode["value"] == "other_model" else config.groq.model
            return HTTPResult(
                200,
                mode["headers"],
                {
                    "data": [
                        {
                            "id": model,
                            "active": True,
                            "context_window": 131072,
                            "max_completion_tokens": 16384,
                        }
                    ]
                },
                3,
            )
        assert path == "/openai/v1/chat/completions"
        with runtime.core.ledger.transaction() as connection:
            assert (
                connection.execute("SELECT state FROM reservations").fetchone()[0] == "dispatched"
            )
            assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2
        decoded = json.loads(body)
        assert decoded["model"] == config.groq.model and decoded["n"] == 1
        assert decoded["stream"] is False
        assert CANARY not in body.decode() and str(root) not in body.decode()
        assert "project_private" not in body.decode() and "local_only" not in body.decode()
        value = mode["value"]
        if value == "timeout":
            raise GroqError("send_outcome_unknown")
        if value in {401, 403, 429, 500, 503, 302}:
            return HTTPResult(value, mode["headers"], {"error": {"message": "do not log me"}}, 4)
        result = {
            "model": config.groq.model,
            "usage": {"prompt_tokens": 113, "completion_tokens": 12, "total_tokens": 125},
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": '{"summary":"The lighthouse is blue."}',
                    },
                }
            ],
        }
        if value == "missing_usage":
            del result["usage"]["completion_tokens"]
        elif value == "inconsistent_usage":
            result["usage"]["total_tokens"] = 1
        elif value == "bool_usage":
            result["usage"]["prompt_tokens"] = True
        elif value == "wrong_usage_model":
            result["model"] = "different"
        elif value == "bad_output":
            result["choices"][0]["message"]["content"] = "{"
        elif value == "bad_shape":
            result["choices"][0]["message"]["content"] = '{"unexpected": "data"}'
        elif value == "bad_message":
            result["choices"][0]["message"] = []
        elif value == "truncated_output":
            result["choices"][0]["finish_reason"] = "length"
        elif value == "overshoot":
            result["usage"] = {"prompt_tokens": 5000, "completion_tokens": 12, "total_tokens": 5012}
        elif value == "invalid_envelope":
            result = None
        return HTTPResult(200, mode["headers"], result, 17)

    monkeypatch.setattr(runtime.adapter.http, "request", http)
    return runtime, task, calls, mode


def events(runtime):
    return EventOutbox(runtime.core.ledger).pending(project="p")


def test_complete_path_accounting_and_restart_no_replay(cloud):
    runtime, task, calls, _ = cloud
    result = runtime.run(task)
    assert result.status == "completed"
    assert result.provider_input_estimate > result.actual_model_input_tokens == 113
    assert result.offline_context_proxy != result.provider_input_estimate
    assert result.model_input_tokens_preflight is None
    assert result.semantic_acceptance is None
    assert result.quota.requests_per_day is None and result.quota.tokens_per_minute is None
    assert [event.transition for event in events(runtime)] == ["reserved", "dispatched", "settled"]
    assert all(not event.synthetic for event in events(runtime))
    assert runtime.run(task).reason == "request_already_attempted"
    assert CloudRuntime(runtime.config).run(task).reason == "request_already_attempted"
    assert len(calls) == 2
    receipt = json.loads(next((runtime.state / "exports").glob("*.json")).read_text())
    assert receipt["provenance"][0]["original"][0]["sensitivity"] == "project_private"
    assert receipt["provenance"][0]["released_sha256"] == sha256(PUBLIC.encode())


@pytest.mark.parametrize(
    "mode,reason",
    [
        ("timeout", "send_outcome_unknown"),
        ("missing_usage", "usage_incomplete"),
        ("inconsistent_usage", "usage_incomplete"),
        ("bool_usage", "usage_incomplete"),
        ("wrong_usage_model", "usage_incomplete"),
        ("invalid_envelope", "usage_incomplete"),
        (401, "auth"),
        (403, "entitlement"),
        (429, "rate_limit"),
        (500, "transient"),
        (503, "transient"),
        (302, "permanent"),
    ],
)
def test_ambiguous_and_http_errors_keep_liability(cloud, mode, reason):
    runtime, task, calls, setting = cloud
    setting["value"] = mode
    result = runtime.run(task)
    assert result.status == "unknown_usage" and result.reason == reason
    assert result.actual_model_input_tokens is None
    assert [event.transition for event in events(runtime)] == [
        "reserved",
        "dispatched",
        "unknown_usage",
    ]
    assert all(item.actual is None for item in events(runtime)[-1].allocations)
    assert sum(path.endswith("completions") for path, _ in calls) == 1


@pytest.mark.parametrize(
    "mode", ["bad_output", "bad_shape", "bad_message", "truncated_output", "overshoot"]
)
def test_valid_usage_settles_even_when_output_fails(cloud, mode):
    runtime, task, _, setting = cloud
    setting["value"] = mode
    result = runtime.run(task)
    assert result.status == "failed"
    assert result.actual_model_input_tokens is not None
    assert events(runtime)[-1].transition == "settled"


def test_private_canary_fails_before_adapter_receives_payload(cloud, monkeypatch):
    runtime, task, calls, _ = cloud
    Path(runtime.config.root, "guide.md").write_text(
        PUBLIC + CANARY + "\n", encoding="utf-8", newline="\n"
    )

    def forbidden(*_args):
        pytest.fail("unapproved source reached Groq adapter")

    monkeypatch.setattr(runtime.adapter, "prepare", forbidden)
    assert runtime.run(task).reason == "cloud_source_not_approved"
    assert not calls and not events(runtime)


def test_explicit_redaction_removes_canary_and_keeps_local_provenance(cloud):
    runtime, task, calls, _ = cloud
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
    assert CANARY not in calls[-1][1].decode()
    receipt = json.loads(next((runtime.state / "exports").glob("*.json")).read_text())
    assert receipt["provenance"][0]["classification"] == "redacted"
    assert receipt["provenance"][0]["public_lines"] == [1]
    assert receipt["provenance"][0]["original"][0]["source_sha256"] == sha256(text.encode())


def test_task_and_project_binding_and_no_raw_package_adapter_input(cloud):
    runtime, task, calls, _ = cloud
    assert (
        runtime.run(task.model_copy(update={"instructions": CANARY})).reason
        == "cloud_task_or_project_not_approved"
    )
    runtime.config = runtime.config.model_copy(
        update={
            "export": runtime.config.export.model_copy(
                update={"scope": runtime.scope.model_copy(update={"project_id": "other"})}
            )
        }
    )
    assert runtime.run(task).reason == "cloud_task_or_project_not_approved"
    with pytest.raises(Denied, match="cloud_export_required"):
        runtime.adapter.prepare({"privacy": "local_only", "text": CANARY})
    assert not calls


def test_stale_context_after_reservation_released_no_send(cloud, monkeypatch):
    runtime, task, calls, _ = cloud
    original = runtime.builder.validate_package
    validations = 0

    def stale(*args, **kwargs):
        nonlocal validations
        validations += 1
        return original(*args, **kwargs) if validations == 1 else False

    monkeypatch.setattr(runtime.builder, "validate_package", stale)
    assert runtime.run(task).reason == "context_insufficient"
    assert [event.transition for event in events(runtime)] == ["reserved", "released"]
    assert len(calls) == 1


def test_model_check_and_full_request_estimate_before_reservation(cloud):
    runtime, task, calls, setting = cloud
    setting["value"] = "other_model"
    assert runtime.run(task).reason == "model_unavailable"
    setting["value"] = "valid"
    runtime.adapter.config = runtime.adapter.config.model_copy(update={"probe_token_cap": 1024})
    assert runtime.run(task).status == "context_insufficient"
    assert not events(runtime)
    assert all(body is None for _, body in calls)


def rate_headers(remaining="7999"):
    return {
        "x-ratelimit-limit-requests": "1000",
        "x-ratelimit-remaining-requests": "999",
        "x-ratelimit-reset-requests": "1h2m3.5s",
        "x-ratelimit-limit-tokens": "8000",
        "x-ratelimit-remaining-tokens": remaining,
        "x-ratelimit-reset-tokens": "7.66s",
    }


def test_observed_rate_headers_are_correct_dimensions():
    observation = observe(rate_headers(), scope="scope", now_ms=1000, source="models_response")
    assert observation.requests_per_day.limit == 1000
    assert observation.requests_per_day.reset_after_ms == 3723500
    assert observation.tokens_per_minute.remaining == 7999
    assert observation.tokens_per_minute.reset_after_ms == 7660
    assert observation.requests_per_minute is None and observation.tokens_per_day is None
    assert not observation.malformed


@pytest.mark.parametrize(
    "headers,reason",
    [
        (rate_headers("0"), "observed_quota_exhausted"),
        ({"x-ratelimit-remaining-tokens": "8000"}, "quota_observation_stale_or_invalid"),
        ({"retry-after": "30"}, "provider_cooldown"),
        (rate_headers("9000"), "quota_observation_stale_or_invalid"),
    ],
)
def test_quota_headers_constrain_controller_before_send(cloud, headers, reason):
    runtime, task, calls, setting = cloud
    setting["headers"] = headers
    assert reason in runtime.run(task).reason
    assert not events(runtime) and len(calls) == 1


def test_atomic_one_shot_across_requests_and_default_disabled(cloud):
    runtime, _, _, _ = cloud
    now = now_ms()
    save_observation(
        runtime.core.ledger,
        observe({}, scope=runtime.config.groq.quota_scope, now_ms=now, source="models_response"),
    )

    def request(index):
        return Admission(
            project="p",
            task=f"task{index}",
            key=f"key{index}",
            resource=runtime.resource,
            payload_sha256="a" * 64,
            input_tokens=100,
            max_output_tokens=10,
            expires_ms=now + 1000,
        )

    with pytest.raises(Denied, match="free_probe_disabled"):
        ResourceController(runtime.core.ledger).reserve(request(0), now_ms=now)
    barrier = Barrier(2)

    def reserve(index):
        barrier.wait()
        try:
            return runtime.core.reserve(request(index), now_ms=now).state
        except Denied as error:
            return str(error)

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(reserve, range(2))) == ["free_probe_already_consumed", "reserved"]


def test_mcp_boundary_strict_and_complete_path(cloud):
    runtime, task, _, _ = cloud

    async def run():
        async with Client(create_cloud_server(runtime)) as client:
            args = json.loads(task.model_dump_json())
            with pytest.raises(MCPError):
                await client.call_tool("devhub_cloud_probe", args | {"api_key": "forbidden"})
            result = await client.call_tool("devhub_cloud_probe", args)
            assert not result.is_error and result.structured_content["status"] == "completed"

    asyncio.run(run())


@pytest.mark.parametrize("status", [200, 302, 401, 429, 500])
def test_http_one_attempt_no_redirect_no_secret_echo(monkeypatch, status):
    import devhub.groq as groq

    key = "fake-test-credential-unique"
    calls = []
    monkeypatch.setattr(groq, "windows_user_key", lambda: key)

    class Connection:
        def __init__(self, host, **kwargs):
            assert host == "api.groq.com"

        def request(self, method, path, body=None, headers=None):
            assert headers["Authorization"] == "Bearer " + key
            calls.append((method, path))

        def getresponse(self):
            return self

        def getheaders(self):
            return [("Location", "https://evil.invalid"), ("x-ratelimit-limit-tokens", key)]

        def read(self, limit):
            return json.dumps({"secret_echo": key}).encode()

        def close(self):
            pass

    Connection.status = status
    monkeypatch.setattr(groq.http.client, "HTTPSConnection", Connection)
    response = GroqHTTP(2).request("/openai/v1/models")
    assert response.status == status and response.body is None
    assert response.headers == {"x-ratelimit-limit-tokens": "invalid"}
    assert key not in repr(response) and len(calls) == 1
    with pytest.raises(GroqError, match="endpoint_denied"):
        GroqHTTP(2).request("https://evil.invalid")


def test_config_rejects_key_paid_or_unbounded_probe(cloud):
    config = cloud[0].config.groq.model_dump()
    for update in (
        {"api_key": "forbidden"},
        {"plan": "Developer"},
        {"single_probe": False},
        {"endpoint": "https://evil.invalid"},
        {"probe_token_cap": 999999},
    ):
        with pytest.raises(ValidationError):
            GroqConfig.model_validate(config | update)


def test_duplicate_headers_are_not_trusted():
    assert safe_headers(
        [("x-ratelimit-limit-tokens", "8000"), ("X-Ratelimit-Limit-Tokens", "8000")]
    ) == {"x-ratelimit-limit-tokens": "invalid"}


def test_restart_recovers_crash_after_dispatch_without_resending(cloud, monkeypatch):
    runtime, task, calls, _ = cloud

    def crash(_prepared):
        raise SystemExit("process crash")

    monkeypatch.setattr(runtime.adapter, "send", crash)
    with pytest.raises(SystemExit):
        runtime.run(task)
    core = ResourceController(runtime.core.ledger, allow_free_probe=True)
    assert core.recover(now_ms=now_ms() + 120000)["unknown_usage"] == 1
    assert CloudRuntime(runtime.config).run(task).reason == "request_already_attempted"
    assert events(runtime)[-1].transition == "unknown_usage"
    assert len(calls) == 1


def test_headerless_probe_cannot_erase_exhausted_or_stale_quota(cloud):
    runtime, task, calls, _ = cloud
    save_observation(
        runtime.core.ledger,
        observe(
            rate_headers("0"),
            scope=runtime.config.groq.quota_scope,
            now_ms=now_ms() - 61000,
            source="models_response",
        ),
    )
    assert "quota_observation_stale_or_invalid" in runtime.run(task).reason
    assert len(calls) == 1 and not events(runtime)


def test_quota_rechecked_between_reservation_and_dispatch(cloud, monkeypatch):
    runtime, task, calls, _ = cloud
    original = runtime.builder.validate_package
    validations = 0

    def exhausted(*args, **kwargs):
        nonlocal validations
        validations += 1
        if validations == 2:
            save_observation(
                runtime.core.ledger,
                observe(
                    rate_headers("0"),
                    scope=runtime.config.groq.quota_scope,
                    now_ms=now_ms(),
                    source="models_response",
                ),
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(runtime.builder, "validate_package", exhausted)
    assert runtime.run(task).reason == "observed_quota_exhausted"
    assert [event.transition for event in events(runtime)] == ["reserved"]
    assert len(calls) == 1  # safe lease recovery; no potentially ambiguous release


def test_released_payload_cannot_be_mutated_before_send(cloud, monkeypatch):
    runtime, task, calls, _ = cloud
    original = runtime.adapter.send

    def corrupt(prepared):
        return original(replace(prepared, body=prepared.body + b" "))

    monkeypatch.setattr(runtime.adapter, "send", corrupt)
    result = runtime.run(task)
    assert result.status == "unknown_usage" and len(calls) == 1


def test_recomputed_hash_does_not_authorize_private_canary(cloud, monkeypatch):
    runtime, task, calls, _ = cloud
    original = runtime.adapter.prepare

    def corrupt(payload):
        text = payload.text + CANARY
        return original(replace(payload, text=text, digest=sha256(text.encode())))

    monkeypatch.setattr(runtime.adapter, "prepare", corrupt)
    assert runtime.run(task).reason == "cloud_export_required"
    assert len(calls) == 1 and not events(runtime)


def test_transport_exception_is_sanitized_and_not_retried(monkeypatch):
    import devhub.groq as groq

    key = "credential-must-not-appear"
    calls = []
    monkeypatch.setattr(groq, "windows_user_key", lambda: key)

    class Broken:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            calls.append(1)
            raise TimeoutError(key)

        def close(self):
            pass

    monkeypatch.setattr(groq.http.client, "HTTPSConnection", Broken)
    with pytest.raises(GroqError) as error:
        GroqHTTP(1).request("/openai/v1/chat/completions", b"{}")
    assert str(error.value) == "send_outcome_unknown" and calls == [1]
