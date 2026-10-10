import asyncio
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters
from mcp.shared.exceptions import MCPError
from pydantic import ValidationError

from devhub import delegate
from devhub.cloud_export import task_release_hash
from devhub.context_models import ContextTask
from devhub.delegate import (
    DelegationConfig,
    DelegationRequest,
    DelegationRuntime,
    ProviderProfile,
)
from devhub.delegate_server import create_delegation_server
from devhub.events import EventOutbox
from devhub.local import LocalRuntime
from devhub.ollama import OllamaError
from devhub.output import OutputPolicy, validate_output
from devhub.resources import Admission

VALID = json.dumps(dict(schema_version=1, summary="Validate source hashes.", citations=["s1"]))


def request(runtime, task, **updates):
    return DelegationRequest(**task.model_dump(), project=runtime.config.project, **updates)


def configure_local(monkeypatch, runtime, response=VALID):
    original = runtime.adapter.http.request

    def http(path, body=None):
        result = original(path, body)
        if path == "/api/generate" and response is not None:
            result["response"] = response
        return result

    runtime.adapter.http.request = http

    def factory(config, *, output_policy, recover_on_startup=True):
        assert config == runtime.config
        assert recover_on_startup is False
        runtime.output_policy = runtime.adapter.output_policy = output_policy
        return runtime

    monkeypatch.setattr(delegate, "LocalRuntime", factory)


def service(runtime, **config):
    return DelegationRuntime(
        DelegationConfig(
            profiles=(ProviderProfile(id="approved", config=runtime.config),), **config
        )
    )


def test_local_structured_accounting_and_restart_replay(local, monkeypatch):
    runtime, task, calls, _ = local
    configure_local(monkeypatch, runtime)
    hub = service(runtime)
    result = hub.run(request(runtime, task))
    assert (result.status, result.execution, result.accounting) == (
        "completed",
        "completed",
        "settled",
    )
    assert result.output_validation == result.citations_validation == "passed"
    assert result.citations == ("s1",) and result.provider == "ollama"
    assert result.actual_input_tokens == result.input_preflight
    assert result.package_hash and result.accounting_reference
    assert result.semantic_acceptance is result.savings is result.delegation_value is None
    assert [e.transition for e in EventOutbox(runtime.core.ledger).pending(project="p")] == [
        "reserved",
        "dispatched",
        "settled",
    ]
    assert (
        DelegationRuntime(hub.config).run(request(runtime, task)).reason
        == "request_already_attempted"
    )
    assert calls.count("/api/generate") == 1


def expired_admission(runtime, task):
    return Admission(
        project=runtime.config.project,
        task=task.task_id,
        key=task.request_key,
        resource=runtime.resource,
        payload_sha256="a" * 64,
        input_tokens=1,
        max_output_tokens=1,
        expires_ms=1,
    )


def test_delegation_startup_recovers_before_replay_and_is_idempotent(local):
    runtime, task, calls, _ = local
    admission = expired_admission(runtime, task)
    ticket = runtime.core.reserve(admission, now_ms=0)
    runtime.core.dispatch(ticket.id, admission, now_ms=0)
    hub = service(runtime)
    with hub.ledger.transaction() as connection:
        state = connection.execute(
            "SELECT state FROM reservations WHERE id=?", (ticket.id,)
        ).fetchone()[0]
    transitions = [
        event.transition
        for event in EventOutbox(hub.ledger).pending(project=runtime.config.project)
    ]
    assert state == "unknown_usage"
    assert transitions == ["reserved", "dispatched", "unknown_usage"]
    assert hub.run(request(runtime, task)).reason == "request_already_attempted"
    assert calls.count("/api/generate") == 0
    service(runtime)
    assert [
        event.transition
        for event in EventOutbox(hub.ledger).pending(project=runtime.config.project)
    ] == transitions


def test_delegation_startup_releases_reserved_once_and_preserves_terminal_states(local):
    runtime, task, _, _ = local
    admission = expired_admission(runtime, task)
    ticket = runtime.core.reserve(admission, now_ms=0)
    hub = service(runtime)
    with hub.ledger.transaction() as connection:
        assert (
            connection.execute(
                "SELECT state FROM reservations WHERE id=?", (ticket.id,)
            ).fetchone()[0]
            == "released"
        )
    transitions = [
        event.transition
        for event in EventOutbox(hub.ledger).pending(project=runtime.config.project)
    ]
    assert transitions == ["reserved", "released"]
    service(runtime)
    assert [
        event.transition
        for event in EventOutbox(hub.ledger).pending(project=runtime.config.project)
    ] == transitions


def test_recovery_failure_prevents_delegation_runtime_startup(local, monkeypatch):
    runtime, _, _, _ = local

    def fail(*args, **kwargs):
        raise RuntimeError("recovery authority unavailable")

    monkeypatch.setattr(delegate.ResourceController, "recover", fail)
    with pytest.raises(RuntimeError, match="recovery authority"):
        service(runtime)


def test_shared_profiles_trigger_one_authoritative_startup_recovery(local, monkeypatch):
    runtime, _, _, _ = local
    original = delegate.ResourceController.recover
    calls = []

    def counted(self, *, now_ms):
        calls.append(now_ms)
        return original(self, now_ms=now_ms)

    monkeypatch.setattr(delegate.ResourceController, "recover", counted)
    DelegationRuntime(
        DelegationConfig(
            profiles=(
                ProviderProfile(id="one", config=runtime.config),
                ProviderProfile(id="two", config=runtime.config),
            )
        )
    )
    assert len(calls) == 1


def test_startup_recovery_preserves_settled_and_unknown_liability(local):
    runtime, task, _, _ = local
    settled_admission = expired_admission(runtime, task).model_copy(
        update={"task": "settled", "key": "settled"}
    )
    settled = runtime.core.reserve(settled_admission, now_ms=0)
    runtime.core.dispatch(settled.id, settled_admission, now_ms=0)
    runtime.core.settle(
        settled.id,
        project=runtime.config.project,
        actual={
            bucket: 2 if unit == "total_tokens" else 1 for unit, bucket in runtime.buckets.items()
        },
    )
    unknown_admission = expired_admission(runtime, task).model_copy(update={"key": "unknown"})
    unknown = runtime.core.reserve(unknown_admission, now_ms=0)
    runtime.core.dispatch(unknown.id, unknown_admission, now_ms=0)
    runtime.core.unknown(unknown.id, project=runtime.config.project)
    before = [event.transition for event in EventOutbox(runtime.core.ledger).pending(project="p")]
    service(runtime)
    with runtime.core.ledger.transaction() as connection:
        states = dict(
            connection.execute(
                "SELECT id,state FROM reservations WHERE id IN (?,?)", (unknown.id, settled.id)
            )
        )
    assert states == {unknown.id: "unknown_usage", settled.id: "settled"}
    assert [
        event.transition for event in EventOutbox(runtime.core.ledger).pending(project="p")
    ] == before


@pytest.mark.parametrize(
    "response,validation,citations",
    [
        ("{", "failed", "not_checked"),
        ('{"summary":"missing version","citations":["s1"]}', "failed", "not_checked"),
        ('{"schema_version":1,"summary":"fake","citations":["s99"]}', "passed", "failed"),
        ('{"schema_version":1,"summary":"missing","citations":[]}', "passed", "failed"),
    ],
)
def test_invalid_output_and_citations_settle_without_backend_switch(
    local, monkeypatch, response, validation, citations
):
    runtime, task, calls, _ = local
    configure_local(monkeypatch, runtime, response)
    hub = DelegationRuntime(
        DelegationConfig(
            profiles=(
                ProviderProfile(id="first", config=runtime.config),
                ProviderProfile(id="second", config=runtime.config),
            )
        )
    )
    result = hub.run(request(runtime, task))
    assert result.status == "failed" and result.accounting == "settled"
    assert result.output_validation == validation and result.citations_validation == citations
    assert result.summary is None and len(result.selection) == 1
    assert calls.count("/api/generate") == 1 and result.fallback is False


@pytest.mark.parametrize("mode", ["timeout", "missing_usage"])
def test_ambiguous_dispatch_never_switches_or_retries(local, monkeypatch, mode):
    runtime, task, calls, settings = local
    settings["value"] = mode
    configure_local(monkeypatch, runtime)
    hub = DelegationRuntime(
        DelegationConfig(
            profiles=(
                ProviderProfile(id="first", config=runtime.config),
                ProviderProfile(id="next", config=runtime.config),
            )
        )
    )
    result = hub.run(request(runtime, task))
    assert result.status == result.accounting == "unknown_usage"
    assert result.execution == "unknown" and len(result.selection) == 1
    assert result.actual_input_tokens is None and calls.count("/api/generate") == 1
    assert hub.run(request(runtime, task)).reason == "request_already_attempted"


def test_stale_package_rejected_before_send(local, monkeypatch):
    runtime, task, calls, _ = local
    configure_local(monkeypatch, runtime)
    reserve = runtime.core.reserve

    def invalidate(admission, **kwargs):
        ticket = reserve(admission, **kwargs)
        monkeypatch.setattr(runtime.builder, "validate_package", lambda *a, **k: False)
        return ticket

    monkeypatch.setattr(runtime.core, "reserve", invalidate)
    result = service(runtime).run(request(runtime, task))
    assert result.accounting == "released" and result.execution == "not_sent"
    assert "/api/generate" not in calls


def test_selected_before_reservation_and_deterministic(local, monkeypatch):
    runtime, task, calls, _ = local
    configure_local(monkeypatch, runtime)
    observed = []
    reserve = runtime.core.reserve

    def checked(admission, **kwargs):
        observed.append(admission.resource)
        assert admission.resource == runtime.resource
        return reserve(admission, **kwargs)

    monkeypatch.setattr(runtime.core, "reserve", checked)
    hub = service(runtime)
    one = hub.run(request(runtime, task))
    from test_ollama import metadata

    from devhub.ollama import QwenTokenizer

    tokenizer = QwenTokenizer(metadata())
    original_http = runtime.adapter.http.request

    def next_http(path, body=None):
        if path != "/api/generate":
            return original_http(path, body)
        return dict(
            model="test",
            done=True,
            done_reason="stop",
            prompt_eval_count=tokenizer.count(body["prompt"]),
            eval_count=12,
            response=VALID,
        )

    monkeypatch.setattr(runtime.adapter.http, "request", next_http)
    two = hub.run(
        request(runtime, task.model_copy(update={"task_id": "next", "request_key": "next"}))
    )
    assert one.provider == two.provider == "ollama" and one.selection == two.selection
    assert observed == [runtime.resource, runtime.resource]


def test_project_isolation_and_untrusted_overrides(local, monkeypatch):
    runtime, task, calls, _ = local
    configure_local(monkeypatch, runtime)
    req = request(runtime, task)
    assert (
        service(runtime).run(req.model_copy(update={"project": "other"})).reason == "project_denied"
    )
    assert not calls
    for field in ["api_key", "endpoint", "provider", "model", "billing", "quota"]:
        with pytest.raises(ValidationError):
            DelegationRequest.model_validate_json(
                json.dumps(req.model_dump() | {field: "untrusted"})
            )
    with pytest.raises(ValidationError):
        DelegationConfig(
            profiles=(
                ProviderProfile(id="one", config=runtime.config),
                ProviderProfile(
                    id="other", config=runtime.config.model_copy(update={"project": "other"})
                ),
            )
        )


def configure_cloud(monkeypatch, runtime, req, response=VALID):
    task = req.local_task()
    bound = ContextTask(
        task_id=task.task_id,
        instructions=task.instructions,
        acceptance_criteria=task.acceptance_criteria,
    )
    export = runtime.config.export.model_copy(update={"task_sha256": task_release_hash(bound)})
    runtime.config = runtime.config.model_copy(update={"export": export})
    original = runtime.adapter.http.request

    def http(path, body=None):
        reply = original(path, body)
        if "completions" in path:
            reply.body["choices"][0]["message"]["content"] = response
        if "generateContent" in path:
            reply.body["candidates"][0]["content"]["parts"][0]["text"] = response
        return reply

    runtime.adapter.http.request = http

    def factory(config, *, output_policy, recover_on_startup=True):
        assert config == runtime.config
        assert recover_on_startup is False
        runtime.output_policy = runtime.adapter.output_policy = output_policy
        return runtime

    monkeypatch.setattr(delegate, "CloudRuntime", factory)


@pytest.mark.parametrize(
    "privacy,allowed",
    [("local_only", True), ("project_private", True), ("public", False), ("redacted", False)],
)
def test_private_or_unapproved_cloud_never_receives_payload(cloud, monkeypatch, privacy, allowed):
    runtime, task, calls, _ = cloud
    req = request(runtime, task, privacy=privacy, allow_cloud=allowed)
    configure_cloud(monkeypatch, runtime, req)
    result = service(runtime, cloud_enabled=True).run(req)
    assert result.status == "denied" and not calls


@pytest.mark.parametrize("provider", ["groq", "gemini"])
def test_approved_cloud_uses_same_contract_and_accounting(
    cloud, gemini_cloud, monkeypatch, provider
):
    runtime, task, calls, _ = cloud if provider == "groq" else gemini_cloud
    req = request(runtime, task, privacy="public", allow_cloud=True)
    configure_cloud(monkeypatch, runtime, req)
    result = service(runtime, cloud_enabled=True).run(req)
    assert result.status == "completed" and result.accounting == "settled"
    assert result.citations_validation == "passed" and result.provider == provider
    assert result.export_hash and result.citations == ("s1",)


def test_unapproved_source_stops_before_cloud_preparation(cloud, monkeypatch):
    runtime, task, calls, _ = cloud
    req = request(runtime, task, privacy="public", allow_cloud=True)
    configure_cloud(monkeypatch, runtime, req)
    grant = runtime.config.export.releases[0].model_copy(update={"source_sha256": "0" * 64})
    runtime.config = runtime.config.model_copy(
        update={"export": runtime.config.export.model_copy(update={"releases": (grant,)})}
    )
    result = service(runtime, cloud_enabled=True).run(req)
    assert result.status == "denied" and not calls


def test_pre_reservation_ineligible_provider_chooses_next(local, monkeypatch):
    runtime, task, calls, _ = local
    configure_local(monkeypatch, runtime)
    factory = delegate.LocalRuntime
    attempts = []

    def next_candidate(config, *, output_policy, recover_on_startup=True):
        assert recover_on_startup is False
        attempts.append(config.ollama.model)
        if config.ollama.model == "unavailable":
            failed = LocalRuntime(config, output_policy=output_policy)

            def deny():
                raise OllamaError("model_identity_changed_or_missing")

            monkeypatch.setattr(failed.adapter, "inspect", deny)
            return failed
        return factory(config, output_policy=output_policy, recover_on_startup=False)

    monkeypatch.setattr(delegate, "LocalRuntime", next_candidate)
    unavailable = runtime.config.model_copy(
        update={"ollama": runtime.config.ollama.model_copy(update={"model": "unavailable"})}
    )
    hub = DelegationRuntime(
        DelegationConfig(
            profiles=(
                ProviderProfile(id="missing", config=unavailable),
                ProviderProfile(id="installed", config=runtime.config),
            )
        )
    )
    result = hub.run(request(runtime, task))
    assert result.status == "completed" and attempts == ["unavailable", "test"]
    assert len(result.selection) == 2 and calls.count("/api/generate") == 1


def test_citation_validator_rejects_duplicates_and_other_package_ids():
    assert validate_output(VALID, ("s2",), OutputPolicy()).reason == "invalid_citations"
    duplicate = json.dumps(dict(schema_version=1, summary="duplicate", citations=["s1", "s1"]))
    assert validate_output(duplicate, ("s1",), OutputPolicy()).reason == "invalid_citations"


def test_mcp_strict_contract_and_no_secret_echo(local, monkeypatch):
    runtime, task, calls, _ = local
    configure_local(monkeypatch, runtime)
    req = request(runtime, task)

    async def run():
        async with Client(create_delegation_server(service(runtime))) as client:
            assert [t.name for t in (await client.list_tools()).tools] == ["devhub_delegate"]
            with pytest.raises(MCPError) as error:
                await client.call_tool(
                    "devhub_delegate", req.model_dump(mode="json") | {"api_key": "secret-canary"}
                )
            assert "secret-canary" not in str(error.value)
            result = await client.call_tool("devhub_delegate", req.model_dump(mode="json"))
            assert result.structured_content["status"] == "completed"

    asyncio.run(run())


@pytest.mark.windows_smoke
def test_delegate_real_stdio_unicode_path(tmp_path, local):
    runtime, task, calls, _ = local
    config = tmp_path / "конфіг with spaces.json"
    config.write_text(
        DelegationConfig(
            profiles=(ProviderProfile(id="local", config=runtime.config),)
        ).model_dump_json(),
        encoding="utf-8",
    )
    req = request(runtime, task).model_copy(update={"project": "other"})

    async def run():
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "devhub.delegate_server", "--config", str(config)]
        )
        async with Client(params, read_timeout_seconds=15) as client:
            assert [t.name for t in (await client.list_tools()).tools] == ["devhub_delegate"]
            result = await client.call_tool("devhub_delegate", req.model_dump(mode="json"))
            assert result.structured_content["reason"] == "project_denied"

    asyncio.run(run())
    assert not calls


@pytest.mark.windows_smoke
@pytest.mark.skipif(sys.platform != "win32", reason="native Windows stdio lifecycle")
def test_delegate_real_stdio_eof_and_truncated_input_fail_closed(tmp_path, local):
    runtime, _, _, _ = local
    config = tmp_path / "конфіг EOF with spaces.json"
    config.write_text(
        DelegationConfig(
            profiles=(ProviderProfile(id="local", config=runtime.config),)
        ).model_dump_json(),
        encoding="utf-8",
    )
    command = [sys.executable, "-m", "devhub.delegate_server", "--config", str(config)]

    def accounting_counts() -> tuple[int, int, int]:
        with sqlite3.connect(Path(runtime.config.state_root) / "ledger.db") as connection:
            return tuple(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("reservations", "allocations", "events")
            )

    before = accounting_counts()

    eof = subprocess.run(command, input=b"", capture_output=True, timeout=15, check=False)
    assert eof.returncode == 0
    assert eof.stdout == b""

    malformed = subprocess.run(
        command,
        input=b'{"jsonrpc":"2.0","id":1',
        capture_output=True,
        timeout=15,
        check=False,
    )
    assert malformed.returncode == 0
    assert b'"result"' not in malformed.stdout
    for line in malformed.stdout.splitlines():
        json.loads(line)
    assert accounting_counts() == before == (0, 0, 0)


pytest_plugins = ["test_ollama", "test_groq", "test_gemini"]


@pytest.mark.parametrize("privacy", ["local_only", "project_private", "public"])
def test_policy_cloud_exclusion_or_preflight_ineligibility_can_choose_local(
    isolated_local, cloud, monkeypatch, privacy
):
    local_runtime, task, calls, _ = isolated_local
    cloud_runtime, _, cloud_calls, _ = cloud
    configure_local(monkeypatch, local_runtime)
    cfg = cloud_runtime.config.model_copy(
        update={"root": local_runtime.config.root, "state_root": local_runtime.config.state_root}
    )
    # Its export belongs to another worktree. Even public caller intent cannot release it.
    hub = DelegationRuntime(
        DelegationConfig(
            cloud_enabled=True,
            profiles=(
                ProviderProfile(id="cloud-first", config=cfg),
                ProviderProfile(id="local-next", config=local_runtime.config),
            ),
        )
    )
    result = hub.run(request(local_runtime, task, privacy=privacy, allow_cloud=True))
    assert result.status == "completed" and result.provider == "ollama"
    assert len(result.selection) == 2 and calls.count("/api/generate") == 1
    assert not cloud_calls


def test_cloud_dispatch_failure_never_switches_to_local(cloud, isolated_local, monkeypatch):
    runtime, task, calls, mode = cloud
    local_runtime, _, local_calls, _ = isolated_local
    req = request(runtime, task, privacy="public", allow_cloud=True)
    configure_cloud(monkeypatch, runtime, req)
    mode["value"] = "timeout"
    cfg = local_runtime.config.model_copy(
        update={"root": runtime.config.root, "state_root": runtime.config.state_root}
    )
    hub = DelegationRuntime(
        DelegationConfig(
            cloud_enabled=True,
            profiles=(
                ProviderProfile(id="cloud", config=runtime.config),
                ProviderProfile(id="local", config=cfg),
            ),
        )
    )

    def forbidden(*a, **kw):
        raise AssertionError("post-dispatch backend switch")

    monkeypatch.setattr(delegate, "LocalRuntime", forbidden)
    result = hub.run(req)
    assert result.status == result.accounting == "unknown_usage"
    assert len(result.selection) == 1 and not local_calls
    assert sum("completions" in p for p, b in calls) == 1


def test_optional_citations_still_reject_fabrication():
    policy = OutputPolicy(require_citations=False)
    empty = json.dumps(dict(schema_version=1, summary="ok", citations=[]))
    assert validate_output(empty, ("s1",), policy).output is not None
    assert validate_output(VALID, (), policy).reason == "invalid_citations"


@pytest.fixture
def isolated_local(tmp_path_factory, monkeypatch):
    from test_ollama import local

    return local.__wrapped__(tmp_path_factory.mktemp("second-provider"), monkeypatch)


@pytest.mark.parametrize("mode", ["off", "compact", "verbose"])
def test_usage_footer_preserves_execution_and_structured_handoff(local, monkeypatch, mode):
    from devhub import delegate_server

    runtime, task, calls, _ = local
    configure_local(monkeypatch, runtime)
    hub = service(runtime, telemetry_footer=mode)
    req = request(runtime, task)
    original_run = hub.run
    handoffs = []

    def capture(request):
        result = original_run(request)
        handoffs.append(result)
        return result

    monkeypatch.setattr(hub, "run", capture)
    if mode == "off":

        def forbidden(*args, **kwargs):
            raise AssertionError("off must not derive observability")

        monkeypatch.setattr(delegate_server, "derive_usage", forbidden)

    async def run():
        async with Client(create_delegation_server(hub)) as client:
            result = await client.call_tool("devhub_delegate", req.model_dump(mode="json"))
            assert result.structured_content == handoffs[0].model_dump(mode="json")
            if mode == "off":
                assert not result.meta or "devfabric_usage" not in result.meta
                assert len(result.content) == 1
            else:
                summary = result.meta["devfabric_usage"]
                assert summary["savings"] is summary["codex_usage"] is None
                assert summary["delegated_total"] == (
                    handoffs[0].actual_input_tokens + handoffs[0].actual_output_tokens
                )
                assert "unknown" in result.content[-1].text
            with pytest.raises(MCPError):
                await client.call_tool(
                    "devhub_delegate", req.model_dump(mode="json") | {"telemetry_footer": "verbose"}
                )

    asyncio.run(run())
    result = handoffs[0]
    assert result.provider == "ollama" and result.accounting == "settled"
    assert result.output_validation == result.citations_validation == "passed"
    assert calls.count("/api/generate") == 1
    assert [e.transition for e in EventOutbox(runtime.core.ledger).pending(project="p")] == [
        "reserved",
        "dispatched",
        "settled",
    ]
