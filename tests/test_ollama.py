import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Barrier, Thread

import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError
from pydantic import ValidationError
from test_brain import repo
from tokenizers import pre_tokenizers

from devhub.controller import Denied, ResourceController
from devhub.events import EventOutbox
from devhub.local import LocalConfig, LocalRuntime, LocalTask
from devhub.local_server import create_local_server
from devhub.ollama import LocalHTTP, OllamaConfig, OllamaError, QwenTokenizer
from devhub.resources import Admission, ResourcePolicy


def metadata():
    return {
        "general.architecture": "qwen2",
        "qwen2.context_length": 32768,
        "tokenizer.ggml.model": "gpt2",
        "tokenizer.ggml.pre": "qwen2",
        "tokenizer.ggml.add_bos_token": False,
        "tokenizer.ggml.tokens": sorted(pre_tokenizers.ByteLevel.alphabet())
        + ["<|im_start|>", "<|im_end|>"],
        "tokenizer.ggml.token_type": [1] * 256 + [3, 3],
        "tokenizer.ggml.merges": [],
    }


@pytest.fixture
def local(tmp_path, monkeypatch):
    root = repo(tmp_path / "repo", {"guide.md": "Validate source hashes before dispatch.\n"})
    config = LocalConfig(
        project="p",
        root=str(root),
        state_root=str(tmp_path / "state"),
        approved_paths=("guide.md",),
        ollama=OllamaConfig(
            endpoint="http://127.0.0.1:11434",
            model="test",
            model_digest="a" * 64,
        ),
    )
    runtime = LocalRuntime(config)
    tokenizer = QwenTokenizer(metadata())
    calls, mode = [], {"value": "valid"}

    def http(path, body=None):
        calls.append(path)
        if path == "/api/version":
            return {"version": "0.34.2"}
        if path == "/api/tags":
            return {"models": [{"name": "test", "digest": "a" * 64}]}
        if path == "/api/show":
            return {"capabilities": ["completion"], "model_info": metadata()}
        assert path == "/api/generate"
        with runtime.core.ledger.transaction() as connection:
            assert (
                connection.execute("SELECT state FROM reservations").fetchone()[0] == "dispatched"
            )
            assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2
        assert body["raw"] and body["stream"] is False and body["truncate"] is False
        assert body["shift"] is False
        assert "system\n" in body["prompt"] and "<|im_start|>assistant\n" in body["prompt"]
        if mode["value"] == "timeout":
            raise OllamaError("transport_or_json_failure")
        response = dict(
            model="test",
            done=True,
            done_reason="stop",
            prompt_eval_count=tokenizer.count(body["prompt"]),
            eval_count=12,
            response='{"summary":"Revalidate source evidence before dispatch."}',
        )
        if mode["value"] == "missing_usage":
            del response["eval_count"]
        if mode["value"] == "invalid_json":
            response["response"] = "{"
        if mode["value"] == "invalid_shape":
            response["response"] = '{"extra":123}'
        if mode["value"] == "tokenizer_mismatch":
            response["prompt_eval_count"] += 1
        return response

    monkeypatch.setattr(runtime.adapter.http, "request", http)
    task = LocalTask(
        task_id="task",
        request_key="one",
        instructions="Explain freshness.",
        acceptance_criteria=("Mention validation.",),
        query="guide.md",
    )
    return runtime, task, calls, mode


def test_local_accounting_and_no_replay(local):
    runtime, task, calls, _ = local
    result = runtime.run(task)
    assert result.status == "completed"
    assert result.actual_model_input_tokens == result.model_input_tokens_preflight
    assert result.offline_context_proxy != result.actual_model_input_tokens
    events = EventOutbox(runtime.core.ledger).pending(project="p")
    assert [e.transition for e in events] == ["reserved", "dispatched", "settled"]
    assert all(e.synthetic is False for e in events)
    assert runtime.run(task).reason == "request_already_attempted"
    assert LocalRuntime(runtime.config).run(task).reason == "request_already_attempted"
    assert calls.count("/api/generate") == 1


@pytest.mark.parametrize(
    "mode,status",
    [
        ("timeout", "unknown_usage"),
        ("missing_usage", "unknown_usage"),
        ("invalid_json", "failed"),
        ("invalid_shape", "failed"),
        ("tokenizer_mismatch", "failed"),
    ],
)
def test_usage_survives_failure(local, mode, status, monkeypatch):
    runtime, task, calls, setting = local
    setting["value"] = mode
    if mode == "tokenizer_mismatch":
        original_settle = runtime.core.settle

        def check_block(*args, **kwargs):
            assert (runtime.state / "tokenizer-mismatch.block").exists()
            return original_settle(*args, **kwargs)

        monkeypatch.setattr(runtime.core, "settle", check_block)
    result = runtime.run(task)
    assert result.status == status
    events = EventOutbox(runtime.core.ledger).pending(project="p")
    assert events[-1].transition == ("unknown_usage" if status == "unknown_usage" else "settled")
    if status == "unknown_usage":
        assert result.actual_model_input_tokens is None
        assert all(item.actual is None for item in events[-1].allocations)
        assert (
            runtime.run(task.model_copy(update={"task_id": "other", "request_key": "two"})).status
            == "denied"
        )
    else:
        assert result.actual_model_input_tokens > 0 and result.actual_model_output_tokens == 12
    assert calls.count("/api/generate") == 1
    if mode == "tokenizer_mismatch":
        assert (
            runtime.run(task.model_copy(update={"request_key": "two"})).reason
            == "tokenizer_verification_required"
        )


def test_model_identity_checked_before_reservation(local, monkeypatch):
    runtime, task, calls, _ = local

    def denied():
        raise OllamaError("model_identity_changed_or_missing")

    monkeypatch.setattr(runtime.adapter, "check_digest", denied)
    assert runtime.run(task).status == "denied"
    assert not EventOutbox(runtime.core.ledger).pending(project="p")
    assert "/api/generate" not in calls


def test_full_request_admission_and_source_revalidation(local, monkeypatch):
    runtime, task, calls, _ = local
    runtime.adapter.config = runtime.adapter.config.model_copy(update={"context_tokens": 512})
    assert runtime.run(task).status == "context_insufficient"
    assert not EventOutbox(runtime.core.ledger).pending(project="p")
    runtime.adapter.config = runtime.config.ollama
    original = runtime.builder.validate_package
    validations = 0

    def stale(*args, **kwargs):
        nonlocal validations
        validations += 1
        return original(*args, **kwargs) if validations == 1 else False

    monkeypatch.setattr(runtime.builder, "validate_package", stale)
    assert runtime.run(task).status == "context_insufficient"
    assert EventOutbox(runtime.core.ledger).pending(project="p")[-1].transition == "released"
    assert "/api/generate" not in calls


def test_durable_single_local_slot(local):
    runtime, _, _, _ = local
    barrier = Barrier(2)

    def reserve(index):
        core = ResourceController(runtime.core.ledger, allow_local_execution=True)
        request = Admission(
            project="p",
            task=str(index),
            key=str(index),
            resource=runtime.resource,
            payload_sha256="a" * 64,
            input_tokens=10,
            max_output_tokens=10,
            expires_ms=500,
        )
        barrier.wait()
        try:
            return core.reserve(request, now_ms=1).state
        except Denied as error:
            return str(error)

    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(reserve, range(2))) == ["local_inference_busy", "reserved"]


def test_mcp_contract_and_complete_local_path(local):
    runtime, task, _, _ = local

    async def run():
        async with Client(create_local_server(runtime)) as client:
            assert [tool.name for tool in (await client.list_tools()).tools] == [
                "devhub_local_task"
            ]
            args = json.loads(task.model_dump_json())
            with pytest.raises(MCPError):
                await client.call_tool("devhub_local_task", args | {"endpoint": "http://remote"})
            result = await client.call_tool("devhub_local_task", args)
            assert not result.is_error
            assert result.structured_content["status"] == "completed"

    asyncio.run(run())


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://localhost:11434",
        "https://127.0.0.1:11434",
        "http://8.8.8.8:11434",
        "http://127.0.0.1:11434/path",
        "http://u:p@127.0.0.1:11434",
    ],
)
def test_endpoint_allowlist_is_numeric_local_only(endpoint):
    with pytest.raises(ValidationError):
        OllamaConfig(endpoint=endpoint, model="test", model_digest="a" * 64)


def test_tokenizer_bytes_specials_and_unsupported_metadata():
    info = metadata()
    tokenizer = QwenTokenizer(info)
    assert tokenizer.count("<|im_start|>Привіт 123\n<|im_end|>") == 2 + len("Привіт 123\n".encode())
    for changed in ({"tokenizer.ggml.pre": "other"}, {"tokenizer.ggml.add_bos_token": True}):
        with pytest.raises(OllamaError, match="unsupported_tokenizer"):
            QwenTokenizer(info | changed)
    with pytest.raises(ValidationError):
        ResourcePolicy(id="cloud", kind="free", synthetic=False, buckets=("x",))


@pytest.mark.parametrize("reply", ["redirect", "broken_json"])
def test_http_never_follows_redirect_or_retries(reply):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            calls.append(self.path)
            self.send_response(302 if reply == "redirect" else 200)
            self.send_header("Location", "/unexpected")
            self.end_headers()
            self.wfile.write(b"{")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = OllamaConfig(
        endpoint=f"http://127.0.0.1:{server.server_port}", model="test", model_digest="a" * 64
    )
    try:
        with pytest.raises(OllamaError):
            LocalHTTP(config).request("/api/version")
        with pytest.raises(OllamaError, match="endpoint_denied"):
            LocalHTTP(config).request("/api/pull", {"model": "test"})
        assert calls == ["/api/version"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_live_execution_disabled_by_default(local):
    runtime, _, _, _ = local
    core = ResourceController(runtime.core.ledger)
    request = Admission(
        project="p",
        task="blocked",
        key="blocked",
        resource=runtime.resource,
        payload_sha256="a" * 64,
        input_tokens=10,
        max_output_tokens=10,
        expires_ms=500,
    )
    with pytest.raises(Denied, match="local_execution_disabled"):
        core.reserve(request, now_ms=1)


def test_concurrent_tokenizer_block_is_checked_before_dispatch(local, monkeypatch):
    runtime, task, calls, _ = local
    original = runtime.adapter.check_digest
    inspections = 0

    def block_before_dispatch():
        nonlocal inspections
        inspections += 1
        original()
        if inspections == 3:
            (runtime.state / "tokenizer-mismatch.block").write_text("blocked")

    monkeypatch.setattr(runtime.adapter, "check_digest", block_before_dispatch)
    assert runtime.run(task).reason == "tokenizer_verification_required"
    assert "/api/generate" not in calls
    assert [
        event.transition for event in EventOutbox(runtime.core.ledger).pending(project="p")
    ] == ["reserved", "released"]


def test_existing_stage3c_policy_survives_default_field_additions(local):
    runtime, _, _, _ = local
    with runtime.core.ledger.transaction() as connection:
        spec = json.loads(connection.execute("SELECT spec FROM policies").fetchone()[0])
        for field in ("live_account", "quota_scope", "single_probe"):
            del spec[field]
        connection.execute("UPDATE policies SET spec=?", (json.dumps(spec),))
    # Old persisted specs have no Stage 3D fields; semantically identical defaults
    # must not trigger immutable_policy on a previously accepted local runtime.
    assert LocalRuntime(runtime.config).resource == runtime.resource
