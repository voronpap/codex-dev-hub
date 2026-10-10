"""Offline protocol/launcher tests. No benchmark fixture goes through Codex/provider."""

import json
import shutil
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from devhub.benchmark import Quality, digest
from devhub.experiment import ExperimentProtocol, PlannedSession, RuntimeBindings, plan
from devhub.experiment_bridge import MCPGate, connect_target
from devhub.experiment_launch import (
    AttemptAbortV1,
    AttemptResult,
    ContainerRuntimeSpec,
    DelegationObservation,
    capture_process,
    codex_argv,
    codex_usage,
    completed_turn,
    container_command,
    durable_claim,
    launch_container,
    safe_artifacts,
)
from devhub.experiment_review import ComparisonInput, compare, reviewer_rules
from devhub.experiment_run import execute_next, packet_bytes
from devhub.process_capture import CapturedStream, CapturedStreamV1, ProcessCapture

ROOT = Path(__file__).resolve().parents[1]


def test_protocol_v2_removes_only_rejected_overrides(protocol):
    from devhub.experiment import CODEX_OVERRIDES

    revised = ExperimentProtocol.model_validate_json(
        (ROOT / "benchmarks/real-protocol-v2.json").read_bytes()
    )
    assert revised.model_dump(exclude={"protocol_id"}) == protocol.model_dump(
        exclude={"protocol_id"}
    )
    assert protocol.codex_overrides() == CODEX_OVERRIDES
    assert revised.codex_overrides() == CODEX_OVERRIDES[:-2]
    assert CODEX_OVERRIDES[-2:] == (
        "model_providers.openai.request_max_retries=0",
        "model_providers.openai.stream_max_retries=0",
    )
    historical = json.loads((ROOT / "docs/evidence/stage3g-c/local-plan.json").read_bytes())
    assert protocol.hashes() == historical["hashes"]
    assert revised.hashes()["protocol"] != protocol.hashes()["protocol"]
    assert revised.hashes()["codex_config"] != protocol.hashes()["codex_config"]
    for key in ("routing_policy", "context_policy", "output_policy", "instructions"):
        assert revised.hashes()[key] == protocol.hashes()[key]
    for arm in ("A", "B"):
        argv = codex_argv(session(arm), revised)
        assert not any("model_providers.openai" in value for value in argv)
        assert ("mcp_servers.devhub_delegate.required=true" in argv) is (arm == "B")


def test_v2_plan_rebinds_all_sessions_without_changing_order(repo, protocol):
    revised = ExperimentProtocol.model_validate_json(
        (ROOT / "benchmarks/real-protocol-v2.json").read_bytes()
    )
    old = plan(repo, protocol, "revision-test")
    new = plan(repo, revised, "revision-test")
    assert len(new["sessions"]) == 24
    assert len({s["session_id"] for s in new["sessions"]}) == 24
    for a, b in zip(old["sessions"], new["sessions"], strict=True):
        assert a["session_id"] != b["session_id"]
        assert {k: v for k, v in a.items() if k != "session_id"} == {
            k: v for k, v in b.items() if k != "session_id"
        }
    assert old["reviewer_rules_sha256"] == new["reviewer_rules_sha256"]
    assert new["retry_semantics"]["codex_internal_retries"] is None
    assert new["execution_ready"] is False
    assert new["provider_sends"] == new["real_codex_executions"] == 0


@pytest.fixture
def protocol():
    return ExperimentProtocol.model_validate_json(
        (ROOT / "benchmarks/real-protocol.json").read_bytes()
    )


@pytest.fixture
def repo(tmp_path):
    repo = tmp_path / "source"
    shutil.copytree(ROOT / "src", repo / "src")
    shutil.copytree(ROOT / "benchmarks", repo / "benchmarks")
    for args in (
        ["init", "-q"],
        ["config", "core.autocrlf", "false"],
        ["add", "."],
        ["-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-qm", "frozen"],
    ):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)
    return repo


def session(arm="A"):
    return PlannedSession(
        order=1,
        fixture_id="synthetic-only",
        fixture_sha256="a" * 64,
        oracle_sha256="b" * 64,
        arm=arm,
        session_id="synthetic-session",
        packet_path="synthetic/packet",
        available_mcp_tools=() if arm == "A" else ("devhub_delegate",),
    )


@pytest.fixture
def boundary(tmp_path, protocol):
    packet = tmp_path / "control"
    packet.mkdir()
    (packet / "session.json").write_bytes(b"SYNTHETIC CONTROL ONLY")
    bridge = tmp_path / "bridge"
    bridge.mkdir()
    (bridge / "proxy.sock").touch()
    capture = tmp_path / "capture"
    capture.mkdir()
    bootstrap = tmp_path / "bootstrap.py"
    bootstrap.write_bytes(b"# synthetic bootstrap")
    auth = tmp_path / "auth.json"
    auth.write_bytes(b"{}")
    host_manifest = tmp_path / "stage3g-host.json"
    host_manifest.write_bytes((ROOT / "benchmarks/stage3g-host-manifest-v2.json").read_bytes())
    runtime = ContainerRuntimeSpec(
        image_id="sha256:" + "d" * 64,
        bootstrap_sha256=digest(bootstrap.read_bytes()),
        protocol_sha256=protocol.hashes()["protocol"],
        reviewed_plan_sha256="c" * 64,
        codex_cli_version=protocol.codex_cli_version,
    )
    return runtime, packet, bridge, capture, bootstrap, auth, host_manifest


def events(usage=True):
    data = [
        {"type": "thread.started", "thread_id": "synthetic"},
        {"type": "turn.started"},
        {"type": "turn.completed"},
    ]
    if usage:
        data[-1]["usage"] = {"input_tokens": 81, "output_tokens": 11, "cached_input_tokens": 20}
    return b"\n".join(json.dumps(v).encode() for v in data)


def test_all_planned_sessions_balanced_independent_and_bound(repo, protocol):
    manifest = plan(repo, protocol, "offline-planning")
    assert manifest == plan(repo, protocol, "offline-planning")
    sessions = [PlannedSession.model_validate_json(json.dumps(s)) for s in manifest["sessions"]]
    assert len(sessions) == 24 and len({s.session_id for s in sessions}) == 24
    assert [s.order for s in sessions] == list(range(1, 25))
    assert [s.arm for s in sessions] == ["A", "B", "B", "A"] * 6
    assert manifest["real_codex_executions"] == 0 and manifest["provider_sends"] == 0
    assert all(manifest["hashes"].values())
    for i in range(0, 24, 2):
        a, b = sessions[i : i + 2]
        assert a.fixture_id == b.fixture_id
        pa, pb = packet_bytes(repo, a, protocol), packet_bytes(repo, b, protocol)
        assert pa["input.txt"] == pb["input.txt"] and pa["task.txt"] == pb["task.txt"]
        for s, p in ((a, pa), (b, pb)):
            assert set(p) == {"input.txt", "task.txt", "instructions.txt", "session.json"}
            assert s.available_mcp_tools == (() if s.arm == "A" else ("devhub_delegate",))
            assert str(repo).encode() not in b"".join(p.values())
            assert b"output.bin" not in b"".join(p.values())
            assert b"oracles/" not in b"".join(p.values())
    assert "optional" in protocol.arm_b_instructions
    assert "do-not-delegate" in protocol.arm_b_instructions


def test_no_mcp_in_a_only_local_entry_point_in_b(protocol):
    a = codex_argv(session(), protocol)
    b = codex_argv(session("B"), protocol)
    assert "mcp_servers={}" in a
    assert not any("devhub_delegate" in arg for arg in a)
    assert "--ephemeral" in a and "resume" not in a and "fork" not in a
    assert "--ignore-user-config" in a and "--ignore-rules" in a
    assert a[a.index("--devhub-stage3g-arm") + 1] == "a"
    assert b[b.index("--devhub-stage3g-arm") + 1] == "b"
    assert "/stage3g-host.json" in a and "/stage3g-host.json" in b
    assert "features.shell_tool=false" in a and 'web_search="disabled"' in a
    assert 'mcp_servers.devhub_delegate.enabled_tools=["devhub_delegate"]' in b
    assert not any("groq" in arg or "gemini" in arg or "local_task" in arg for arg in b)
    assert "model_providers.openai.request_max_retries=0" in a


def test_oci_mount_and_network_scope(boundary):
    bindings, packet, bridge, capture, bootstrap, auth, host_manifest = boundary
    args = container_command(
        session(), bindings, packet, bridge, capture, bootstrap, auth, host_manifest
    )
    assert "--network=none" in args and "--read-only" in args and "--pull=never" in args
    assert "--cap-drop=ALL" in args and "--security-opt=no-new-privileges" in args
    mounts = [args[i + 1] for i, v in enumerate(args) if v == "--mount"]
    assert len(mounts) == 6
    assert any("dst=/control" in mount for mount in mounts)
    assert any("dst=/stage3g-host.json" in mount and "readonly" in mount for mount in mounts)
    assert not any("dst=/packet" in mount for mount in mounts)
    assert any(value.startswith("/packet:rw,noexec,nosuid,size=16m") for value in args)
    assert all(str(ROOT) not in m and "docker.sock" not in m for m in mounts)
    assert not any("host" == a or "privileged" in a for a in args)
    assert not any("GROQ_API_KEY" in a or "GEMINI_API_KEY" in a for a in args)
    (bridge / "mcp.sock").touch()
    with pytest.raises(ValueError, match="bridge"):
        container_command(
            session(), bindings, packet, bridge, capture, bootstrap, auth, host_manifest
        )
    assert container_command(
        session("B"), bindings, packet, bridge, capture, bootstrap, auth, host_manifest
    )


@pytest.mark.parametrize("extra", ["oracle.json", "task.txt", "previous-output.txt"])
def test_contaminated_guest_control_rejected(boundary, extra):
    bindings, packet, bridge, capture, bootstrap, auth, host_manifest = boundary
    (packet / extra).write_text("canary")
    with pytest.raises(ValueError, match="control"):
        container_command(
            session(), bindings, packet, bridge, capture, bootstrap, auth, host_manifest
        )


def test_output_reuse_and_bootstrap_change_rejected(boundary):
    bindings, packet, bridge, capture, bootstrap, auth, host_manifest = boundary
    (capture / "final.txt").write_bytes(b"old")
    with pytest.raises(ValueError, match="reused"):
        container_command(
            session(), bindings, packet, bridge, capture, bootstrap, auth, host_manifest
        )
    (capture / "final.txt").unlink()
    bootstrap.write_bytes(b"changed")
    with pytest.raises(ValueError, match="Bootstrap"):
        container_command(
            session(), bindings, packet, bridge, capture, bootstrap, auth, host_manifest
        )


def test_usage_documented_jsonl_not_ui_or_proxy(protocol):
    usage = codex_usage(events(), protocol.codex_cli_version, protocol.codex_cli_version)
    assert (usage.input_tokens, usage.output_tokens, usage.cached_input_tokens) == (81, 11, 20)
    assert usage.context_usage is None and usage.internal_retries is None
    for raw in (
        b"Input: 81 tokens",
        events(False),
        events() + b"\n" + events(),
        b'{"type":"turn.completed","usage":{"input_tokens":true,"output_tokens":1}}',
    ):
        assert (
            codex_usage(raw, protocol.codex_cli_version, protocol.codex_cli_version).input_tokens
            is None
        )
    assert codex_usage(events(), "different", protocol.codex_cli_version).input_tokens is None
    assert completed_turn(events(False))  # missing usage is not execution failure
    assert not completed_turn(events() + b'\n{"type":"error"}')


def test_generated_execution_event_compromises_boundary():
    assert not completed_turn(
        events() + b'\n{"type":"item.completed","item":{"type":"command_execution"}}'
    )


def test_actual_process_failure_timeout_and_raw_bytes():
    raw = b"original\r\n\x00bytes"
    captured = capture_process(
        [sys.executable, "-c", f"import sys;sys.stdout.buffer.write({raw!r});sys.exit(7)"], b"", 5
    )
    assert captured.stdout.data == raw and captured.returncode == 7 and not captured.timed_out
    timed = capture_process([sys.executable, "-c", "import time;time.sleep(3)"], b"", 0.05)
    assert timed.timed_out


def test_claim_exclusive_and_no_actual_result_without_provenance(tmp_path):
    path = tmp_path / "claimed.json"
    durable_claim(path, b"first")
    with pytest.raises(FileExistsError):
        durable_claim(path, b"second")
    assert path.read_bytes() == b"first"
    with pytest.raises(ValidationError):
        AttemptResult.model_validate({"status": "completed", "reason": "invented"})


@pytest.mark.parametrize(
    "exposure,consumed,rerun",
    [("not_exposed", False, None), ("unknown", True, None), ("exposed", True, False)],
)
def test_attempt_abort_exposure_contract(exposure, consumed, rerun):
    item = AttemptAbortV1(
        status="not_run" if exposure == "not_exposed" else "failed",
        reason="synthetic",
        last_state="claimed" if exposure == "not_exposed" else "guest_ready",
        exposure_state=exposure,
        attempt_consumed=consumed,
        rerun_permitted=rerun,
        cleanup_succeeded=True,
    )
    assert item.attempt_consumed is consumed
    with pytest.raises(ValidationError):
        AttemptAbortV1.model_validate(item.model_dump() | {"attempt_consumed": not consumed})


def test_no_delegation_does_not_create_cost_measurement():
    item = DelegationObservation(delegate_called=False, count=0, provider_sends=0)
    assert item.provider_api_cost_microusd is None
    with pytest.raises(ValidationError):
        DelegationObservation(delegate_called=False, count=0, provider_api_cost_microusd=0)


def request(**updates):
    args = dict(
        project="synthetic-session",
        task_id="synthetic-session",
        request_key="synthetic-session",
        instructions="synthetic only",
        acceptance_criteria=["one fact"],
        query="input.txt",
        privacy="local_only",
        allow_cloud=False,
        require_citations=True,
    )
    args.update(updates)
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "devhub_delegate", "arguments": args},
        }
    ).encode()


def test_bridge_scope_enforces_optional_single_local_call():
    gate = MCPGate("synthetic-session")
    assert gate.calls == 0
    gate.request(request())
    assert gate.calls == 1
    with pytest.raises(ValueError):
        gate.request(request())
    for patch in (
        {"privacy": "public"},
        {"allow_cloud": True},
        {"project": "other"},
        {"require_citations": False},
        {"request_key": "other"},
    ):
        other = MCPGate("synthetic-session")
        with pytest.raises(ValueError):
            other.request(request(**patch))
        assert other.calls == 0 and other.violation
    for method in ("resources/read", "prompts/get", "tools/other"):
        with pytest.raises(ValueError):
            MCPGate("s").request(json.dumps({"method": method}).encode())


def test_proxy_allows_codex_service_not_providers_or_loopback():
    assert connect_target(b"CONNECT chatgpt.com:443 HTTP/1.1\r\n\r\n") == "chatgpt.com"
    for target in (
        "api.groq.com:443",
        "generativelanguage.googleapis.com:443",
        "127.0.0.1:11434",
        "chatgpt.com.evil.invalid:443",
        "user@chatgpt.com:443",
        "chatgpt.com:80",
    ):
        with pytest.raises(ValueError):
            connect_target(f"CONNECT {target} HTTP/1.1\r\n\r\n".encode())


def test_secret_canary_never_enters_artifacts():
    with pytest.raises(ValueError, match="withheld"):
        safe_artifacts((b"text private-canary text",), (b"private-canary",))
    safe_artifacts((b"safe bytes",))


def test_protocol_pins_and_no_execution_without_review(repo, protocol, boundary, tmp_path):
    _, *_ = boundary
    bindings = RuntimeBindings(qualification_manifest_id="f" * 64)
    manifest = plan(repo, protocol, "dry")
    with pytest.raises(ValueError, match="review"):
        execute_next(
            repo,
            protocol,
            manifest,
            bindings,
            tmp_path / "run",
            tmp_path / "auth",
            tmp_path / "probe",
            tmp_path / "accepted-state",
        )
    with pytest.raises(ValidationError):
        ExperimentProtocol(**{**protocol.model_dump(), "timeout_seconds": 0})
    with pytest.raises(ValidationError):
        ExperimentProtocol(**{**protocol.model_dump(), "common_instructions": "tuned"})
    changed = ExperimentProtocol(**{**protocol.model_dump(), "codex_model": "explicit-test-model"})
    assert changed.hashes()["codex_config"] != protocol.hashes()["codex_config"]


def quality(accepted=True, correction="none", duration=20000, valid=True):
    return ComparisonInput(
        quality=Quality(acceptance_pass=accepted, human_correction=correction),
        duration_ms=duration,
        technically_valid=valid,
        timing_valid=True,
    )


def test_frozen_comparison_raw_dimensions(protocol):
    assert compare(quality(False, "major"), quality(), protocol).result == "B better"
    assert compare(quality(), quality(duration=24000), protocol).result == "equivalent"
    assert compare(quality(duration=20000), quality(duration=26000), protocol).result == "A better"
    assert compare(quality(correction="minor"), quality(), protocol).dimension == "human_correction"
    assert compare(quality(accepted=None), quality(), protocol).result == "inconclusive"
    assert compare(quality(duration=None), quality(), protocol).result == "inconclusive"
    assert compare(quality(valid=False), quality(), protocol).result == "inconclusive"
    assert (
        compare(quality(False, "major"), quality(False, "major"), protocol).result == "inconclusive"
    )


def test_reviewer_requirements_from_frozen_oracles_only(repo):
    rules = reviewer_rules(repo)
    assert len(rules) == 12
    assert {r["fixture_id"] for r in rules if r["requires_isolated_test_execution"]} == {
        "tests-01",
        "tests-02",
    }
    assert all(r["output"] == "text_only" and not r["needs_files_during_execution"] for r in rules)
    assert (
        next(r for r in rules if r["fixture_id"] == "direct-01")["manual_checks"][
            "expected_delegation"
        ]
        is False
    )


@pytest.mark.parametrize("exit_code,timed_out", [(0, False), (7, False), (None, True)])
def test_synthetic_engine_freezes_unmodified_output_and_failure(
    boundary, protocol, tmp_path, monkeypatch, exit_code, timed_out
):
    bindings, packet, bridge, capture, bootstrap, auth, host_manifest = boundary
    import devhub.experiment_launch as mod

    monkeypatch.setattr(mod.platform, "system", lambda: "Linux")
    commands = []

    def run(args, **kwargs):
        commands.append(args)
        code = 1 if "inspect" in args else 0
        stdout = ("d" * 64 + "\n").encode() if "create" in args else b""
        return subprocess.CompletedProcess(args, code, stdout, b"")

    monkeypatch.setattr(mod.subprocess, "run", run)
    raw = b"unchanged\r\nfinal\x00"

    def process(*args, **kwargs):
        ready = {
            "schema_version": 1,
            "kind": "guest_ready",
            "session_id": "synthetic-session",
            "plan_sha256": "c" * 64,
            "prompt_sha256": digest(b"SYNTHETIC ONLY"),
            "prompt_length": len(b"SYNTHETIC ONLY"),
            "protocol_sha256": bindings.protocol_sha256,
            "bootstrap_sha256": bindings.bootstrap_sha256,
        }
        (capture / "guest-ready.json").write_text(json.dumps(ready))

        def accept():
            frame_path = capture / "task-frame.json"
            while True:
                try:
                    frame = json.loads(frame_path.read_bytes())
                    break
                except (FileNotFoundError, PermissionError):
                    time.sleep(0.005)
            (capture / "task-accepted.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "kind": "task_accepted",
                        "session_id": frame["session_id"],
                        "prompt_sha256": frame["prompt_sha256"],
                        "prompt_length": frame["prompt_length"],
                    }
                )
            )

        thread = threading.Thread(target=accept)
        thread.start()
        kwargs["input_driver"](object(), time.monotonic() + 5, threading.Event())
        thread.join(timeout=5)
        (capture / "final.txt").write_bytes(raw)
        now = datetime.now(UTC)
        if timed_out:
            kwargs["terminate_execution"]()
        stdout = CapturedStream(
            events(),
            CapturedStreamV1(
                retained_bytes=len(events()),
                observed_bytes=len(events()),
                truncated=False,
                retained_sha256=digest(events()),
            ),
        )
        stderr = CapturedStream(
            b"",
            CapturedStreamV1(
                retained_bytes=0, observed_bytes=0, truncated=False, retained_sha256=digest(b"")
            ),
        )
        return ProcessCapture(
            stdout=stdout,
            stderr=stderr,
            returncode=exit_code,
            timed_out=timed_out,
            output_limit_exceeded=False,
            secret_detected=False,
            input_error=None,
            started_at=now,
            ended_at=now,
            duration_ns=10,
        )

    monkeypatch.setattr(mod, "capture_process", process)
    monkeypatch.setattr(
        mod.subprocess,
        "check_output",
        lambda *args, **kwargs: json.dumps(
            {"Running": False, "ExitCode": exit_code if exit_code is not None else 137}
        ).encode(),
    )
    dest = tmp_path / "attempt"
    result = launch_container(
        session(),
        protocol,
        bindings,
        packet,
        bridge,
        capture,
        bootstrap,
        auth,
        host_manifest,
        dest,
        b"SYNTHETIC ONLY",
        reviewed_plan_sha256="c" * 64,
        secret_values=(),
        delegation=lambda: DelegationObservation(delegate_called=False, count=0, provider_sends=0),
    )
    assert (dest / "output.bin").read_bytes() == raw
    assert result.provenance.output_sha256 == digest(raw)
    assert result.status == ("completed" if exit_code == 0 and not timed_out else "failed")
    assert any("rm" in args and "--force" in args for args in commands)
    assert result.executor_retries == 0


def test_local_settlement_cost_and_usage_are_separate():
    from devhub.delegate import DelegationResult

    handoff = DelegationResult(
        status="failed",
        reason="invalid_output",
        provider="ollama",
        model="fixture",
        actual_input_tokens=81,
        actual_output_tokens=11,
        accounting="settled",
        execution="completed",
        accounting_reference="reservation",
        output_validation="failed",
    )
    observed = DelegationObservation(
        delegate_called=True,
        count=1,
        handoff=handoff,
        outbox_transitions=("reserved", "dispatched", "settled"),
        provider_sends=1,
        provider_api_cost_microusd=0,
    )
    assert observed.handoff.actual_input_tokens == 81
    assert observed.handoff.status == "failed"
    with pytest.raises(ValidationError):
        DelegationObservation(
            delegate_called=True, count=1, handoff=handoff, provider_api_cost_microusd=0
        )


@pytest.mark.skipif(sys.platform != "linux", reason="Unix transport selected for real launcher")
def test_actual_mcp_unix_bridge_only_synthetic_runtime(tmp_path):
    import socket
    import time

    from mcp.types import LATEST_PROTOCOL_VERSION

    from devhub.experiment_bridge import UnixBridge

    code = (
        "from devhub.delegate import DelegationResult; "
        "from devhub.delegate_server import create_delegation_server; "
        'R=type("R",(),{"run":lambda self,request: '
        'DelegationResult(status="denied",reason="offline_stub")}); '
        "create_delegation_server(R()).run()"
    )
    gate = MCPGate("synthetic-session")
    bridge = UnixBridge(
        tmp_path / "mcp.sock",
        lambda conn: gate.serve(conn, [sys.executable, "-c", code]),
        once=True,
    )
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(15)
            connection.connect(str(tmp_path / "mcp.sock"))
            stream = connection.makefile("rwb")

            def send(data):
                stream.write(json.dumps(data).encode() + b"\n")
                stream.flush()

            send(
                {
                    "jsonrpc": "2.0",
                    "id": 0,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": LATEST_PROTOCOL_VERSION,
                        "capabilities": {},
                        "clientInfo": {"name": "offline-test", "version": "1"},
                    },
                }
            )
            assert "result" in json.loads(stream.readline())
            send({"jsonrpc": "2.0", "method": "notifications/initialized"})
            send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            assert [t["name"] for t in json.loads(stream.readline())["result"]["tools"]] == [
                "devhub_delegate"
            ]
            stream.write(request() + b"\n")
            stream.flush()
            assert "result" in json.loads(stream.readline())
            assert gate.calls == 1 and gate.handoff.reason == "offline_stub"
            stream.close()
    finally:
        bridge.close()
    time.sleep(0.05)
    assert not gate.violation
