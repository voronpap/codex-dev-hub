"""Linux OCI executor boundary. API only: the CLI exposes dry-run, never execution.

Images, the scoped egress bridge and local-only MCP bridge must be reviewed and
provisioned before calling this boundary. No implicit pull or host execution fallback.
"""

import json
import os
import platform
import re
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, cast

from pydantic import Field, JsonValue, model_validator

from devhub.benchmark import Digest, canonical, digest, write_new, write_sealed
from devhub.delegate import DelegationResult
from devhub.events import AccountingEvent
from devhub.experiment import ExperimentProtocol, PlannedSession, RuntimeBindings
from devhub.models import Contract

DOCKER = ("docker", "--host=unix:///var/run/docker.sock")


class ExecutorProvenance(Contract):
    kind: Literal["linux_oci_process"]
    session_id: str
    plan_sha256: Digest
    protocol_sha256: Digest
    image_id: str
    command_sha256: Digest
    container_id: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    started_at: datetime
    ended_at: datetime
    duration_ns: Annotated[int, Field(ge=0)]
    exit_code: int | None
    launcher_exit_code: int | None
    timed_out: bool
    task_exposed: bool
    stdout_sha256: Digest
    stderr_sha256: Digest
    output_sha256: Digest | None

    @model_validator(mode="after")
    def timestamps(self) -> "ExecutorProvenance":
        if any(t.utcoffset() is None for t in (self.started_at, self.ended_at)):
            raise ValueError("UTC timestamps required")
        if self.ended_at < self.started_at:
            raise ValueError("Invalid timing")
        return self


class CodexUsage(Contract):
    parser: Literal["exec_jsonl_turn_completed_v1", "unavailable"] = "unavailable"
    input_tokens: Annotated[int, Field(ge=0)] | None = None
    output_tokens: Annotated[int, Field(ge=0)] | None = None
    cached_input_tokens: Annotated[int, Field(ge=0)] | None = None
    context_usage: None = None
    internal_retries: None = None
    source_sha256: Digest


def codex_usage(raw: bytes, version: str, expected_version: str) -> CodexUsage:
    """Documented exec JSONL event, not UI text. Fail to null on ambiguity/schema drift."""
    empty = CodexUsage(source_sha256=digest(raw))
    if version != expected_version:
        return empty
    try:
        events = [json.loads(line) for line in raw.splitlines() if line.strip()]
        if any(not isinstance(e, dict) for e in events):
            return empty
        completed = [e for e in events if e.get("type") == "turn.completed"]
        if (
            len(completed) != 1
            or sum(e.get("type") == "thread.started" for e in events) != 1
            or sum(e.get("type") == "turn.started" for e in events) != 1
            or any(e.get("type") in {"turn.failed", "error"} for e in events)
        ):
            return empty
        usage = completed[0]["usage"]
        if any(
            type(usage[k]) is not int or usage[k] < 0 for k in ("input_tokens", "output_tokens")
        ):
            return empty
        cached = usage.get("cached_input_tokens")
        if cached is not None and (
            type(cached) is not int or not 0 <= cached <= usage["input_tokens"]
        ):
            return empty
        return CodexUsage(
            parser="exec_jsonl_turn_completed_v1",
            input_tokens=usage["input_tokens"],
            output_tokens=usage["output_tokens"],
            cached_input_tokens=cached,
            source_sha256=digest(raw),
        )
    except (ValueError, KeyError, TypeError):
        return empty


class DelegationObservation(Contract):
    delegate_called: bool | None
    count: Annotated[int, Field(ge=0, le=1)] | None
    handoff: DelegationResult | None = None
    outbox_transitions: tuple[str, ...] = ()
    accounting_events: tuple[AccountingEvent, ...] = ()
    provider_api_cost_microusd: Literal[0] | None = None
    provider_sends: Literal[0, 1] | None = None

    @model_validator(mode="after")
    def local_accounting(self) -> "DelegationObservation":
        if self.delegate_called is False:
            if self.count != 0 or self.handoff or self.outbox_transitions:
                raise ValueError("No delegation cannot have inference measurements")
        if self.delegate_called is True and self.count != 1:
            raise ValueError("Observed call count required")
        if self.handoff and self.handoff.provider not in {None, "ollama"}:
            raise ValueError("Unexpected cloud routing: abort")
        if self.provider_api_cost_microusd == 0 and not (
            self.delegate_called is True
            and self.handoff is not None
            and self.handoff.provider == "ollama"
            and self.handoff.accounting == "settled"
            and self.handoff.actual_input_tokens is not None
            and self.handoff.actual_output_tokens is not None
            and self.outbox_transitions == ("reserved", "dispatched", "settled")
        ):
            raise ValueError("API cost requires actual local inference evidence")
        return self


class AttemptResult(Contract):
    provenance: ExecutorProvenance
    status: Literal["completed", "failed", "not_run"]
    reason: str
    codex_usage: CodexUsage
    delegation: DelegationObservation
    executor_retries: Literal[0] = 0
    benchmark_reruns: Literal[0] = 0
    quality_benchmark: None = None
    delegation_value: None = None
    savings: None = None

    @model_validator(mode="after")
    def actual_attempt(self) -> "AttemptResult":
        p = self.provenance
        if self.status == "completed" and (
            not p.task_exposed or p.exit_code != 0 or p.timed_out or p.output_sha256 is None
        ):
            raise ValueError("No completed result without actual executor provenance")
        if self.status == "not_run" and p.task_exposed:
            raise ValueError("Post-exposure crash is an experiment attempt")
        return self


def codex_argv(session: PlannedSession, protocol: ExperimentProtocol) -> list[str]:
    args = [
        "codex",
        "exec",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--cd",
        "/packet",
        "--json",
        "--color",
        "never",
        "-o",
        "/capture/final.txt",
    ]
    if protocol.codex_model is not None:
        args += ["--model", protocol.codex_model]
    for option in protocol.codex_overrides():
        args += ["-c", option]
    if session.arm == "B":
        # No host paths, secrets, diagnostic tools or arbitrary endpoints.
        args += [
            "-c",
            'mcp_servers.devhub_delegate.command="python3"',
            "-c",
            'mcp_servers.devhub_delegate.args=["/bootstrap.py","mcp"]',
            "-c",
            "mcp_servers.devhub_delegate.required=true",
            "-c",
            'mcp_servers.devhub_delegate.enabled_tools=["devhub_delegate"]',
            "-c",
            'mcp_servers.devhub_delegate.tools.devhub_delegate.approval_mode="approve"',
        ]
    return [*args, "-"]


def mount(path: Path, target: str, readonly: bool = True) -> list[str]:
    if "," in str(path) or "\n" in str(path) or not path.is_absolute() or path.is_symlink():
        raise ValueError("Unsafe mount path")
    return ["--mount", f"type=bind,src={path},dst={target}" + (",readonly" if readonly else "")]


def container_command(
    session: PlannedSession,
    bindings: RuntimeBindings,
    packet: Path,
    bridge: Path,
    capture: Path,
    bootstrap: Path,
    auth: Path,
) -> list[str]:
    expected = {"proxy.sock"} | ({"mcp.sock"} if session.arm == "B" else set())
    if {p.name for p in bridge.iterdir()} != expected:
        raise ValueError("Unexpected bridge access")
    if {p.name for p in packet.iterdir()} != {
        "input.txt",
        "task.txt",
        "instructions.txt",
        "session.json",
    }:
        raise ValueError("Packet contains unexpected data")
    if any(p.is_symlink() for p in packet.iterdir()) or any(capture.iterdir()):
        raise ValueError("Packet links or reused output directory")
    if digest(bootstrap.read_bytes()) != bindings.bootstrap_sha256:
        raise ValueError("Bootstrap changed")
    return [
        *DOCKER,
        "create",
        "--pull=never",
        "--name",
        session.session_id,
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=1000:1000",
        "--pids-limit=128",
        "--memory=2g",
        "--cpus=2",
        "--init",
        "-i",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m,mode=1777",
        "--tmpfs",
        "/home/runner:rw,noexec,nosuid,size=64m,uid=1000,gid=1000",
        "--env",
        "HOME=/home/runner",
        "--env",
        "CODEX_HOME=/home/runner/.codex",
        "--env",
        "HTTP_PROXY=http://127.0.0.1:18080",
        "--env",
        "HTTPS_PROXY=http://127.0.0.1:18080",
        "--env",
        "NO_PROXY=",
        "--env",
        "LANG=C.UTF-8",
        *mount(packet, "/packet"),
        *mount(bridge, "/bridge"),
        *mount(capture, "/capture", False),
        *mount(bootstrap, "/bootstrap.py"),
        *mount(auth, "/auth.json"),
        "--entrypoint",
        "python3",
        bindings.image_id,
        "/bootstrap.py",
        "run",
    ]


def safe_artifacts(blobs: tuple[bytes, ...], secret_values: tuple[bytes, ...] = ()) -> None:
    patterns = (
        rb"sk-[A-Za-z0-9_-]{20,}",
        rb"gh[pousr]_[A-Za-z0-9]{20,}",
        rb"github_pat_[A-Za-z0-9_]{20,}",
        rb"gsk_[A-Za-z0-9]{30,}",
        rb"AIza[A-Za-z0-9_-]{30,}",
        rb"AQ\.[A-Za-z0-9_-]{30,}",
        rb"-----BEGIN .*PRIVATE KEY-----",
        rb"eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.",
    )
    if any(
        any(re.search(pattern, raw) for pattern in patterns)
        or any(value and value in raw for value in secret_values)
        for raw in blobs
    ):
        raise ValueError("Artifact withheld: possible credential disclosure; abort run")


def capture_process(
    argv: list[str],
    stdin: bytes,
    timeout: int,
) -> tuple[bytes, bytes, int | None, bool, datetime, datetime, int]:
    """Fixed argv, empty inherited environment. No shell and no automatic retry."""
    started = datetime.now(UTC)
    tick = time.perf_counter_ns()
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": os.defpath, "LANG": "C.UTF-8"},
    )
    timed_out = False
    try:
        out, err = process.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        out, err = process.communicate(timeout=10)
    return (
        out,
        err,
        process.returncode,
        timed_out,
        started,
        datetime.now(UTC),
        time.perf_counter_ns() - tick,
    )


def durable_claim(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if os.name == "posix":
        descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def completed_turn(raw: bytes) -> bool:
    try:
        events = [json.loads(line) for line in raw.splitlines() if line.strip()]
        if any(not isinstance(e, dict) for e in events):
            return False
        if any(e.get("type") in {"turn.failed", "error"} for e in events):
            return False
        if any(
            e.get("item", {}).get("type")
            in {"command_execution", "file_change", "web_search", "collab_tool_call"}
            for e in events
        ):
            return False
        return bool(
            sum(e.get("type") == "thread.started" for e in events) == 1
            and sum(e.get("type") == "turn.started" for e in events) == 1
            and sum(e.get("type") == "turn.completed" for e in events) == 1
        )
    except (ValueError, TypeError, AttributeError):
        return False


def launch_container(
    session: PlannedSession,
    protocol: ExperimentProtocol,
    bindings: RuntimeBindings,
    packet: Path,
    bridge: Path,
    capture: Path,
    bootstrap: Path,
    auth: Path,
    destination: Path,
    prompt: bytes,
    *,
    reviewed_plan_sha256: str,
    secret_values: tuple[bytes, ...],
    delegation: Callable[[], DelegationObservation],
) -> AttemptResult:
    """Low-level boundary; orchestration must preflight and hold bridges for its lifetime.

    There is deliberately no CLI execute option in 3G-B. Review exact plan/environment
    before wiring this API into an experiment coordinator.
    """
    if platform.system() != "Linux":
        raise ValueError("Linux OCI boundary required; no native host fallback")
    if (
        bindings.protocol_sha256 != protocol.hashes()["protocol"]
        or reviewed_plan_sha256 != bindings.reviewed_plan_sha256
        or bindings.environment.codex_cli_version != protocol.codex_cli_version
        or bindings.environment.ollama_digest != protocol.ollama.model_digest
    ):
        raise ValueError("Reviewed environment/protocol binding changed")
    command = container_command(session, bindings, packet, bridge, capture, bootstrap, auth)
    destination.mkdir(parents=True, exist_ok=False)
    # Durable attempt claim before exposing the packet. Never resume/reuse this directory.
    durable_claim(
        destination / "claimed.json",
        canonical(
            {
                "session": session.session_id,
                "plan_sha256": reviewed_plan_sha256,
                "command_sha256": digest(canonical(cast(JsonValue, {"argv": command}))),
            }
        ),
    )
    try:
        created = subprocess.run(
            command, capture_output=True, check=False, env={"PATH": os.defpath}, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        write_sealed(
            destination / "not-run.json",
            canonical(
                {
                    "status": "not_run",
                    "reason": "container_creation_unconfirmed",
                    "task_exposed": False,
                }
            ),
        )
        raise
    if created.returncode != 0:
        write_sealed(
            destination / "not-run.json",
            canonical(
                {"status": "not_run", "reason": "container_create_failed", "task_exposed": False}
            ),
        )
        raise RuntimeError("Container creation failed; claim consumed")
    cid = created.stdout.decode().strip()
    if re.fullmatch(r"[a-f0-9]{64}", cid) is None:
        raise RuntimeError("Invalid container provenance; abort")
    tick = time.perf_counter_ns()
    start = datetime.now(UTC)
    try:
        # Time starts immediately before docker start/attach; includes Codex startup and tools.
        out, err, code, timeout, _, _, _ = capture_process(
            [*DOCKER, "start", "--attach", "--interactive", cid],
            stdin=prompt,
            timeout=protocol.timeout_seconds,
        )
        if timeout:
            subprocess.run([*DOCKER, "kill", cid], capture_output=True, timeout=15, check=False)
        state = json.loads(
            subprocess.check_output(
                [*DOCKER, "inspect", "--format", "{{json .State}}", cid], timeout=10
            )
        )
        if state.get("Running") is not False or type(state.get("ExitCode")) is not int:
            raise RuntimeError("Container did not reach a verified exit state")
        container_code = state["ExitCode"]
        final_path = capture / "final.txt"
        raw = (
            final_path.read_bytes()
            if final_path.is_file() and not final_path.is_symlink()
            else None
        )
        end = datetime.now(UTC)
        elapsed = time.perf_counter_ns() - tick
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError):
        write_sealed(
            destination / "failed.json",
            canonical(
                {
                    "status": "failed",
                    "reason": "executor_process_failure",
                    "task_exposed": True,
                    "retry": 0,
                }
            ),
        )
        raise
    finally:
        # Killing the CLI alone does not kill the container. Stop the complete process tree.
        subprocess.run([*DOCKER, "kill", cid], capture_output=True, timeout=15, check=False)
    safe_artifacts((out, err, raw or b""), secret_values)
    usage = codex_usage(out, bindings.environment.codex_cli_version, protocol.codex_cli_version)
    complete = (
        code == 0
        and container_code == 0
        and not timeout
        and raw is not None
        and completed_turn(out)
    )
    receipt = ExecutorProvenance(
        kind="linux_oci_process",
        session_id=session.session_id,
        plan_sha256=reviewed_plan_sha256,
        protocol_sha256=bindings.protocol_sha256,
        image_id=bindings.image_id,
        command_sha256=digest(canonical(cast(JsonValue, {"argv": command}))),
        container_id=cid,
        started_at=start,
        ended_at=end,
        duration_ns=elapsed,
        exit_code=container_code,
        launcher_exit_code=code,
        timed_out=timeout,
        task_exposed=True,
        stdout_sha256=digest(out),
        stderr_sha256=digest(err),
        output_sha256=digest(raw) if raw is not None else None,
    )
    result = AttemptResult(
        provenance=receipt,
        status="completed" if complete else "failed",
        reason="output_captured" if complete else "timeout" if timeout else "executor_failed",
        codex_usage=usage,
        delegation=delegation(),
    )
    if raw is not None:
        write_new(destination / "output.bin", raw)  # exact bytes; no normalization
    write_new(destination / "events.jsonl", out)
    write_new(destination / "stderr.bin", err)
    write_sealed(destination / "result.json", canonical(result.model_dump(mode="json")))
    return result
