"""Linux OCI executor boundary. API only: the CLI exposes dry-run, never execution.

Images, the scoped egress bridge and local-only MCP bridge must be reviewed and
provisioned before calling this boundary. No implicit pull or host execution fallback.
"""

import base64
import json
import os
import platform
import re
import subprocess
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Annotated, Literal, cast

from pydantic import Field, JsonValue, model_validator

from devhub.benchmark import Digest, canonical, digest, write_new, write_sealed
from devhub.delegate import DelegationResult
from devhub.events import AccountingEvent
from devhub.experiment import ExperimentProtocol, PlannedSession
from devhub.experiment_observation import BArmDelegationObservationV2
from devhub.models import Contract
from devhub.process_capture import CapturedStreamV1, ProcessCapture, capture_process

DOCKER = ("docker", "--host=unix:///var/run/docker.sock")
TASK_PAYLOAD_BYTE_LIMIT = 1024 * 1024
FINAL_OUTPUT_BYTE_LIMIT = 1024 * 1024
STAGE3G_HOST_MANIFEST_CONTAINER = "/stage3g-host.json"


class ContainerRuntimeSpec(Contract):
    """Derived launch mechanics; never an independent execution authority."""

    image_id: Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
    bootstrap_sha256: Digest
    protocol_sha256: Digest
    reviewed_plan_sha256: Digest
    codex_cli_version: str = Field(min_length=1)


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
    exposure_state: Literal["not_exposed", "exposed", "unknown"]
    attempt_consumed: bool
    cleanup_succeeded: bool
    stdout: CapturedStreamV1
    stderr: CapturedStreamV1
    output_sha256: Digest | None

    @model_validator(mode="after")
    def timestamps(self) -> "ExecutorProvenance":
        if any(t.utcoffset() is None for t in (self.started_at, self.ended_at)):
            raise ValueError("UTC timestamps required")
        if self.ended_at < self.started_at:
            raise ValueError("Invalid timing")
        if self.attempt_consumed != (self.exposure_state != "not_exposed"):
            raise ValueError("Attempt consumption must follow exposure evidence")
        return self


class GuestReadyV1(Contract):
    kind: Literal["guest_ready"] = "guest_ready"
    session_id: str
    plan_sha256: Digest
    prompt_sha256: Digest
    prompt_length: Annotated[int, Field(ge=1, le=TASK_PAYLOAD_BYTE_LIMIT)]
    protocol_sha256: Digest
    bootstrap_sha256: Digest


class TaskAcceptedV1(Contract):
    kind: Literal["task_accepted"] = "task_accepted"
    session_id: str
    prompt_sha256: Digest
    prompt_length: Annotated[int, Field(ge=1, le=TASK_PAYLOAD_BYTE_LIMIT)]


class TaskFrameV1(Contract):
    kind: Literal["task_frame"] = "task_frame"
    session_id: str
    prompt_sha256: Digest
    prompt_length: Annotated[int, Field(ge=1, le=TASK_PAYLOAD_BYTE_LIMIT)]
    payload_base64: str = Field(min_length=1, max_length=1_398_104)


class AttemptAbortV1(Contract):
    status: Literal["failed", "not_run"]
    reason: str
    last_state: Literal["claimed", "container_created", "guest_ready", "task_exposed"]
    exposure_state: Literal["not_exposed", "exposed", "unknown"]
    attempt_consumed: bool
    rerun_permitted: Literal[False] | None
    review_required: Literal[True] = True
    cleanup_succeeded: bool | None

    @model_validator(mode="after")
    def exposure(self) -> "AttemptAbortV1":
        if self.attempt_consumed != (self.exposure_state != "not_exposed"):
            raise ValueError("Attempt consumption must follow exposure evidence")
        if self.exposure_state == "exposed" and self.rerun_permitted is not False:
            raise ValueError("Exposed attempts cannot be rerun")
        if self.exposure_state != "exposed" and self.rerun_permitted is not None:
            raise ValueError("Unexposed or ambiguous failures require review")
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
    delegation: DelegationObservation | BArmDelegationObservationV2
    executor_retries: Literal[0] = 0
    benchmark_reruns: Literal[0] = 0
    quality_benchmark: None = None
    delegation_value: None = None
    savings: None = None

    @model_validator(mode="after")
    def actual_attempt(self) -> "AttemptResult":
        p = self.provenance
        if self.status == "completed" and (
            p.exposure_state != "exposed"
            or p.exit_code != 0
            or p.timed_out
            or p.output_sha256 is None
            or not p.cleanup_succeeded
        ):
            raise ValueError("No completed result without actual executor provenance")
        if self.status == "not_run" and p.exposure_state != "not_exposed":
            raise ValueError("Post-exposure crash is an experiment attempt")
        if (
            self.status == "completed"
            and isinstance(self.delegation, BArmDelegationObservationV2)
            and not self.delegation.delegation_success
        ):
            raise ValueError("No completed B arm without authoritative delegation success")
        return self


def delegation_complete_for_arm(
    arm: Literal["A", "B"],
    observation: DelegationObservation | BArmDelegationObservationV2,
) -> bool:
    """Arm B requires the strict authority-joined observation; Arm A has no delegation."""

    return arm == "A" or (
        isinstance(observation, BArmDelegationObservationV2) and observation.delegation_success
    )


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
        "--devhub-stage3g-host-manifest",
        STAGE3G_HOST_MANIFEST_CONTAINER,
        "--devhub-stage3g-arm",
        session.arm.lower(),
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
            'features.code_mode.direct_only_tool_namespaces=["mcp__devhub_delegate"]',
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
    runtime: ContainerRuntimeSpec,
    control: Path,
    bridge: Path,
    capture: Path,
    bootstrap: Path,
    auth: Path,
    host_manifest: Path,
) -> list[str]:
    expected = {"proxy.sock"} | ({"mcp.sock"} if session.arm == "B" else set())
    if {p.name for p in bridge.iterdir()} != expected:
        raise ValueError("Unexpected bridge access")
    # Task-bearing packet data is never mounted before the exposure handshake.
    if {p.name for p in control.iterdir()} != {"session.json"}:
        raise ValueError("Guest control contains unexpected data")
    if any(p.is_symlink() for p in control.iterdir()) or any(capture.iterdir()):
        raise ValueError("Control links or reused output directory")
    if digest(bootstrap.read_bytes()) != runtime.bootstrap_sha256:
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
        "--tmpfs",
        "/packet:rw,noexec,nosuid,size=16m,uid=1000,gid=1000",
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
        *mount(control, "/control"),
        *mount(bridge, "/bridge"),
        *mount(capture, "/capture", False),
        *mount(bootstrap, "/bootstrap.py"),
        *mount(auth, "/auth.json"),
        *mount(host_manifest, STAGE3G_HOST_MANIFEST_CONTAINER),
        "--entrypoint",
        "python3",
        runtime.image_id,
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


def durable_publish(path: Path, raw: bytes) -> None:
    """Publish a new control frame atomically and durably."""

    temporary = path.with_name(path.name + ".tmp")
    if path.exists() or temporary.exists():
        raise FileExistsError(path)
    durable_claim(temporary, raw)
    os.replace(temporary, path)
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


def cleanup_container(cid: str) -> bool:
    """Remove exactly one validated container and verify that it no longer exists."""

    if re.fullmatch(r"[a-f0-9]{64}", cid) is None:
        raise ValueError("Invalid container cleanup authority")
    try:
        removed = subprocess.run(
            [*DOCKER, "rm", "--force", cid], capture_output=True, timeout=20, check=False
        )
        probe = subprocess.run(
            [*DOCKER, "inspect", cid], capture_output=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return removed.returncode == 0 and probe.returncode != 0


def _abort(
    destination: Path,
    *,
    reason: str,
    last_state: Literal["claimed", "container_created", "guest_ready", "task_exposed"],
    exposure_state: Literal["not_exposed", "exposed", "unknown"],
    cleanup_succeeded: bool | None,
) -> None:
    item = AttemptAbortV1(
        status="not_run" if exposure_state == "not_exposed" else "failed",
        reason=reason,
        last_state=last_state,
        exposure_state=exposure_state,
        attempt_consumed=exposure_state != "not_exposed",
        rerun_permitted=False if exposure_state == "exposed" else None,
        cleanup_succeeded=cleanup_succeeded,
    )
    write_sealed(destination / "abort.json", canonical(item.model_dump(mode="json")))


def launch_container(
    session: PlannedSession,
    protocol: ExperimentProtocol,
    runtime: ContainerRuntimeSpec,
    control: Path,
    bridge: Path,
    capture: Path,
    bootstrap: Path,
    auth: Path,
    host_manifest: Path,
    destination: Path,
    prompt: bytes,
    *,
    reviewed_plan_sha256: str,
    secret_values: tuple[bytes, ...],
    delegation: Callable[[], DelegationObservation | BArmDelegationObservationV2],
) -> AttemptResult:
    """Low-level boundary; orchestration must preflight and hold bridges for its lifetime.

    There is deliberately no CLI execute option in 3G-B. Review exact plan/environment
    before wiring this API into an experiment coordinator.
    """
    if platform.system() != "Linux":
        raise ValueError("Linux OCI boundary required; no native host fallback")
    if (
        runtime.protocol_sha256 != protocol.hashes()["protocol"]
        or reviewed_plan_sha256 != runtime.reviewed_plan_sha256
        or runtime.codex_cli_version != protocol.codex_cli_version
    ):
        raise ValueError("Reviewed environment/protocol binding changed")
    if not 0 < len(prompt) <= TASK_PAYLOAD_BYTE_LIMIT:
        raise ValueError("Task payload exceeds reviewed control-channel limit")
    command = container_command(
        session, runtime, control, bridge, capture, bootstrap, auth, host_manifest
    )
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
        _abort(
            destination,
            reason="container_creation_unconfirmed",
            last_state="claimed",
            exposure_state="not_exposed",
            cleanup_succeeded=None,
        )
        raise
    if created.returncode != 0:
        _abort(
            destination,
            reason="container_create_failed",
            last_state="claimed",
            exposure_state="not_exposed",
            cleanup_succeeded=None,
        )
        raise RuntimeError("Container creation failed; claim consumed")
    cid = created.stdout.decode().strip()
    if re.fullmatch(r"[a-f0-9]{64}", cid) is None:
        _abort(
            destination,
            reason="invalid_container_identity",
            last_state="claimed",
            exposure_state="not_exposed",
            cleanup_succeeded=None,
        )
        raise RuntimeError("Invalid container provenance; abort")
    prompt_hash = digest(prompt)
    expected_ready = GuestReadyV1(
        session_id=session.session_id,
        plan_sha256=reviewed_plan_sha256,
        prompt_sha256=prompt_hash,
        prompt_length=len(prompt),
        protocol_sha256=runtime.protocol_sha256,
        bootstrap_sha256=runtime.bootstrap_sha256,
    )
    expected_accepted = TaskAcceptedV1(
        session_id=session.session_id,
        prompt_sha256=prompt_hash,
        prompt_length=len(prompt),
    )
    last_state: Literal["claimed", "container_created", "guest_ready", "task_exposed"] = (
        "container_created"
    )
    exposure_state: Literal["not_exposed", "exposed", "unknown"] = "not_exposed"
    capture_result: ProcessCapture | None = None
    state: dict[str, object] | None = None
    container_code: int | None = None
    raw: bytes | None = None
    final_output_limit_exceeded = False
    artifact_withheld = False
    execution_error: Exception | None = None
    cleanup_succeeded = False

    def wait_record(path: Path, deadline: float, stop: Event) -> bytes:
        while not path.is_file():
            if time.monotonic() >= deadline:
                raise RuntimeError(f"Missing {path.name}")
            if stop.is_set():
                raise RuntimeError("Executor output boundary terminated handshake")
            time.sleep(0.02)
        if path.is_symlink():
            raise RuntimeError(f"Unsafe {path.name}")
        return path.read_bytes()

    def handshake(process: subprocess.Popen[bytes], deadline: float, stop: Event) -> None:
        nonlocal exposure_state, last_state
        ready = GuestReadyV1.model_validate_json(
            wait_record(capture / "guest-ready.json", deadline, stop)
        )
        if ready != expected_ready:
            raise ValueError("Guest READY binding mismatch")
        last_state = "guest_ready"
        # Once the pending receipt is durable, a host crash during publication is
        # conservatively ambiguous rather than falsely declared unexposed.
        durable_claim(
            destination / "task-transfer-pending.json",
            canonical(
                {
                    "schema_version": 1,
                    "kind": "task_transfer_pending",
                    "session_id": session.session_id,
                    "plan_sha256": reviewed_plan_sha256,
                    "prompt_sha256": prompt_hash,
                    "prompt_length": len(prompt),
                    "container_id": cid,
                }
            ),
        )
        exposure_state = "unknown"
        frame = TaskFrameV1(
            session_id=session.session_id,
            prompt_sha256=prompt_hash,
            prompt_length=len(prompt),
            payload_base64=base64.b64encode(prompt).decode("ascii"),
        )
        durable_publish(capture / "task-frame.json", canonical(frame.model_dump(mode="json")))
        accepted = TaskAcceptedV1.model_validate_json(
            wait_record(capture / "task-accepted.json", deadline, stop)
        )
        if accepted != expected_accepted:
            raise ValueError("TASK_ACCEPTED binding mismatch")
        durable_claim(
            destination / "task-exposed.json",
            canonical(
                {
                    "schema_version": 1,
                    "kind": "task_exposed",
                    "session_id": session.session_id,
                    "plan_sha256": reviewed_plan_sha256,
                    "prompt_sha256": prompt_hash,
                    "prompt_length": len(prompt),
                    "container_id": cid,
                    "guest_ready_sha256": digest(canonical(ready.model_dump(mode="json"))),
                    "task_accepted_sha256": digest(canonical(accepted.model_dump(mode="json"))),
                    "exposed_at": datetime.now(UTC).isoformat(),
                    "task_exposed": True,
                }
            ),
        )
        exposure_state = "exposed"
        last_state = "task_exposed"

    def terminate_container() -> None:
        subprocess.run([*DOCKER, "kill", cid], capture_output=True, timeout=15, check=False)

    try:
        # The original timing boundary is preserved: start before docker start/attach,
        # including guest readiness, Codex startup and all tool execution.
        capture_result = capture_process(
            [*DOCKER, "start", "--attach", cid],
            stdin=None,
            timeout=protocol.timeout_seconds,
            input_driver=handshake,
            terminate_execution=terminate_container,
            secret_values=secret_values,
        )
        state = json.loads(
            subprocess.check_output(
                [*DOCKER, "inspect", "--format", "{{json .State}}", cid], timeout=10
            )
        )
        if state.get("Running") is not False or type(state.get("ExitCode")) is not int:
            raise RuntimeError("Container did not reach a verified exit state")
        container_code = cast(int, state["ExitCode"])
        final_path = capture / "final.txt"
        if final_path.is_file() and not final_path.is_symlink():
            if final_path.stat().st_size > FINAL_OUTPUT_BYTE_LIMIT:
                final_output_limit_exceeded = True
            else:
                raw = final_path.read_bytes()
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as error:
        execution_error = error
    finally:
        cleanup_succeeded = cleanup_container(cid)
    if capture_result is None:
        _abort(
            destination,
            reason="executor_start_failure" if execution_error else "executor_capture_missing",
            last_state=last_state,
            exposure_state=exposure_state,
            cleanup_succeeded=cleanup_succeeded,
        )
        if execution_error is not None:
            raise execution_error
        raise RuntimeError("Executor capture missing")
    out = capture_result.stdout.data
    err = capture_result.stderr.data
    try:
        safe_artifacts((out, err, raw or b""), secret_values)
    except ValueError:
        # Final-output scanning is a second boundary after incremental stream
        # scanning. Never persist a secret-bearing final/stream artifact.
        artifact_withheld = True
        out = b""
        err = b""
        raw = None
    usage = codex_usage(out, runtime.codex_cli_version, protocol.codex_cli_version)
    complete = (
        capture_result.returncode == 0
        and container_code == 0
        and not capture_result.timed_out
        and not capture_result.output_limit_exceeded
        and not final_output_limit_exceeded
        and not capture_result.secret_detected
        and not artifact_withheld
        and capture_result.input_error is None
        and raw is not None
        and completed_turn(out)
        and exposure_state == "exposed"
        and cleanup_succeeded
        and execution_error is None
    )
    receipt = ExecutorProvenance(
        kind="linux_oci_process",
        session_id=session.session_id,
        plan_sha256=reviewed_plan_sha256,
        protocol_sha256=runtime.protocol_sha256,
        image_id=runtime.image_id,
        command_sha256=digest(canonical(cast(JsonValue, {"argv": command}))),
        container_id=cid,
        started_at=capture_result.started_at,
        ended_at=capture_result.ended_at,
        duration_ns=capture_result.duration_ns,
        exit_code=container_code,
        launcher_exit_code=capture_result.returncode,
        timed_out=capture_result.timed_out,
        exposure_state=exposure_state,
        attempt_consumed=exposure_state != "not_exposed",
        cleanup_succeeded=cleanup_succeeded,
        stdout=capture_result.stdout.evidence,
        stderr=capture_result.stderr.evidence,
        output_sha256=digest(raw) if raw is not None else None,
    )
    delegation_observation = delegation()
    b_arm_delegation_complete = delegation_complete_for_arm(session.arm, delegation_observation)
    if session.arm == "B" and not b_arm_delegation_complete:
        complete = False
    result = AttemptResult(
        provenance=receipt,
        status="completed" if complete else "failed",
        reason=(
            "output_captured"
            if complete
            else "timeout"
            if capture_result.timed_out
            else "artifact_withheld"
            if capture_result.secret_detected or artifact_withheld
            else "output_limit_exceeded"
            if capture_result.output_limit_exceeded or final_output_limit_exceeded
            else "executor_cleanup_failed"
            if not cleanup_succeeded
            else "task_exposure_unproven"
            if exposure_state != "exposed"
            else "b_arm_delegation_incomplete"
            if session.arm == "B" and not b_arm_delegation_complete
            else "executor_failed"
        ),
        codex_usage=usage,
        delegation=delegation_observation,
    )
    if raw is not None:
        write_new(destination / "output.bin", raw)  # exact bytes; no normalization
    write_new(destination / "events.jsonl", out)
    write_new(destination / "stderr.bin", err)
    write_sealed(destination / "result.json", canonical(result.model_dump(mode="json")))
    if execution_error is not None:
        raise execution_error
    return result
