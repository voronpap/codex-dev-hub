"""One reviewed session coordinator. No bulk-run CLI; no execution during dry-run."""

import json
import platform
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, cast

from pydantic import JsonValue

from devhub.baseline import verified_cases
from devhub.benchmark import canonical, digest, read_sealed, write_new
from devhub.delegate import DelegationConfig, ProviderProfile
from devhub.events import EventOutbox
from devhub.experiment import (
    ARM_A,
    ARM_B,
    COMMON,
    ExperimentProtocol,
    PlannedSession,
    RuntimeBindings,
    plan,
)
from devhub.experiment_bridge import MCPGate, UnixBridge, proxy
from devhub.experiment_launch import (
    DOCKER,
    AttemptResult,
    DelegationObservation,
    codex_argv,
    launch_container,
)
from devhub.ledger import Ledger
from devhub.local import LocalConfig
from devhub.ollama import OllamaAdapter


def packet_bytes(
    repo: Path, session: PlannedSession, protocol: ExperimentProtocol
) -> dict[str, bytes]:
    case = next(c for c in verified_cases(repo / "benchmarks") if c["id"] == session.fixture_id)
    if (case["fixture_sha256"], case["oracle_sha256"]) != (
        session.fixture_sha256,
        session.oracle_sha256,
    ):
        raise ValueError("Fixture binding changed")
    fixture = json.loads((repo / "benchmarks" / case["fixture"]).read_bytes())
    instructions = COMMON + "\n" + (ARM_A if session.arm == "A" else ARM_B)
    return {
        "input.txt": fixture["input"].encode(),
        "task.txt": fixture["prompt"].encode(),
        "instructions.txt": instructions.encode(),
        "session.json": canonical(
            {
                "project": session.session_id,
                "task_id": session.session_id,
                "request_key": session.session_id,
                "codex_argv": cast(JsonValue, codex_argv(session, protocol)),
            }
        ),
    }


def environment_guard(repo: Path, bindings: RuntimeBindings, protocol: ExperimentProtocol) -> None:
    if platform.system() != "Linux":
        raise ValueError("Real execution requires reviewed Linux OCI environment")
    if (
        bindings.environment.devhub_commit
        != subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip()
    ):
        raise ValueError("Implementation changed")
    if (
        bindings.environment.os != platform.platform()
        or bindings.environment.python != platform.python_version()
        or bindings.environment.ollama_model != protocol.ollama.model
        or bindings.environment.ollama_version != protocol.ollama.version
    ):
        raise ValueError("Environment changed")
    image = json.loads(subprocess.check_output([*DOCKER, "image", "inspect", bindings.image_id]))[0]
    if image["Id"] != bindings.image_id or image["Config"].get("Volumes"):
        raise ValueError("Image identity or implicit mounts changed")
    allowed_env = {"PATH", "LANG", "LC_ALL", "HOME", "PYTHON_VERSION"}
    if any(entry.split("=", 1)[0] not in allowed_env for entry in image["Config"].get("Env") or []):
        raise ValueError("Image has unreviewed environment overrides")
    if image.get("Os") != "linux":
        raise ValueError("Linux image required")
    # Image's baked credentials/config/skills must also be excluded by operator image review.
    version = (
        subprocess.check_output(
            [
                "docker",
                "run",
                "--rm",
                "--pull=never",
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--entrypoint",
                "codex",
                bindings.image_id,
                "--version",
            ],
            timeout=30,
        )
        .decode()
        .strip()
    )
    if version != protocol.codex_cli_version:
        raise ValueError("Codex version changed")
    OllamaAdapter(protocol.ollama).inspect()  # metadata/tokenizer only, never inference


def secret_strings(value: Any) -> tuple[bytes, ...]:
    if isinstance(value, str):
        return (value.encode(),) if len(value) >= 6 else ()
    if isinstance(value, dict):
        return tuple(raw for item in value.values() for raw in secret_strings(item))
    if isinstance(value, list):
        return tuple(raw for item in value for raw in secret_strings(item))
    return ()


def execute_next(
    repo: Path,
    protocol: ExperimentProtocol,
    frozen_plan: dict[str, Any],
    bindings: RuntimeBindings,
    run_root: Path,
    auth_file: Path,
    isolation_probe: Path,
    accounting_root: Path,
    *,
    operator_reviewed: bool = False,
    qualification: Path | None = None,
) -> AttemptResult:
    """Opt-in API for the next reviewed phase, never called by 3G-B CLI/tests on fixtures.

    Fails closed without reviewed bindings. Source/run/controller storage stays outside
    every mount; only derived files for one arm are ever exposed.
    """
    if not operator_reviewed:
        raise ValueError("Explicit protocol/environment review required")
    from devhub.experiment_preflight import isolation_valid, require_ready

    if qualification is None or bindings.qualification_sha256 is None:
        raise ValueError("Stage 3G-C qualification required")
    qualification_raw = qualification.read_bytes()
    if digest(qualification_raw) != bindings.qualification_sha256:
        raise ValueError("Qualification evidence changed")
    require_ready(
        qualification_raw,
        {
            "image_id": bindings.image_id,
            "implementation_commit": bindings.environment.devhub_commit,
            "protocol_sha256": bindings.protocol_sha256,
            "plan_sha256": bindings.reviewed_plan_sha256,
            "bootstrap_sha256": bindings.bootstrap_sha256,
        },
    )
    proof_raw = isolation_probe.read_bytes()
    if digest(proof_raw) != bindings.isolation_probe_sha256:
        raise ValueError("Isolation proof changed")
    proof = json.loads(proof_raw)
    if not isolation_valid(proof, bindings.image_id, bindings.bootstrap_sha256):
        raise ValueError("Exact-image isolation proof required")
    current = plan(repo, protocol, frozen_plan["run_id"])
    if current != frozen_plan or digest(canonical(current)) != bindings.reviewed_plan_sha256:
        raise ValueError("Plan/config/implementation changed")
    if run_root.resolve().is_relative_to(repo.resolve()) or run_root.is_symlink():
        raise ValueError("Run storage must be external")
    run_root.mkdir(parents=True, exist_ok=True)
    if (run_root / "aborted.json").exists():
        raise ValueError("Run aborted; preserve it and use a new run ID")
    manifest_path = run_root / "plan.json"
    if not manifest_path.exists():
        if any(run_root.iterdir()):
            raise ValueError("Unbound run directory is not empty")
        write_new(manifest_path, canonical(current))
        write_new(run_root / "bindings.json", canonical(bindings.model_dump(mode="json")))
    if manifest_path.read_bytes() != canonical(current) or (
        run_root / "bindings.json"
    ).read_bytes() != (canonical(bindings.model_dump(mode="json"))):
        raise ValueError("Run binding changed")
    sessions = [PlannedSession.model_validate_json(json.dumps(s)) for s in frozen_plan["sessions"]]
    selected = None
    for session in sessions:
        target = run_root / "attempts" / session.session_id
        if target.exists():
            if selected is not None:
                raise ValueError("Execution order compromised")
            result_path = target / "result.json"
            if not result_path.exists():
                raise ValueError("Interrupted attempt cannot be repeated or skipped")
            prior = AttemptResult.model_validate_json(read_sealed(result_path))
            if (
                prior.status != "completed"
                or prior.provenance.session_id != session.session_id
                or prior.provenance.plan_sha256 != bindings.reviewed_plan_sha256
                or prior.provenance.output_sha256 != digest((target / "output.bin").read_bytes())
            ):
                raise ValueError("Failed/changed attempt cannot be repeated or skipped")
        elif selected is None:
            selected = session
    if selected is None:
        raise ValueError("All sessions attempted")
    session = selected
    volatile_capture = None
    try:
        environment_guard(repo, bindings, protocol)
        packets = packet_bytes(repo, session, protocol)
        control = run_root / "private" / session.session_id
        control.mkdir(parents=True, exist_ok=False)
        control.chmod(0o700)
        packet = control / "packet"
        packet.mkdir()
        for name, raw in packets.items():
            write_new(packet / name, raw)
        volatile_capture = tempfile.TemporaryDirectory(prefix="devhub-capture-", dir="/dev/shm")
        capture = Path(volatile_capture.name) / "capture"
        capture.mkdir()
        capture.chmod(0o777)  # only this fresh container's output; private ancestors on host
        bridge = control / "bridge"
        bridge.mkdir()
        bridge.chmod(0o755)
        # Auth is a separate runtime secret, never part of packet/config/result or its hashes.
        if auth_file.is_symlink() or not auth_file.is_file():
            raise ValueError("Explicit regular credential file required")
        auth = auth_file.resolve()
        auth_raw = auth.read_bytes()
        auth_data = json.loads(auth_raw)
        if auth_data.get("OPENAI_API_KEY") or not auth_data.get("tokens", {}).get("access_token"):
            raise ValueError("Only reviewed existing ChatGPT CLI authentication is allowed")
        secrets = secret_strings(auth_data)
        gateway = MCPGate(session.session_id)
        state = accounting_root.resolve()  # reuse accepted ledger, never mounted
        if not (state / "ledger.db").is_file() or state.is_relative_to(run_root.resolve()):
            raise ValueError("Existing accepted accounting state outside run required")
        if session.arm == "B":
            # Trusted Git snapshot for Brain contains only the two equivalent task source files.
            brain_root = control / "brain-source"
            brain_root.mkdir()
            for name in ("input.txt", "task.txt"):
                write_new(brain_root / name, packets[name])
            for args in (
                ["init", "-q"],
                ["add", "input.txt", "task.txt"],
                [
                    "-c",
                    "user.name=Benchmark",
                    "-c",
                    "user.email=benchmark@example.invalid",
                    "commit",
                    "-qm",
                    "Frozen task input",
                ],
            ):
                subprocess.run(
                    ["git", "-c", "core.hooksPath=/dev/null", "-C", str(brain_root), *args],
                    check=True,
                    capture_output=True,
                    timeout=10,
                )
            config = DelegationConfig(
                profiles=(
                    ProviderProfile(
                        id="accepted-local",
                        config=LocalConfig(
                            project=session.session_id,
                            root=str(brain_root),
                            state_root=str(state),
                            approved_paths=("input.txt", "task.txt"),
                            authoritative_paths=("input.txt", "task.txt"),
                            ollama=protocol.ollama,
                        ),
                    ),
                )
            )
            config_path = control / "local.json"
            write_new(config_path, canonical(config.model_dump(mode="json")))
            server_argv = [
                sys.executable,
                "-m",
                "devhub.delegate_server",
                "--config",
                str(config_path),
            ]
        bridges = [UnixBridge(bridge / "proxy.sock", proxy)]
        if session.arm == "B":
            bridges.append(
                UnixBridge(
                    bridge / "mcp.sock", lambda conn: gateway.serve(conn, server_argv), once=True
                )
            )

        def observed() -> DelegationObservation:
            if gateway.violation or any(b.failed for b in bridges):
                raise ValueError("Isolation/network/MCP boundary violation")
            handoff = gateway.handoff
            events = (
                EventOutbox(Ledger(state / "ledger.db")).pending(project=session.session_id)
                if state.exists()
                else ()
            )
            transitions = tuple(e.transition for e in events)
            settled = bool(handoff and handoff.accounting == "settled")
            return DelegationObservation(
                delegate_called=gateway.calls > 0,
                count=gateway.calls,
                handoff=handoff,
                outbox_transitions=transitions,
                accounting_events=events,
                provider_sends=1 if settled else 0 if not gateway.calls else None,
                provider_api_cost_microusd=0 if settled else None,
            )

        prompt = canonical(
            {
                "instructions": packets["instructions.txt"].decode(),
                "task": packets["task.txt"].decode(),
                "input": packets["input.txt"].decode(),
                "session": {
                    "project": session.session_id,
                    "task_id": session.session_id,
                    "request_key": session.session_id,
                },
            }
        )
        try:
            result = launch_container(
                session,
                protocol,
                bindings,
                packet,
                bridge,
                capture,
                repo / "scripts/benchmark_guest.py",
                auth,
                run_root / "attempts" / session.session_id,
                prompt,
                reviewed_plan_sha256=bindings.reviewed_plan_sha256,
                secret_values=secrets,
                delegation=observed,
            )
        finally:
            for b in bridges:
                b.close()
        environment_guard(repo, bindings, protocol)
        if result.status != "completed":
            raise ValueError("Failed/timed-out attempt preserved; run aborted")
        return result
    except Exception:
        if not (run_root / "aborted.json").exists():
            write_new(
                run_root / "aborted.json",
                canonical(
                    {
                        "session": session.session_id,
                        "reason": "preflight_or_attempt_failed",
                        "rerun_permitted": False,
                    }
                ),
            )
        raise
    finally:
        if volatile_capture is not None:
            volatile_capture.cleanup()
