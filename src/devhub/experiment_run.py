"""One reviewed session coordinator. No bulk-run CLI; no execution during dry-run."""

import json
import platform
import subprocess
import tempfile
from pathlib import Path
from typing import Any, cast

from pydantic import JsonValue

from devhub.baseline import verified_cases
from devhub.benchmark import canonical, digest, read_sealed, write_new, write_sealed
from devhub.delegate import DelegationConfig, ProviderProfile
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
    AttemptAbortV1,
    AttemptResult,
    ContainerRuntimeSpec,
    DelegationObservation,
    ExecutionSession,
    codex_argv,
    launch_container,
)
from devhub.experiment_observation import (
    BArmDelegationObservationV2,
    ProviderResourceModelIdentityV1,
    observe_b_arm_delegation,
)
from devhub.experiment_rehearsal import (
    Stage3GRehearsalPairResultV1,
    Stage3GRehearsalPlanV1,
    build_rehearsal_plan,
    rehearsal_packet_bytes,
)
from devhub.ledger import Ledger
from devhub.local import LocalConfig, local_resource_id
from devhub.ollama import OllamaAdapter
from devhub.ollama_transport import OllamaBridgeAuthorityV1, validate_ollama_bridge
from devhub.qualification import VerifiedQualificationV2, verify_manifest_tree
from devhub.runtime_artifact import verified_delegate_command
from devhub.stage3g_host import read_stage3g_host_manifest


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


def environment_guard(
    repo: Path, qualification: VerifiedQualificationV2, protocol: ExperimentProtocol
) -> None:
    expected = qualification.context.payload
    if platform.system() != "Linux":
        raise ValueError("Real execution requires reviewed Linux OCI environment")
    if (
        expected.implementation.devhub_commit
        != subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip()
    ):
        raise ValueError("Implementation changed")
    if (
        expected.ollama_expected.version != protocol.ollama.version
        or expected.ollama_expected.model != protocol.ollama.model
        or expected.ollama_expected.digest != protocol.ollama.model_digest
    ):
        raise ValueError("Ollama protocol identity differs from qualification")
    host_manifest = repo / "benchmarks" / "stage3g-host-manifest-v2.json"
    _, host_manifest_raw = read_stage3g_host_manifest(host_manifest)
    if digest(host_manifest_raw) != expected.runtime_expected.approved_host_manifest_sha256:
        raise ValueError("Stage 3G host manifest differs from qualification")
    image_id = expected.runtime_expected.image_id
    image = json.loads(subprocess.check_output([*DOCKER, "image", "inspect", image_id]))[0]
    if image["Id"] != image_id or image["Config"].get("Volumes"):
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
                *DOCKER,
                "run",
                "--rm",
                "--pull=never",
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--entrypoint",
                "codex",
                image_id,
                "--version",
            ],
            timeout=30,
        )
        .decode()
        .strip()
    )
    binary = (
        subprocess.check_output(
            [
                *DOCKER,
                "run",
                "--rm",
                "--pull=never",
                "--network=none",
                "--read-only",
                "--entrypoint",
                "sha256sum",
                image_id,
                "/usr/local/bin/codex",
            ],
            timeout=30,
        )
        .decode()
        .split()[0]
    )
    if (
        version != protocol.codex_cli_version
        or version != expected.codex.executable_version
        or binary != expected.codex.executable_sha256
    ):
        raise ValueError("Codex version changed")
    bridge_receipt = qualification.receipts.get("ollama_metadata")
    if bridge_receipt is None:
        raise ValueError("Qualified Ollama bridge receipt is missing")
    bridge = OllamaBridgeAuthorityV1.model_validate(bridge_receipt.get("bridge"))
    validate_ollama_bridge(bridge)
    OllamaAdapter(
        protocol.ollama, bridge=bridge
    ).inspect()  # metadata/tokenizer only, never inference


def secret_strings(value: Any) -> tuple[bytes, ...]:
    if isinstance(value, str):
        return (value.encode(),) if len(value) >= 6 else ()
    if isinstance(value, dict):
        return tuple(raw for item in value.values() for raw in secret_strings(item))
    if isinstance(value, list):
        return tuple(raw for item in value for raw in secret_strings(item))
    return ()


def _runtime_spec(
    qualification: VerifiedQualificationV2, execution_plan_sha256: str
) -> ContainerRuntimeSpec:
    expected = qualification.context.payload
    return ContainerRuntimeSpec(
        image_id=expected.runtime_expected.image_id,
        bootstrap_sha256=expected.runtime_expected.bootstrap_sha256,
        protocol_sha256=expected.benchmark.protocol_sha256,
        reviewed_plan_sha256=execution_plan_sha256,
        codex_cli_version=expected.codex.executable_version,
    )


def _execute_reviewed_session(
    repo: Path,
    protocol: ExperimentProtocol,
    qualification: VerifiedQualificationV2,
    runtime: ContainerRuntimeSpec,
    session: ExecutionSession,
    packets: dict[str, bytes],
    run_root: Path,
    auth_file: Path,
    accounting_root: Path,
) -> AttemptResult:
    """Single production launch path shared by benchmark and rehearsal coordinators."""

    expected = qualification.context.payload
    delegate_argv = verified_delegate_command(qualification)
    ollama_receipt = qualification.receipts.get("ollama_metadata")
    if ollama_receipt is None:
        raise ValueError("Qualified Ollama bridge receipt is missing")
    ollama_bridge = OllamaBridgeAuthorityV1.model_validate(ollama_receipt.get("bridge"))
    validate_ollama_bridge(ollama_bridge)
    volatile_capture = None
    try:
        environment_guard(repo, qualification, protocol)
        host_manifest = repo / "benchmarks" / "stage3g-host-manifest-v2.json"
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
        bridge_dir = control / "bridge"
        bridge_dir.mkdir()
        bridge_dir.chmod(0o755)
        ollama_authority_path = control / "ollama-bridge-authority.json"
        write_new(ollama_authority_path, canonical(ollama_bridge.model_dump(mode="json")))
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
        # Preserve the lexical root so Ledger can reject symlink/reparse traversal.
        state = accounting_root.absolute()  # reuse accepted ledger, never mounted
        if not (state / "ledger.db").is_file() or state.is_relative_to(run_root.resolve()):
            raise ValueError("Existing accepted accounting state outside run required")
        shared_ledger = Ledger(
            state / "ledger.db", expected.ledger_expected.identity, state_root=state
        )
        if session.arm == "B":
            # Trusted Git snapshot contains only this reviewed task's two source files.
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
                    "Reviewed task input",
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
                            ledger_identity=expected.ledger_expected.identity,
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
                *delegate_argv,
                "--config",
                str(config_path),
                "--ollama-bridge-authority",
                str(ollama_authority_path),
            ]
        bridges = [UnixBridge(bridge_dir / "proxy.sock", proxy)]
        if session.arm == "B":
            bridges.append(
                UnixBridge(
                    bridge_dir / "mcp.sock",
                    lambda conn: gateway.serve(conn, server_argv),
                    once=True,
                )
            )

        def observed() -> DelegationObservation | BArmDelegationObservationV2:
            if gateway.violation or any(b.failed for b in bridges):
                raise ValueError("Isolation/network/MCP boundary violation")
            if session.arm == "A":
                return DelegationObservation(delegate_called=False, count=0, provider_sends=0)
            ollama_receipt = qualification.receipts["ollama_metadata"]
            resource = local_resource_id(protocol.ollama)
            expected_identity = ProviderResourceModelIdentityV1(
                provider="ollama",
                resource=resource,
                model=expected.ollama_expected.model,
                ollama_version=expected.ollama_expected.version,
                model_digest=expected.ollama_expected.digest,
            )
            return observe_b_arm_delegation(
                shared_ledger,
                session_id=session.session_id,
                call_count=gateway.calls,
                request_identity=gateway.request_identity,
                response_kind=gateway.response_kind,
                handoff_schema_sha256=gateway.handoff_schema_sha256,
                handoff=gateway.handoff,
                expected_provider_resource_model=expected_identity,
                observed_ollama_version=cast(str, ollama_receipt["version"]),
                observed_model=cast(str, ollama_receipt["model"]),
                observed_model_digest=cast(str, ollama_receipt["digest"]),
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
        guest_control = control / "guest-control"
        guest_control.mkdir()
        write_new(
            guest_control / "session.json",
            canonical(
                {
                    "codex_argv": cast(JsonValue, codex_argv(session, protocol)),
                    "session_id": session.session_id,
                    "plan_sha256": runtime.reviewed_plan_sha256,
                    "prompt_sha256": digest(prompt),
                    "prompt_length": len(prompt),
                    "protocol_sha256": runtime.protocol_sha256,
                    "bootstrap_sha256": runtime.bootstrap_sha256,
                }
            ),
        )
        try:
            result = launch_container(
                session,
                protocol,
                runtime,
                guest_control,
                bridge_dir,
                capture,
                repo / "scripts/benchmark_guest.py",
                auth,
                host_manifest,
                run_root / "attempts" / session.session_id,
                prompt,
                reviewed_plan_sha256=runtime.reviewed_plan_sha256,
                secret_values=secrets,
                delegation=observed,
            )
        finally:
            for b in bridges:
                b.close()
        environment_guard(repo, qualification, protocol)
        if result.status != "completed":
            raise ValueError("Failed/timed-out attempt preserved; run aborted")
        return result
    except Exception:
        if not (run_root / "aborted.json").exists():
            exposure_state = "not_exposed"
            attempt_consumed = False
            attempt_path = run_root / "attempts" / session.session_id
            if (attempt_path / "result.json").exists():
                failed = AttemptResult.model_validate_json(
                    read_sealed(attempt_path / "result.json")
                )
                exposure_state = failed.provenance.exposure_state
                attempt_consumed = failed.provenance.attempt_consumed
            elif (attempt_path / "abort.json").exists():
                aborted = AttemptAbortV1.model_validate_json(
                    read_sealed(attempt_path / "abort.json")
                )
                exposure_state = aborted.exposure_state
                attempt_consumed = aborted.attempt_consumed
            write_new(
                run_root / "aborted.json",
                canonical(
                    {
                        "session": session.session_id,
                        "reason": "preflight_or_attempt_failed",
                        "exposure_state": exposure_state,
                        "attempt_consumed": attempt_consumed,
                        "rerun_permitted": False if exposure_state == "exposed" else None,
                        "review_required": True,
                    }
                ),
            )
        raise
    finally:
        if volatile_capture is not None:
            volatile_capture.cleanup()


def execute_next(
    repo: Path,
    protocol: ExperimentProtocol,
    frozen_plan: dict[str, Any],
    bindings: RuntimeBindings,
    run_root: Path,
    auth_file: Path,
    qualification_manifest: Path,
    accounting_root: Path,
    *,
    operator_reviewed: bool = False,
) -> AttemptResult:
    """Opt-in API for the next reviewed phase, never called by 3G-B CLI/tests on fixtures.

    Fails closed without reviewed bindings. Source/run/controller storage stays outside
    every mount; only derived files for one arm are ever exposed.
    """
    if not operator_reviewed:
        raise ValueError("Explicit protocol/environment review required")
    qualification = verify_manifest_tree(qualification_manifest, bindings.qualification_manifest_id)
    expected = qualification.context.payload
    runtime = _runtime_spec(qualification, expected.benchmark.plan_sha256)
    if protocol.hashes()["protocol"] != runtime.protocol_sha256:
        raise ValueError("Protocol differs from final qualification manifest")
    current = plan(repo, protocol, frozen_plan["run_id"])
    if current != frozen_plan or digest(canonical(current)) != runtime.reviewed_plan_sha256:
        raise ValueError("Plan/config/implementation changed")
    verified_delegate_command(qualification)
    environment_guard(repo, qualification, protocol)
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
                abort_path = target / "abort.json"
                if not abort_path.exists():
                    raise ValueError("Attempt exposure is unknown; manual review required")
                abort = AttemptAbortV1.model_validate_json(read_sealed(abort_path))
                raise ValueError(
                    f"Attempt stopped at {abort.last_state} with "
                    f"{abort.exposure_state} exposure; manual review required"
                )
            prior = AttemptResult.model_validate_json(read_sealed(result_path))
            if (
                prior.status != "completed"
                or prior.provenance.session_id != session.session_id
                or prior.provenance.plan_sha256 != runtime.reviewed_plan_sha256
                or prior.provenance.output_sha256 != digest((target / "output.bin").read_bytes())
                or (
                    session.arm == "B"
                    and (
                        not isinstance(prior.delegation, BArmDelegationObservationV2)
                        or not prior.delegation.delegation_success
                    )
                )
            ):
                raise ValueError("Failed/changed attempt cannot be repeated or skipped")
        elif selected is None:
            selected = session
    if selected is None:
        raise ValueError("All sessions attempted")
    session = selected
    return _execute_reviewed_session(
        repo,
        protocol,
        qualification,
        runtime,
        session,
        packet_bytes(repo, session, protocol),
        run_root,
        auth_file,
        accounting_root,
    )


def execute_rehearsal_pair(
    repo: Path,
    protocol: ExperimentProtocol,
    rehearsal: Stage3GRehearsalPlanV1,
    bindings: RuntimeBindings,
    run_root: Path,
    auth_file: Path,
    qualification_manifest: Path,
    accounting_root: Path,
    *,
    operator_reviewed: bool = False,
) -> Stage3GRehearsalPairResultV1:
    """Run one reviewed non-benchmark A/B pair with no resume or automatic retry."""

    if not operator_reviewed:
        raise ValueError("Explicit rehearsal review required")
    qualification = verify_manifest_tree(qualification_manifest, bindings.qualification_manifest_id)
    expected = qualification.context.payload
    payload = rehearsal.payload
    current = build_rehearsal_plan(
        repo,
        protocol,
        qualification,
        run_id=payload.run_id,
        task_id=payload.task_id,
        input_bytes=payload.input_bytes(),
        task_bytes=payload.task_bytes(),
    )
    if current != rehearsal:
        raise ValueError("Rehearsal plan differs from qualification authority")
    verified_delegate_command(qualification)
    environment_guard(repo, qualification, protocol)
    if run_root.resolve().is_relative_to(repo.resolve()) or run_root.is_symlink():
        raise ValueError("Rehearsal storage must be external")
    run_root.mkdir(parents=True, exist_ok=True)
    if any(run_root.iterdir()):
        raise ValueError("Rehearsal cannot resume or overwrite an existing run")
    write_sealed(run_root / "rehearsal-plan.json", canonical(rehearsal.model_dump(mode="json")))
    write_sealed(run_root / "bindings.json", canonical(bindings.model_dump(mode="json")))
    runtime = _runtime_spec(qualification, rehearsal.rehearsal_plan_id)
    results = []
    for session in payload.sessions:
        results.append(
            _execute_reviewed_session(
                repo,
                protocol,
                qualification,
                runtime,
                session,
                rehearsal_packet_bytes(rehearsal, session, protocol),
                run_root,
                auth_file,
                accounting_root,
            )
        )
    arm_a, arm_b = results
    if arm_a.provenance.output_sha256 is None or arm_b.provenance.output_sha256 is None:
        raise ValueError("Completed rehearsal output identity is missing")
    if not isinstance(arm_b.delegation, BArmDelegationObservationV2) or not (
        arm_b.delegation.delegation_success
    ):
        raise ValueError("Rehearsal B arm lacks authoritative delegation observation")
    summary = Stage3GRehearsalPairResultV1(
        rehearsal_plan_id=rehearsal.rehearsal_plan_id,
        qualification_manifest_id=qualification.manifest.qualification_manifest_id,
        qualification_context_id=qualification.context.qualification_context_id,
        environment_instance_id=expected.environment_instance_id,
        arm_a_result_sha256=digest(
            read_sealed(run_root / "attempts" / payload.sessions[0].session_id / "result.json")
        ),
        arm_b_result_sha256=digest(
            read_sealed(run_root / "attempts" / payload.sessions[1].session_id / "result.json")
        ),
        arm_a_output_sha256=arm_a.provenance.output_sha256,
        arm_b_output_sha256=arm_b.provenance.output_sha256,
        arm_b_delegation_success=True,
    )
    write_sealed(run_root / "pair-summary.json", canonical(summary.model_dump(mode="json")))
    return summary
