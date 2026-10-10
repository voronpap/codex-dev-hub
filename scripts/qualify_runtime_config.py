"""Exact-image metadata-only config/auth/bridge probe with synthetic auth, no tasks."""

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from devhub.benchmark import canonical, digest, write_new
from devhub.experiment import ExperimentProtocol, PlannedSession
from devhub.experiment_bridge import UnixBridge, proxy
from devhub.experiment_launch import (
    DOCKER,
    ContainerRuntimeSpec,
    codex_argv,
    container_command,
    mount,
    safe_artifacts,
)
from devhub.qualification import (
    HostProcessVisibilityReceiptV1,
    RuntimeConfigProbeReceiptV1,
    load_context,
    receipt_header,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--host-process-visibility", type=Path, required=True)
    args = parser.parse_args()
    context = load_context(args.context)
    host_visibility_raw = args.host_process_visibility.read_bytes()
    host_visibility = HostProcessVisibilityReceiptV1.model_validate_json(host_visibility_raw)
    if (
        host_visibility.qualification_context_id != context.qualification_context_id
        or host_visibility.environment_instance_id != context.payload.environment_instance_id
    ):
        raise ValueError("Host visibility belongs to another qualification environment")
    repo = Path(__file__).resolve().parents[1]
    protocol = ExperimentProtocol.model_validate_json(args.protocol.read_bytes())
    bootstrap = repo / "scripts/benchmark_guest.py"
    results = []
    with tempfile.TemporaryDirectory(prefix="devhub-config-probe-") as temporary:
        root = Path(temporary)
        # No real auth material is read in this synthetic copy/config proof.
        auth = root / "auth.json"
        auth.write_text('{"tokens":{"access_token":"synthetic-auth-canary-only"}}')
        guest = root / "probe.py"
        guest.write_bytes((repo / "scripts/benchmark_config_probe.py").read_bytes())
        for arm in ("A", "B"):
            packet, bridge, capture = (root / (arm + x) for x in ("packet", "bridge", "capture"))
            for d in (packet, bridge, capture):
                d.mkdir()
            capture.chmod(0o777)
            if arm == "B":
                (bridge / "mcp.sock").touch()  # CLI list is metadata only, no server invocation.
            session = PlannedSession(
                order=1,
                fixture_id="synthetic-config",
                fixture_sha256="0" * 64,
                oracle_sha256="0" * 64,
                arm=arm,
                session_id="config-probe-" + arm.lower(),
                packet_path="synthetic",
                available_mcp_tools=() if arm == "A" else ("devhub_delegate",),
            )
            (packet / "session.json").write_bytes(
                canonical({"codex_argv": codex_argv(session, protocol), "arm": arm})
            )
            runtime = ContainerRuntimeSpec(
                image_id=args.image_id,
                bootstrap_sha256=digest(bootstrap.read_bytes()),
                protocol_sha256=protocol.hashes()["protocol"],
                reviewed_plan_sha256="0" * 64,
                codex_cli_version=protocol.codex_cli_version,
            )
            server = UnixBridge(bridge / "proxy.sock", proxy)
            try:
                argv = container_command(
                    session,
                    runtime,
                    packet,
                    bridge,
                    capture,
                    bootstrap,
                    auth,
                    repo / "benchmarks/stage3g-host-manifest-v2.json",
                )
                argv[len(DOCKER)] = "run"
                argv.insert(len(DOCKER) + 1, "--rm")
                pos = argv.index("--entrypoint")
                argv = argv[:pos] + mount(guest, "/probe.py") + argv[pos : pos + 3] + ["/probe.py"]
                raw = subprocess.check_output(argv, timeout=60)
                safe_artifacts((raw,), (b"synthetic-auth-canary-only",))
                results.append(json.loads(raw.splitlines()[-1]))
            finally:
                server.close()
        arm_observations = [
            {
                "schema_version": 1,
                "arm": arm,
                **result["config_diagnostics"],
                "config_error": result.get("config_error"),
            }
            for arm, result in zip(("A", "B"), results, strict=True)
        ]
        checks = {
            "auth_tmpfs": all(result["auth_tmpfs"] for result in results),
            "cli_config": all(result["metadata_config"] for result in results),
            "egress_runtime": all(result["egress_runtime"] for result in results),
        }
        value = {
            **receipt_header(context, "runtime_config_probe"),
            "kind": "runtime_config_probe",
            "image_id": args.image_id,
            "protocol_sha256": protocol.hashes()["protocol"],
            "host_process_visibility_sha256": digest(host_visibility_raw),
            "checks": checks,
            "arms": arm_observations,
            "auth_material": "synthetic only; real auth presence is a separate preflight gate",
            "real_codex_executions": 0,
            "model_requests": 0,
            "provider_sends": 0,
            "qualification_passed": all(checks.values()),
        }
        evidence = RuntimeConfigProbeReceiptV1.model_validate_json(canonical(value))
        raw = canonical(evidence.model_dump(mode="json"))
        write_new(args.output, raw)
        print(raw.decode())
        if not evidence.qualification_passed:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
