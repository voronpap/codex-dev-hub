"""Exact-image metadata-only config/auth/bridge probe with synthetic auth, no tasks."""

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from devhub.benchmark import canonical, digest, write_new
from devhub.experiment import ExperimentProtocol, PlannedSession, RuntimeBindings
from devhub.experiment_bridge import UnixBridge, proxy
from devhub.experiment_launch import DOCKER, codex_argv, container_command, mount, safe_artifacts
from devhub.experiment_tool_gate import POLICY_VERSION, policy_hash


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    args = parser.parse_args()
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
            for name in ("input.txt", "task.txt", "instructions.txt"):
                (packet / name).write_text("synthetic metadata only")
            (packet / "session.json").write_bytes(
                canonical({"codex_argv": codex_argv(session, protocol), "arm": arm})
            )
            bindings = RuntimeBindings.model_construct(
                image_id=args.image_id, bootstrap_sha256=digest(bootstrap.read_bytes())
            )
            server = UnixBridge(bridge / "proxy.sock", proxy)
            try:
                argv = container_command(
                    session, bindings, packet, bridge, capture, bootstrap, auth
                )
                argv[len(DOCKER)] = "run"
                argv.insert(len(DOCKER) + 1, "--rm")
                pos = argv.index("--entrypoint")
                argv = (
                    argv[:pos]
                    + mount(guest, "/probe.py")
                    + mount(repo / "src/devhub/experiment_tool_gate.py", "/tool_gate.py")
                    + argv[pos : pos + 3]
                    + ["/probe.py"]
                )
                raw = subprocess.check_output(argv, timeout=60)
                safe_artifacts((raw,), (b"synthetic-auth-canary-only",))
                results.append(json.loads(raw.splitlines()[-1]))
            finally:
                server.close()
        evidence = {
            "kind": "runtime_config_probe",
            "image_id": args.image_id,
            "bootstrap_sha256": digest(bootstrap.read_bytes()),
            "protocol_sha256": protocol.hashes()["protocol"],
            "checks": {
                k: all(r[k] for r in results)
                for k in ("auth_tmpfs", "cli_config", "egress_runtime")
            },
            "qualification_policy_version": POLICY_VERSION,
            "qualification_policy_sha256": policy_hash(),
            "tool_surfaces": [r["tool_surface"] for r in results],
            "config_errors": [r.get("config_error") for r in results],
            "config_diagnostics": [r.get("config_diagnostics") for r in results],
            "auth_material": "synthetic only; real auth presence is a separate preflight gate",
            "real_codex_executions": 0,
            "provider_sends": 0,
        }
        write_new(args.output, canonical(evidence))
        print(json.dumps(evidence))
        if not all(evidence["checks"].values()):
            raise SystemExit(1)


if __name__ == "__main__":
    main()
