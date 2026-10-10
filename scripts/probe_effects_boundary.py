"""Synthetic A/B effects evidence on an immutable image; never starts Codex."""

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from devhub.benchmark import digest
from devhub.experiment import PlannedSession
from devhub.experiment_launch import DOCKER, ContainerRuntimeSpec, container_command
from devhub.qualification import load_context, receipt_header

PROTECTED_PATHS = {"/control/session.json", "/bootstrap.py", "/auth.json"}
HIDDEN_HOST_PATHS = {
    "/host",
    "/workspace",
    "/repository",
    "/root/.codex",
    "/ledger",
    "/oracle",
    "/opposite-arm",
    "/previous-session",
    "/future-session",
    "/reviewer",
    "/evaluator",
    "/var/run/docker.sock",
}
TASK_FILES = {"/packet/input.txt", "/packet/task.txt", "/packet/instructions.txt"}
WRITABLE_TMPFS = {"/tmp", "/home/runner", "/capture", "/dev/shm", "/packet"}


def validate(report):
    return (
        set(report["protected"]) == PROTECTED_PATHS
        and set(report["hidden_host_paths"]) == HIDDEN_HOST_PATHS
        and set(report["task_files_initially_absent"]) == TASK_FILES
        and set(report["writable_tmpfs"]) == WRITABLE_TMPFS
        and all(
            row["unchanged"] and all(op["denied"] for op in row["operations"].values())
            for row in report["protected"].values()
        )
        and all(
            row["stat"]["denied"] and row["stat"]["errno"] in {2, 13} and row["create"]["denied"]
            for row in report["hidden_host_paths"].values()
        )
        and all(
            row["stat"]["denied"] and row["stat"]["errno"] == 2
            for row in report["task_files_initially_absent"].values()
        )
        and all(report["writable_tmpfs"].values())
        and all(row["denied"] for row in report["system_files"].values())
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--context", required=True, type=Path)
    opts = parser.parse_args()
    context = load_context(opts.context)
    repo = Path(__file__).resolve().parents[1]
    host_manifest = repo / "benchmarks/stage3g-host-manifest-v2.json"
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", opts.image_id):
        parser.error("Immutable image ID required")
    guest = Path(__file__).with_name("effects_guest.py").resolve()
    bootstrap = Path(__file__).with_name("benchmark_guest.py").resolve()
    reports = {}
    for arm in ("A", "B"):
        with tempfile.TemporaryDirectory(prefix="synthetic-effects-") as directory:
            root = Path(directory)
            for name in ("control", "bridge", "capture"):
                (root / name).mkdir()
            (root / "capture").chmod(0o777)
            (root / "control" / "session.json").write_text("synthetic control only")
            # Inert markers, not live bridge endpoints. RPC/egress validated separately.
            for name in ("proxy.sock", "mcp.sock") if arm == "B" else ("proxy.sock",):
                (root / "bridge" / name).touch()
            (root / "auth.json").write_text("{}")
            runtime = ContainerRuntimeSpec(
                image_id=opts.image_id,
                bootstrap_sha256=digest(bootstrap.read_bytes()),
                protocol_sha256="0" * 64,
                reviewed_plan_sha256="0" * 64,
                codex_cli_version="not invoked",
            )
            session = PlannedSession(
                order=1,
                fixture_id="synthetic-only",
                fixture_sha256="0" * 64,
                oracle_sha256="0" * 64,
                arm=arm,
                session_id=f"synthetic-effects-{arm.lower()}-{os.getpid()}",
                packet_path="synthetic",
                available_mcp_tools=() if arm == "A" else ("devhub_delegate",),
            )
            argv = container_command(
                session,
                runtime,
                root / "control",
                root / "bridge",
                root / "capture",
                bootstrap,
                root / "auth.json",
                host_manifest,
            )
            position = argv.index("--entrypoint")
            argv[position:position] = ["--mount", f"type=bind,src={guest},dst=/probe.py,readonly"]
            argv[-2:] = ["/probe.py"]
            cid = subprocess.check_output(argv, timeout=30).decode().strip()
            try:
                inspect = json.loads(subprocess.check_output([*DOCKER, "inspect", cid]))[0]
                raw = subprocess.check_output([*DOCKER, "start", "--attach", cid], timeout=30)
                report = json.loads(raw)
                config = inspect["HostConfig"]
                report["host_config"] = {
                    k: config[k]
                    for k in (
                        "ReadonlyRootfs",
                        "NetworkMode",
                        "PidMode",
                        "IpcMode",
                        "CapDrop",
                        "SecurityOpt",
                        "Memory",
                        "NanoCpus",
                        "PidsLimit",
                    )
                }
                report["namespace_separation"] = {
                    name: report["namespaces"][name] != os.readlink(f"/proc/self/ns/{name}")
                    for name in ("pid", "mnt", "net", "ipc", "uts")
                }
                report["boundary_config_passed"] = (
                    config["ReadonlyRootfs"] is True
                    and config["NetworkMode"] == "none"
                    and config["PidMode"] == ""
                    and config["IpcMode"] == "private"
                    and config["CapDrop"] == ["ALL"]
                    and "no-new-privileges" in config["SecurityOpt"]
                    and config["Memory"] == 2147483648
                    and config["NanoCpus"] == 2000000000
                    and config["PidsLimit"] == 128
                    and inspect["Config"]["User"] == "1000:1000"
                )
                report["passed"] = (
                    validate(report)
                    and report["boundary_config_passed"]
                    and all(report["namespace_separation"].values())
                )
                reports[arm] = report
            finally:
                subprocess.run([*DOCKER, "rm", "-f", cid], check=True, capture_output=True)
    evidence = {
        **receipt_header(context, "effects_boundary"),
        "kind": "synthetic_filesystem_equivalent_effects",
        "image_id": opts.image_id,
        "guest_sha256": digest(guest.read_bytes()),
        "bootstrap_sha256": digest(bootstrap.read_bytes()),
        "arms": reports,
        "direct_apply_patch_handler": False,
        "real_codex_executions": 0,
        "provider_sends": 0,
        "execution_ready": False,
        "qualification_passed": all(report["passed"] for report in reports.values()),
        "limitations": "CI image only; inert sockets; no remote-effect or intended-host proof",
    }
    with opts.output.open("x", encoding="utf-8") as stream:
        json.dump(evidence, stream, indent=2)
        stream.write("\n")
    if not all(report["passed"] for report in reports.values()):
        raise SystemExit("Synthetic effects regression")


if __name__ == "__main__":
    main()
