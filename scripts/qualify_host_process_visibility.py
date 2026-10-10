"""Observe the retained Codex router in the exact image and stop before sampling."""

import argparse
import json
import socket
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from devhub.benchmark import canonical, digest, write_new
from devhub.experiment import ExperimentProtocol, PlannedSession
from devhub.experiment_bridge import UnixBridge
from devhub.experiment_launch import DOCKER, codex_argv, mount, safe_artifacts
from devhub.qualification import (
    DELEGATE_SCHEMA_SHA256,
    HostProcessVisibilityReceiptV1,
    load_context,
    receipt_header,
)
from devhub.stage3g_host import read_stage3g_host_manifest

PRE_SAMPLING_STOP_MARKER = b"DevFabric proof observer stopped before model sampling"
SAFE_FAILURE_MARKERS = {
    b"configuration": "configuration",
    b"failed to": "failed_to",
    b"invalid value": "invalid_value",
    b"no such file or directory": "not_found",
    b"operation not permitted": "operation_not_permitted",
    b"permission denied": "permission_denied",
    b"read-only file system": "read_only_filesystem",
    b"required arguments": "required_arguments",
    b"unexpected argument": "unexpected_argument",
}


def _safe_failure_categories(value: bytes) -> tuple[str, ...]:
    lowered = value.lower()
    return tuple(name for marker, name in SAFE_FAILURE_MARKERS.items() if marker in lowered)


def _require_reviewed_stop(
    result: subprocess.CompletedProcess[bytes], observer: Path, arm: str
) -> None:
    stopped_before_sampling = (
        result.returncode == 1
        and observer.is_file()
        and PRE_SAMPLING_STOP_MARKER in result.stdout + result.stderr
    )
    if not stopped_before_sampling:
        diagnostics = {
            "arm": arm,
            "returncode": result.returncode,
            "observer_exists": observer.is_file(),
            "stop_marker_observed": PRE_SAMPLING_STOP_MARKER in result.stdout + result.stderr,
            "stdout_sha256": digest(result.stdout),
            "stderr_sha256": digest(result.stderr),
            "stdout_categories": _safe_failure_categories(result.stdout),
            "stderr_categories": _safe_failure_categories(result.stderr),
        }
        raise ValueError(
            f"{arm} pre-sampling observer did not stop at the reviewed boundary: "
            f"{json.dumps(diagnostics, sort_keys=True)}"
        )


class CatalogOnly:
    """Out-of-band catalog evidence; it can never execute a tool or provider."""

    def __init__(self, schema: dict[str, Any]) -> None:
        self.schema = schema
        self.records: list[dict[str, object]] = []
        self.tool_calls = 0

    def __call__(self, connection: socket.socket) -> None:
        with connection.makefile("rb") as reader, connection.makefile("wb") as writer:
            for raw in reader:
                request = json.loads(raw)
                if "id" not in request:
                    continue
                method = request.get("method")
                if method == "initialize":
                    result: object = {
                        "protocolVersion": request["params"]["protocolVersion"],
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "stage3g-catalog-only", "version": "1"},
                    }
                elif method == "tools/list":
                    self.records.append(
                        {
                            "schema_version": 1,
                            "event": "tools_list",
                            "schema_sha256": DELEGATE_SCHEMA_SHA256,
                            "provider_send": False,
                        }
                    )
                    result = {"tools": [{"name": "devhub_delegate", "inputSchema": self.schema}]}
                elif method == "ping":
                    result = {}
                elif method == "tools/call":
                    self.tool_calls += 1
                    result = {
                        "isError": True,
                        "content": [{"type": "text", "text": "pre-sampling proof denies calls"}],
                    }
                else:
                    response = {
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "error": {"code": -32601, "message": "unsupported method"},
                    }
                    writer.write(json.dumps(response).encode() + b"\n")
                    writer.flush()
                    continue
                writer.write(
                    json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
                    + b"\n"
                )
                writer.flush()


def _without_stage3g_authority(args: list[str]) -> list[str]:
    result = list(args)
    for option in ("--devhub-stage3g-host-manifest", "--devhub-stage3g-arm"):
        index = result.index(option)
        del result[index : index + 2]
    return result


def _run_observer(
    *,
    image_id: str,
    protocol: ExperimentProtocol,
    host_manifest: Path,
    bootstrap: Path,
    root: Path,
    arm: str,
    catalog: CatalogOnly | None,
) -> dict[str, Any]:
    session_arm = "A" if arm == "default" else arm
    session = PlannedSession(
        order=1,
        fixture_id="synthetic-host-visibility",
        fixture_sha256="0" * 64,
        oracle_sha256="0" * 64,
        arm=session_arm,
        session_id=f"host-visibility-{arm.lower()}",
        packet_path="synthetic",
        available_mcp_tools=() if session_arm == "A" else ("devhub_delegate",),
    )
    work = root / f"work-{arm.lower()}"
    capture = root / f"capture-{arm.lower()}"
    bridge = root / f"bridge-{arm.lower()}"
    for directory in (work, capture, bridge):
        directory.mkdir()
    capture.chmod(0o777)
    observer = capture / "observer.json"
    args = codex_argv(session, protocol)
    if arm == "default":
        args = _without_stage3g_authority(args)
    else:
        args[-1:-1] = ["--devhub-proof-observe-router", "/capture/observer.json"]
    if arm == "default":
        args[-1:-1] = ["--devhub-proof-observe-router", "/capture/observer.json"]
    command = [
        *DOCKER,
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=1000:1000",
        "--pids-limit=128",
        "--memory=2g",
        "--cpus=2",
        "-i",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m,mode=1777",
        "--tmpfs",
        "/home/runner:rw,noexec,nosuid,size=64m,uid=1000,gid=1000",
        "--tmpfs",
        "/home/runner/.codex:rw,noexec,nosuid,size=16m,uid=1000,gid=1000,mode=0700",
        "--tmpfs",
        "/packet:rw,noexec,nosuid,size=16m,uid=1000,gid=1000",
        "--env",
        "HOME=/home/runner",
        "--env",
        "CODEX_HOME=/home/runner/.codex",
        "--env",
        "OPENAI_API_KEY=stage3g-pre-sampling-proof-only",
        *mount(work, "/work"),
        *mount(capture, "/capture", False),
        *mount(host_manifest, "/stage3g-host.json"),
    ]
    server = None
    if arm == "B":
        assert catalog is not None
        server = UnixBridge(bridge / "mcp.sock", catalog, once=True)
        command += [*mount(bridge, "/bridge"), *mount(bootstrap, "/bootstrap.py")]
    command += ["--entrypoint", "codex", image_id, *args[1:]]
    try:
        result = subprocess.run(
            command, input=b"pre-sampling proof only\n", capture_output=True, timeout=60
        )
    finally:
        if server is not None:
            server.close()
    safe_artifacts((result.stdout, result.stderr))
    _require_reviewed_stop(result, observer, arm)
    value = json.loads(observer.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("Router observer must emit an object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    context = load_context(args.context)
    expected = context.payload
    if args.image_id != expected.runtime_expected.image_id:
        raise ValueError("Host visibility image differs from qualification context")
    protocol = ExperimentProtocol.model_validate_json(args.protocol.read_bytes())
    repo = Path(__file__).resolve().parents[1]
    host_manifest = repo / "benchmarks/stage3g-host-manifest-v2.json"
    manifest, manifest_raw = read_stage3g_host_manifest(host_manifest)
    approved = manifest.arms.arm_b.approved_delegate
    assert approved is not None
    catalog = CatalogOnly(approved.expected_input_schema)
    with tempfile.TemporaryDirectory(prefix="devhub-host-visibility-") as temporary:
        root = Path(temporary)
        observations = {
            arm: _run_observer(
                image_id=args.image_id,
                protocol=protocol,
                host_manifest=host_manifest,
                bootstrap=repo / "scripts/benchmark_guest.py",
                root=root,
                arm=arm,
                catalog=catalog if arm == "B" else None,
            )
            for arm in ("default", "A", "B")
        }
    a = set(observations["A"]["visible_model_tools"])
    b = set(observations["B"]["visible_model_tools"])
    value = {
        **receipt_header(context, "host_process_visibility"),
        "kind": "actual_codex_exec_pre_sampling_router_visibility",
        "image_id": args.image_id,
        "executable_sha256": expected.codex.executable_sha256,
        "executable_version": expected.codex.executable_version,
        "approved_host_manifest_sha256": digest(manifest_raw),
        "default_observation": observations["default"],
        "arm_a_observation": observations["A"],
        "arm_b_observation": observations["B"],
        "b_minus_a": sorted(b - a),
        "a_minus_b": sorted(a - b),
        "catalog_records": catalog.records,
        "catalog_tools_list_count": len(catalog.records),
        "mcp_tool_call_count": catalog.tool_calls,
        "stopped_before_sampling": True,
        "model_requests": 0,
        "provider_sends": 0,
        "real_codex_task_executions": 0,
        "qualification_passed": True,
    }
    receipt = HostProcessVisibilityReceiptV1.model_validate_json(canonical(value))
    raw = canonical(receipt.model_dump(mode="json"))
    write_new(args.output, raw)
    print(raw.decode())


if __name__ == "__main__":
    main()
