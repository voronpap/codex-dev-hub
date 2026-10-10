"""Metadata-only qualification of the exact local Stage 3G Ollama runtime."""

import argparse
import hashlib
import json
import os
import platform
import stat
import subprocess
from pathlib import Path

from devhub.benchmark import canonical, digest, write_new
from devhub.ollama import OllamaAdapter, OllamaConfig
from devhub.ollama_transport import (
    OLLAMA_BRIDGE_ARGS,
    OllamaBridgeAuthorityV1,
    file_sha256,
    server_listener_inode,
    validate_ollama_bridge,
)
from devhub.qualification import (
    STAGE3G_OLLAMA_ENDPOINT,
    STAGE3G_OLLAMA_RELEASE_ASSET,
    STAGE3G_OLLAMA_RELEASE_SHA256,
    OllamaMetadataReceiptV2,
    OllamaNetworkIsolationObservationV1,
    QualificationReceiptHeaderV1,
    load_context,
    receipt_header_v2,
)
from devhub.runtime_artifact import PythonRuntimeReceiptV1, verify_runtime_against_expected

PROXY_KEYS = {
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "all_proxy",
    "https_proxy",
    "http_proxy",
    "no_proxy",
}


def _archive_executable_sha256(archive: Path) -> str:
    process = subprocess.Popen(
        ["tar", "--zstd", "-xOf", str(archive), "bin/ollama"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert process.stdout is not None
    value = hashlib.sha256()
    while chunk := process.stdout.read(1024 * 1024):
        value.update(chunk)
    if process.wait() != 0:
        raise ValueError("Official Ollama archive cannot be inspected")
    return value.hexdigest()


def _server_identity_matches(
    executable_sha256: str,
    network: OllamaNetworkIsolationObservationV1,
    server_sha256: str,
    server_namespace: str,
    environment: dict[str, str],
) -> bool:
    return (
        server_sha256 == executable_sha256
        and network.network_namespace_id == server_namespace
        and not PROXY_KEYS & environment.keys()
        and environment.get("OLLAMA_NO_CLOUD") == "1"
        and environment.get("OLLAMA_HOST") == "127.0.0.1:11434"
    )


def _start_time_ticks(pid: int) -> int:
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[19])


def _process_uid(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("Uid:"):
            return int(line.split()[1])
    raise ValueError("Process owner identity is unavailable")


def _environment(pid: int) -> dict[str, str]:
    items = Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
    return {
        key.decode("ascii", "ignore"): value.decode("utf-8", "ignore")
        for item in items
        if b"=" in item
        for key, value in (item.split(b"=", 1),)
    }


def _bridge_module(interpreter: Path) -> tuple[str, Path]:
    raw = subprocess.check_output(
        [
            str(interpreter),
            "-I",
            "-c",
            "import pathlib,devhub.ollama_transport as m;print(pathlib.Path(m.__file__).resolve())",
        ],
        env={"PATH": os.defpath, "PYTHONPATH": "untrusted-must-be-ignored"},
        timeout=30,
    )
    module = Path(raw.decode().strip())
    root = interpreter.parent.parent.resolve(strict=True)
    if module.is_symlink() or not module.is_file() or not module.is_relative_to(root):
        raise ValueError("Ollama bridge module escapes the immutable runtime")
    return module.relative_to(root).as_posix(), module


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--release-artifact", type=Path, required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--server-pid", type=int, required=True)
    parser.add_argument("--bridge-pid", type=int, required=True)
    parser.add_argument("--bridge-socket", type=Path, required=True)
    parser.add_argument("--python-runtime", type=Path, required=True)
    parser.add_argument("--network-isolation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("Intended-host Ollama qualification requires Linux")
    if args.output.exists():
        parser.error("Exclusive output required")
    context = load_context(args.context)
    if args.python_runtime.is_symlink() or not args.python_runtime.is_file():
        parser.error("Python runtime receipt must be a regular file")
    try:
        runtime_receipt = PythonRuntimeReceiptV1.model_validate_json(
            args.python_runtime.read_bytes()
        )
        runtime_header = QualificationReceiptHeaderV1(
            receipt_kind=runtime_receipt.receipt_kind,
            qualification_context_id=runtime_receipt.qualification_context_id,
            environment_instance_id=runtime_receipt.environment_instance_id,
        )
        if (
            runtime_receipt.qualification_context_id != context.qualification_context_id
            or runtime_receipt.environment_instance_id != context.payload.environment_instance_id
        ):
            raise ValueError("Python runtime receipt belongs to another qualification")
        current_runtime = verify_runtime_against_expected(
            Path(runtime_receipt.interpreter_path),
            Path(runtime_receipt.wheel_path),
            Path(runtime_receipt.lock_path),
            context.payload.implementation.python_runtime,
            runtime_header,
        )
        if current_runtime != runtime_receipt:
            raise ValueError("Python runtime receipt no longer matches its artifact locators")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    expected = context.payload.ollama_expected
    for label, path in (
        ("release artifact", args.release_artifact),
        ("Ollama executable", args.executable),
        ("network isolation proof", args.network_isolation),
    ):
        if path.is_symlink() or not path.is_file():
            parser.error(f"{label} must be a regular non-symlink file")
    release_sha = hashlib.sha256(args.release_artifact.read_bytes()).hexdigest()
    executable_sha = hashlib.sha256(args.executable.read_bytes()).hexdigest()
    if release_sha != STAGE3G_OLLAMA_RELEASE_SHA256:
        parser.error("Official Ollama release artifact hash mismatch")
    if _archive_executable_sha256(args.release_artifact) != executable_sha:
        parser.error("Ollama executable is not the executable from the reviewed release artifact")
    network_raw = args.network_isolation.read_bytes()
    network = OllamaNetworkIsolationObservationV1.model_validate_json(network_raw)
    if network.executable_sha256 != executable_sha:
        parser.error("Ollama network isolation proof belongs to another executable")
    process_executable = Path(f"/proc/{args.server_pid}/exe")
    try:
        server_sha = hashlib.sha256(process_executable.read_bytes()).hexdigest()
    except OSError:
        parser.error("Ollama server process cannot be inspected")
    environment = _environment(args.server_pid)
    server_namespace = os.readlink(f"/proc/{args.server_pid}/ns/net")
    if not _server_identity_matches(
        executable_sha, network, server_sha, server_namespace, environment
    ):
        parser.error("Running Ollama server identity or proxy environment differs")
    try:
        command = tuple(
            item.decode("utf-8")
            for item in Path(f"/proc/{args.bridge_pid}/cmdline").read_bytes().split(b"\0")
            if item
        )
        interpreter = Path(command[0])
        if str(interpreter) != runtime_receipt.interpreter_path:
            raise ValueError("Ollama bridge uses another interpreter locator")
        module_origin, module = _bridge_module(interpreter)
        bridge_environment = _environment(args.bridge_pid)
        socket_path = Path(os.path.abspath(args.bridge_socket))
        parent_stat = os.lstat(socket_path.parent)
        socket_stat = os.lstat(socket_path)
        expected_command = (
            str(interpreter),
            *OLLAMA_BRIDGE_ARGS,
            "--socket",
            str(socket_path),
        )
        if (
            command != expected_command
            or PROXY_KEYS & bridge_environment.keys()
            or not stat.S_ISSOCK(socket_stat.st_mode)
            or stat.S_IMODE(parent_stat.st_mode) != 0o700
            or stat.S_IMODE(socket_stat.st_mode) != 0o600
        ):
            raise ValueError("Running Ollama bridge command/environment/socket differs")
        bridge = OllamaBridgeAuthorityV1(
            socket_path=str(socket_path),
            socket_parent_uid=parent_stat.st_uid,
            socket_uid=socket_stat.st_uid,
            socket_device=socket_stat.st_dev,
            socket_inode=socket_stat.st_ino,
            bridge_pid=args.bridge_pid,
            bridge_start_time_ticks=_start_time_ticks(args.bridge_pid),
            bridge_uid=_process_uid(args.bridge_pid),
            bridge_network_namespace_id=os.readlink(f"/proc/{args.bridge_pid}/ns/net"),
            bridge_python_path=str(interpreter),
            bridge_python_executable_sha256=file_sha256(interpreter),
            bridge_process_executable_sha256=file_sha256(Path(f"/proc/{args.bridge_pid}/exe")),
            bridge_runtime_environment_id=runtime_receipt.runtime_environment_id,
            bridge_module_origin=module_origin,
            bridge_module_sha256=file_sha256(module),
            server_pid=args.server_pid,
            server_start_time_ticks=_start_time_ticks(args.server_pid),
            server_uid=_process_uid(args.server_pid),
            server_executable_sha256=server_sha,
            server_network_namespace_id=server_namespace,
            server_listener_inode=server_listener_inode(args.server_pid),
        )
        if (
            bridge.bridge_python_executable_sha256 != runtime_receipt.interpreter_sha256
            or bridge.bridge_process_executable_sha256 != runtime_receipt.interpreter_sha256
        ):
            raise ValueError("Ollama bridge interpreter differs from qualification context")
        validate_ollama_bridge(bridge)
    except (IndexError, OSError, ValueError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    config = OllamaConfig(
        endpoint=STAGE3G_OLLAMA_ENDPOINT,
        model=expected.model,
        model_digest=expected.digest,
        version=expected.version,
        context_tokens=8192,
        max_output_tokens=256,
        safety_tokens=128,
        timeout_seconds=90,
    )
    evidence, _ = OllamaAdapter(config, bridge=bridge).inspect()
    receipt = OllamaMetadataReceiptV2(
        **receipt_header_v2(context, "ollama_metadata"),
        version=expected.version,
        model=expected.model,
        digest=expected.digest,
        endpoint=STAGE3G_OLLAMA_ENDPOINT,
        release_asset=STAGE3G_OLLAMA_RELEASE_ASSET,
        release_artifact_sha256=release_sha,
        executable_sha256=executable_sha,
        server_executable_matches=True,
        network_isolation=network,
        network_isolation_sha256=digest(canonical(network.model_dump(mode="json"))),
        bridge=bridge,
        model_metadata_sha256=evidence.metadata_hash,
        context_tokens=evidence.context_tokens,
        completion_capability=True,
        remote_model=False,
        remote_host=False,
        metadata_endpoints=("/api/show", "/api/tags", "/api/version"),
        generate_requests=0,
        proxy_environment_inherited=False,
        outbound_network_denied=True,
        model_requests=0,
        provider_sends=0,
        qualification_passed=True,
    )
    write_new(args.output, canonical(receipt.model_dump(mode="json")))
    print(json.dumps({"qualification_passed": True, "metadata_only": True}))


if __name__ == "__main__":
    main()
