"""Metadata-only qualification of the exact local Stage 3G Ollama runtime."""

import argparse
import hashlib
import json
import os
import platform
import subprocess
from pathlib import Path

from devhub.benchmark import canonical, digest, write_new
from devhub.ollama import OllamaAdapter, OllamaConfig
from devhub.qualification import (
    STAGE3G_OLLAMA_ENDPOINT,
    STAGE3G_OLLAMA_RELEASE_ASSET,
    STAGE3G_OLLAMA_RELEASE_SHA256,
    OllamaMetadataReceiptV1,
    OllamaNetworkIsolationObservationV1,
    load_context,
    receipt_header,
)

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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--release-artifact", type=Path, required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--server-pid", type=int, required=True)
    parser.add_argument("--network-isolation", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("Intended-host Ollama qualification requires Linux")
    if args.output.exists():
        parser.error("Exclusive output required")
    context = load_context(args.context)
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
        environment_items = Path(f"/proc/{args.server_pid}/environ").read_bytes().split(b"\0")
    except OSError:
        parser.error("Ollama server process cannot be inspected")
    environment = {
        key.decode("ascii", "ignore"): value.decode("utf-8", "ignore")
        for item in environment_items
        if b"=" in item
        for key, value in (item.split(b"=", 1),)
    }
    server_namespace = os.readlink(f"/proc/{args.server_pid}/ns/net")
    if not _server_identity_matches(
        executable_sha, network, server_sha, server_namespace, environment
    ):
        parser.error("Running Ollama server identity or proxy environment differs")
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
    evidence, _ = OllamaAdapter(config).inspect()
    receipt = OllamaMetadataReceiptV1(
        **receipt_header(context, "ollama_metadata"),
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
