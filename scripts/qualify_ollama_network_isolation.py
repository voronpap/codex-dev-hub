"""Prove the portable Ollama process namespace has loopback but no outbound route."""

import argparse
import hashlib
import os
import platform
import socket
from pathlib import Path

from devhub.benchmark import canonical, write_new
from devhub.qualification import OllamaNetworkIsolationObservationV1

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

IPV6_ROUTE_FLAG_REJECT = 0x0200


def _non_loopback_routes_from_text(ipv4: str, ipv6: str) -> int:
    routes = 0
    for line in ipv4.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and (fields[0] != "lo" or fields[1] == "00000000"):
            routes += 1
    for line in ipv6.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 10:
            routes += 1
            continue
        try:
            flags = int(fields[8], 16)
        except ValueError:
            routes += 1
            continue
        if (flags & IPV6_ROUTE_FLAG_REJECT) == 0 and (
            fields[-1] != "lo" or (fields[0] == "0" * 32 and fields[1] == "00")
        ):
            routes += 1
    return routes


def _non_loopback_routes() -> int:
    return _non_loopback_routes_from_text(
        Path("/proc/net/route").read_text(),
        Path("/proc/net/ipv6_route").read_text(),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("Ollama network isolation proof requires Linux")
    if args.output.exists():
        parser.error("Exclusive output required")
    executable = args.executable
    if executable.is_symlink() or not executable.is_file():
        parser.error("Ollama executable must be a regular non-symlink file")
    separate = os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        loopback = listener.getsockname()[0] == "127.0.0.1"
    denied = False
    with socket.socket() as probe:
        probe.settimeout(1)
        try:
            probe.connect(("1.1.1.1", 443))
        except OSError:
            denied = True
    value = OllamaNetworkIsolationObservationV1(
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        network_namespace_id=os.readlink("/proc/self/ns/net"),
        separate_network_namespace=separate,
        loopback_bind_available=loopback,
        non_loopback_route_count=_non_loopback_routes(),
        outbound_probe_denied=denied,
        proxy_environment_inherited=any(key in os.environ for key in PROXY_KEYS),
    )
    write_new(args.output, canonical(value.model_dump(mode="json")))


if __name__ == "__main__":
    main()
