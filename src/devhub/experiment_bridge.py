"""Host-side scoped bridges. No cloud Dev Hub profile or arbitrary MCP methods."""

import ipaddress
import json
import socket
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from devhub.delegate import DelegationRequest, DelegationResult
from devhub.experiment_observation import (
    DELEGATION_RESULT_SCHEMA_SHA256,
    ResponseKind,
    ValidatedRequestIdentityV2,
)

CODEX_HOSTS = frozenset({"chatgpt.com", "api.openai.com"})


def connect_target(header: bytes) -> str:
    lines = header.split(b"\r\n")
    fields = lines[0].decode("ascii").split()
    if len(fields) != 3 or fields[0] != "CONNECT" or fields[2] not in {"HTTP/1.0", "HTTP/1.1"}:
        raise ValueError("Only Codex TLS CONNECT permitted")
    if fields[1] not in {f"{host}:443" for host in CODEX_HOSTS}:
        raise ValueError("Egress target denied")
    return fields[1][:-4]


def public_resolved_addresses(addresses: list[tuple[Any, ...]]) -> bool:
    """Return whether every resolved endpoint is globally routable."""

    return bool(addresses) and all(
        ipaddress.ip_address(entry[4][0]).is_global for entry in addresses
    )


def relay(left: socket.socket, right: socket.socket) -> None:
    def forward(source: socket.socket, target: socket.socket) -> None:
        try:
            while data := source.recv(65536):
                target.sendall(data)
        except OSError:
            pass
        finally:
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    thread = threading.Thread(target=forward, args=(left, right), daemon=True)
    thread.start()
    forward(right, left)
    thread.join(timeout=2)


def proxy(connection: socket.socket) -> None:
    connection.settimeout(30)
    header = b""
    while not header.endswith(b"\r\n\r\n"):
        part = connection.recv(1)
        if not part or len(header) >= 16384:
            raise ValueError("Invalid CONNECT header")
        header += part
    host = connect_target(header)
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not public_resolved_addresses(addresses):
        raise ValueError("Non-public Codex target denied")
    family, kind, proto, _, address = addresses[0]
    with socket.socket(family, kind, proto) as target:
        target.settimeout(30)
        target.connect(address)
        connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        connection.settimeout(900)
        target.settimeout(900)
        relay(connection, target)


class MCPGate:
    """Validate requests before the accepted delegate_server sees them."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.calls = 0
        self.call_id: Any = None
        self.request_identity: ValidatedRequestIdentityV2 | None = None
        self.response_kind: ResponseKind = "none"
        self.handoff_schema_sha256: str | None = None
        self.handoff: DelegationResult | None = None
        self.violation = False

    def request(self, raw: bytes) -> None:
        try:
            data = json.loads(raw)
            method = data["method"]
            if method not in {
                "initialize",
                "notifications/initialized",
                "ping",
                "tools/list",
                "tools/call",
            }:
                raise ValueError("MCP method denied")
            if method == "tools/call":
                if data["params"]["name"] != "devhub_delegate" or self.calls:
                    raise ValueError("Only one local delegation call allowed")
                request = DelegationRequest.model_validate_json(
                    json.dumps(data["params"]["arguments"])
                )
                if (
                    request.project != self.session_id
                    or request.task_id != self.session_id
                    or request.request_key != self.session_id
                    or request.privacy != "local_only"
                    or request.allow_cloud
                    or not request.require_citations
                ):
                    raise ValueError("Session/local-only/output scope denied")
                self.calls += 1
                self.call_id = data["id"]
                self.request_identity = ValidatedRequestIdentityV2(
                    session_id=self.session_id,
                    project=request.project,
                    task_id=request.task_id,
                    request_key=request.request_key,
                )
        except (KeyError, TypeError, ValueError):
            self.violation = True
            raise ValueError("MCP boundary violation; abort run") from None

    def response(self, raw: bytes) -> None:
        data = json.loads(raw)
        if not self.calls or data.get("id") != self.call_id:
            return
        if self.response_kind != "none":
            self.violation = True
            raise ValueError("Multiple delegation responses; abort")
        if "error" in data or "result" not in data:
            self.response_kind = "mcp_error"
            return
        result = data["result"]
        if not isinstance(result, dict):
            self.response_kind = "mcp_error"
            return
        is_error = result.get("isError", False)
        if type(is_error) is not bool:
            self.response_kind = "malformed_structured_content"
            return
        if is_error:
            self.response_kind = "mcp_error"
            return
        if "structuredContent" not in result:
            self.response_kind = "missing_structured_content"
            return
        try:
            self.handoff = DelegationResult.model_validate_json(
                json.dumps(result["structuredContent"])
            )
        except (TypeError, ValueError, ValidationError):
            self.response_kind = "malformed_structured_content"
            return
        self.response_kind = "structured_result"
        self.handoff_schema_sha256 = DELEGATION_RESULT_SCHEMA_SHA256
        if self.handoff.provider not in {None, "ollama"}:
            self.violation = True
            raise ValueError("Unexpected cloud provider; abort")

    def serve(self, connection: socket.socket, argv: list[str]) -> None:
        # This is the unchanged accepted server, in the trusted controller boundary.
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        assert process.stdin and process.stdout
        inbound = connection.makefile("rb")

        def requests() -> None:
            assert process.stdin
            try:
                while raw := inbound.readline(1_000_001):
                    if len(raw) > 1_000_000:
                        raise ValueError("MCP frame too large")
                    self.request(raw)
                    process.stdin.write(raw)
                    process.stdin.flush()
            except (ValueError, OSError):
                self.violation = True
                process.terminate()
            finally:
                process.stdin.close()

        threading.Thread(target=requests, daemon=True).start()
        try:
            while raw := process.stdout.readline(1_000_001):
                if len(raw) > 1_000_000:
                    raise ValueError("MCP frame too large")
                self.response(raw)
                connection.sendall(raw)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


class UnixBridge:
    """One private directory per session; close all connections at teardown."""

    def __init__(self, path: Path, handler: Callable[[socket.socket], None], *, once: bool = False):
        family = getattr(socket, "AF_UNIX", None)
        if family is None:
            raise ValueError("Unix sockets unavailable; no transport fallback")
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        self.socket.bind(str(path))
        path.chmod(0o666)  # parent is private; bind-mount is scoped to one container
        self.socket.listen(8)
        self.connections: list[socket.socket] = []
        self.failed = False
        self.closed = False

        def serve() -> None:
            accepted = False
            while not self.closed:
                try:
                    connection, _ = self.socket.accept()
                except OSError:
                    return
                if once and accepted:
                    connection.close()
                    self.failed = True
                    continue
                accepted = True
                self.connections.append(connection)

                def handle(conn: socket.socket = connection) -> None:
                    try:
                        with conn:
                            handler(conn)
                    except (OSError, ValueError):
                        self.failed = True

                threading.Thread(target=handle, daemon=True).start()

        threading.Thread(target=serve, daemon=True).start()

    def close(self) -> None:
        self.closed = True
        self.socket.close()
        for connection in self.connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
