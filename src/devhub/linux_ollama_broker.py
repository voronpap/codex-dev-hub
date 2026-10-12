"""Exact-peer, metadata-only Ollama broker for native Linux qualification."""

from __future__ import annotations

import json
import os
import socket
import stat
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from pydantic import Field

from devhub.models import Contract

DESTINATION_HOST = "127.0.0.1"
DESTINATION_PORT = 11434
EXPECTED_MODEL = "qwen2.5:14b-instruct"
ALLOWED_REQUESTS = {
    ("GET", "/api/tags"),
    ("GET", "/api/version"),
    ("POST", "/api/show"),
}
ALLOWED_HEADERS = {
    "accept",
    "accept-encoding",
    "connection",
    "content-length",
    "content-type",
    "host",
    "user-agent",
}


class LinuxBrokerPeerAuthorityV1(Contract):
    """Outer-namespace identity of the only process permitted to use the broker."""

    outer_pid: int = Field(ge=1)
    outer_uid: int = Field(ge=1)
    start_time_ticks: int = Field(ge=1)
    inner_pid: Literal[1] = 1
    inner_uid: Literal[1000] = 1000


@dataclass(frozen=True)
class BoundedHTTPRequest:
    method: Literal["GET", "POST"]
    path: Literal["/api/version", "/api/tags", "/api/show"]
    raw: bytes


def process_start_time_ticks(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    end_command = raw.rfind(")")
    fields = raw[end_command + 2 :].split()
    if end_command < 0 or len(fields) < 20:
        raise ValueError("Linux process stat is incomplete")
    return int(fields[19])


def _recv_exact(connection: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = connection.recv(min(64 * 1024, count - len(chunks)))
        if not chunk:
            raise ValueError("Broker request body ended early")
        chunks.extend(chunk)
    return bytes(chunks)


def read_metadata_request(
    connection: socket.socket,
    max_request_bytes: int,
    *,
    expected_model: str = EXPECTED_MODEL,
) -> BoundedHTTPRequest:
    """Read one bounded HTTP/1.1 request and reject every non-metadata operation."""

    header = bytearray()
    while b"\r\n\r\n" not in header:
        if len(header) >= max_request_bytes:
            raise ValueError("Broker request headers exceed the reviewed limit")
        chunk = connection.recv(min(4096, max_request_bytes - len(header)))
        if not chunk:
            raise ValueError("Broker request ended before headers")
        header.extend(chunk)
    boundary = header.index(b"\r\n\r\n") + 4
    head = bytes(header[:boundary])
    buffered_body = bytes(header[boundary:])
    try:
        lines = head[:-4].decode("ascii").split("\r\n")
    except UnicodeDecodeError as error:
        raise ValueError("Broker request headers must be ASCII") from error
    request_parts = lines[0].split(" ")
    if len(request_parts) != 3 or request_parts[2] != "HTTP/1.1":
        raise ValueError("Broker requires one canonical HTTP/1.1 request line")
    method, path, _ = request_parts
    if (method, path) not in ALLOWED_REQUESTS:
        raise ValueError("Broker endpoint or method is not allowed")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            raise ValueError("Broker request contains a malformed header")
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if not key or key in headers:
            raise ValueError("Broker request contains a duplicate or empty header")
        headers[key] = value.strip()
    if set(headers) - ALLOWED_HEADERS:
        raise ValueError("Broker request contains an unsupported header")
    if headers.get("host") not in {"127.0.0.1:11434", "localhost:11434"}:
        raise ValueError("Broker Host header differs from the fixed Ollama destination")
    if "transfer-encoding" in headers or "upgrade" in headers:
        raise ValueError("Broker does not allow streaming or protocol upgrades")
    if headers.get("accept-encoding", "identity") != "identity":
        raise ValueError("Broker accepts only identity response encoding")
    if headers.get("connection", "close").lower() != "close":
        raise ValueError("Broker requests must close after one response")
    raw_length = headers.get("content-length", "0")
    if not raw_length.isascii() or not raw_length.isdecimal() or str(int(raw_length)) != raw_length:
        raise ValueError("Broker Content-Length is invalid")
    content_length = int(raw_length)
    if method == "GET" and content_length != 0:
        raise ValueError("Broker GET metadata requests cannot carry a body")
    if method == "POST" and content_length == 0:
        raise ValueError("Broker show request requires a JSON body")
    if boundary + content_length > max_request_bytes:
        raise ValueError("Broker request exceeds the reviewed byte limit")
    if len(buffered_body) > content_length:
        raise ValueError("Broker request contains trailing bytes")
    body = buffered_body + _recv_exact(connection, content_length - len(buffered_body))
    if method == "POST":
        if headers.get("content-type", "application/json") != "application/json":
            raise ValueError("Broker show request requires application/json")

        def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
            value: dict[str, object] = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("Broker show request contains a duplicate JSON field")
                value[key] = item
            return value

        try:
            parsed = json.loads(body, object_pairs_hook=reject_duplicate_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("Broker show request body is not valid JSON") from error
        if not isinstance(parsed, dict) or set(parsed) - {"model", "name", "verbose"}:
            raise ValueError("Broker show request contains an unsupported field")
        model = parsed.get("model", parsed.get("name"))
        if "model" in parsed and "name" in parsed:
            raise ValueError("Broker show request must use one model identity field")
        if model != expected_model:
            raise ValueError("Broker show request differs from the exact qualified model")
        if "verbose" in parsed and not isinstance(parsed["verbose"], bool):
            raise ValueError("Broker show verbose field must be boolean")
    return BoundedHTTPRequest(
        method=cast(Literal["GET", "POST"], method),
        path=cast(Literal["/api/version", "/api/tags", "/api/show"], path),
        raw=head + body,
    )


def _bounded_response(upstream: socket.socket, client: socket.socket, max_bytes: int) -> None:
    observed = 0
    while True:
        chunk = upstream.recv(min(64 * 1024, max_bytes + 1 - observed))
        if not chunk:
            return
        observed += len(chunk)
        if observed > max_bytes:
            raise ValueError("Ollama metadata response exceeds the reviewed byte limit")
        client.sendall(chunk)


def _peer_credentials(connection: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise ValueError("Linux SO_PEERCRED is unavailable")
    return struct.unpack(
        "3i",
        connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
    )


def validate_peer(connection: socket.socket, expected: LinuxBrokerPeerAuthorityV1) -> None:
    pid, uid, _ = _peer_credentials(connection)
    if pid != expected.outer_pid or uid != expected.outer_uid:
        raise ValueError("Ollama broker peer process identity mismatch")
    if process_start_time_ticks(pid) != expected.start_time_ticks:
        raise ValueError("Ollama broker peer start-time identity mismatch")


class LinuxMetadataBrokerV1:
    """Serve one exact peer through one private socket and fixed TCP destination."""

    def __init__(
        self,
        socket_path: Path,
        peer: LinuxBrokerPeerAuthorityV1,
        *,
        max_request_bytes: int = 64 * 1024,
        max_response_bytes: int = 4 * 1024**2,
        expected_model: str = EXPECTED_MODEL,
    ) -> None:
        self.socket_path = socket_path
        self.peer = peer
        self.max_request_bytes = max_request_bytes
        self.max_response_bytes = max_response_bytes
        if expected_model != EXPECTED_MODEL:
            raise ValueError("Linux metadata broker requires the exact qualified model")
        self.expected_model = expected_model

    def _validate_socket_parent(self) -> None:
        parent = self.socket_path.parent
        info = os.lstat(parent)
        geteuid = getattr(os, "geteuid", None)
        if not callable(geteuid):
            raise ValueError("Native Linux broker requires effective-user identity")
        if (
            self.socket_path.exists()
            or self.socket_path.is_symlink()
            or not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or parent.resolve(strict=True) != parent
            or info.st_uid != int(geteuid())
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError("Broker socket requires an empty path in an owned 0700 directory")

    def serve_requests(
        self,
        count: int,
        *,
        stop_event: threading.Event | None = None,
        deadline: float | None = None,
    ) -> tuple[str, ...]:
        """Serve a bounded number of requests and report allowed/denied paths."""

        if count < 1 or count > 16:
            raise ValueError("Broker request count is outside the reviewed bound")
        if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
            raise ValueError("Native Linux broker requires AF_UNIX")
        self._validate_socket_parent()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.settimeout(0.2)
        outcomes: list[str] = []
        try:
            listener.bind(str(self.socket_path))
            self.socket_path.chmod(0o600)
            listener.listen(1)
            while len(outcomes) < count:
                if stop_event is not None and stop_event.is_set():
                    raise TimeoutError("Linux metadata broker was cancelled")
                if deadline is not None and time.monotonic() >= deadline:
                    raise TimeoutError("Linux metadata broker deadline expired")
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    connection.settimeout(5)
                    validate_peer(connection, self.peer)
                    try:
                        request = read_metadata_request(
                            connection,
                            self.max_request_bytes,
                            expected_model=self.expected_model,
                        )
                    except ValueError:
                        connection.sendall(
                            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n"
                            b"Connection: close\r\n\r\n"
                        )
                        outcomes.append("denied")
                        continue
                    remaining = 10.0
                    if deadline is not None:
                        remaining = max(0.1, min(remaining, deadline - time.monotonic()))
                    with socket.create_connection(
                        (DESTINATION_HOST, DESTINATION_PORT), timeout=remaining
                    ) as target:
                        target.sendall(request.raw)
                        _bounded_response(target, connection, self.max_response_bytes)
                    outcomes.append(request.path)
        finally:
            listener.close()
            try:
                self.socket_path.unlink()
            except FileNotFoundError:
                pass
        return tuple(outcomes)

    def serve_one(self) -> None:
        self.serve_requests(1)
