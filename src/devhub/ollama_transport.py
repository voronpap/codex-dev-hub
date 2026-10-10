"""Fixed-destination Unix transport for the isolated Stage 3G Ollama process."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import os
import platform
import socket
import stat
import struct
import threading
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from devhub.brain_models import Digest
from devhub.models import Contract

OLLAMA_BRIDGE_ENTRYPOINT = "devhub.ollama_transport"
OLLAMA_BRIDGE_ARGS = ("-I", "-m", OLLAMA_BRIDGE_ENTRYPOINT)
OLLAMA_DESTINATION_HOST: Literal["127.0.0.1"] = "127.0.0.1"
OLLAMA_DESTINATION_PORT: Literal[11434] = 11434


def file_sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


class OllamaBridgeAuthorityV1(Contract):
    """Exact process/socket authority for one fixed local Ollama bridge."""

    kind: Literal["stage3g_ollama_unix_bridge"] = "stage3g_ollama_unix_bridge"
    socket_path: str = Field(min_length=1, max_length=1024)
    socket_parent_uid: Annotated[int, Field(ge=1)]
    socket_parent_mode: Literal[448] = 0o700
    socket_uid: Annotated[int, Field(ge=1)]
    socket_mode: Literal[384] = 0o600
    socket_device: Annotated[int, Field(ge=1)]
    socket_inode: Annotated[int, Field(ge=1)]
    bridge_pid: Annotated[int, Field(ge=1)]
    bridge_start_time_ticks: Annotated[int, Field(ge=1)]
    bridge_uid: Annotated[int, Field(ge=1)]
    bridge_network_namespace_id: Annotated[str, Field(pattern=r"^net:\[[0-9]+\]$")]
    bridge_python_path: str = Field(min_length=1, max_length=1024)
    bridge_python_executable_sha256: Digest
    bridge_process_executable_sha256: Digest
    bridge_runtime_environment_id: Digest
    bridge_module_origin: str = Field(min_length=1, max_length=512)
    bridge_module_sha256: Digest
    bridge_proxy_environment_inherited: Literal[False] = False
    server_pid: Annotated[int, Field(ge=1)]
    server_start_time_ticks: Annotated[int, Field(ge=1)]
    server_uid: Annotated[int, Field(ge=1)]
    server_executable_sha256: Digest
    server_network_namespace_id: Annotated[str, Field(pattern=r"^net:\[[0-9]+\]$")]
    server_listener_inode: Annotated[int, Field(ge=1)]
    destination_host: Literal["127.0.0.1"] = OLLAMA_DESTINATION_HOST
    destination_port: Literal[11434] = OLLAMA_DESTINATION_PORT

    @field_validator("socket_path", "bridge_python_path")
    @classmethod
    def absolute_locator(cls, value: str) -> str:
        if not Path(value).is_absolute():
            raise ValueError("Ollama bridge locators must be absolute")
        return value

    @field_validator("bridge_module_origin")
    @classmethod
    def relative_module_origin(cls, value: str) -> str:
        item = PurePosixPath(value)
        if item.is_absolute() or ".." in item.parts or item.name != "ollama_transport.py":
            raise ValueError("Ollama bridge module origin must be a bounded relative locator")
        return value

    @model_validator(mode="after")
    def single_unprivileged_namespace(self) -> OllamaBridgeAuthorityV1:
        if self.socket_uid != self.bridge_uid or self.socket_parent_uid != self.bridge_uid:
            raise ValueError("Ollama bridge socket ownership differs from bridge process")
        if self.server_uid != self.bridge_uid:
            raise ValueError("Ollama server and bridge must run as the same unprivileged user")
        if self.server_network_namespace_id != self.bridge_network_namespace_id:
            raise ValueError("Ollama server and bridge network namespaces differ")
        if self.bridge_process_executable_sha256 != self.bridge_python_executable_sha256:
            raise ValueError("Ollama bridge process and reviewed interpreter differ")
        return self


def _process_start_time_ticks(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text()
    try:
        fields = raw.rsplit(")", 1)[1].split()
        return int(fields[19])
    except (IndexError, ValueError) as error:
        raise ValueError("Ollama process start identity is unavailable") from error


def _process_uid(pid: int) -> int:
    for line in Path(f"/proc/{pid}/status").read_text().splitlines():
        if line.startswith("Uid:"):
            return int(line.split()[1])
    raise ValueError("Ollama process owner identity is unavailable")


def _process_cmdline(pid: int) -> tuple[str, ...]:
    return tuple(
        item.decode("utf-8")
        for item in Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        if item
    )


def server_listener_inode(pid: int) -> int:
    """Return the exact fixed-port LISTEN inode owned by the reviewed Ollama PID."""

    expected = "0100007F:2CAA"  # 127.0.0.1:11434 in /proc/net/tcp encoding.
    matches: list[int] = []
    for table in (Path(f"/proc/{pid}/net/tcp"), Path(f"/proc/{pid}/net/tcp6")):
        try:
            lines = table.read_text().splitlines()[1:]
        except FileNotFoundError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) > 9 and fields[1].upper() == expected and fields[3] == "0A":
                matches.append(int(fields[9]))
    if len(matches) != 1:
        raise ValueError("Exact Ollama loopback listener identity is unavailable")
    inode = matches[0]
    owned = False
    for descriptor in Path(f"/proc/{pid}/fd").iterdir():
        try:
            owned = os.readlink(descriptor) == f"socket:[{inode}]"
        except FileNotFoundError:
            continue
        if owned:
            break
    if not owned:
        raise ValueError("Ollama listener is not owned by the reviewed server process")
    return inode


def _safe_socket_stat(authority: OllamaBridgeAuthorityV1) -> os.stat_result:
    path = Path(authority.socket_path)
    parent = path.parent
    if path.parent == path or path.name in {"", ".", ".."}:
        raise ValueError("Ollama bridge socket locator is invalid")
    parent_stat = os.lstat(parent)
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or stat.S_ISLNK(parent_stat.st_mode)
        or parent.resolve(strict=True) != parent
        or stat.S_IMODE(parent_stat.st_mode) != authority.socket_parent_mode
        or parent_stat.st_uid != authority.socket_parent_uid
    ):
        raise ValueError("Ollama bridge socket parent identity changed")
    socket_stat = os.lstat(path)
    if (
        not stat.S_ISSOCK(socket_stat.st_mode)
        or stat.S_ISLNK(socket_stat.st_mode)
        or stat.S_IMODE(socket_stat.st_mode) != authority.socket_mode
        or socket_stat.st_uid != authority.socket_uid
        or socket_stat.st_dev != authority.socket_device
        or socket_stat.st_ino != authority.socket_inode
    ):
        raise ValueError("Ollama bridge socket identity changed")
    return socket_stat


def validate_ollama_bridge(authority: OllamaBridgeAuthorityV1) -> Path:
    """Revalidate every process and filesystem identity before using the bridge."""

    if platform.system() != "Linux" or not hasattr(socket, "SO_PEERCRED"):
        raise ValueError("Qualified Ollama bridge requires Linux peer credentials")
    path = Path(authority.socket_path)
    _safe_socket_stat(authority)
    bridge_namespace = os.readlink(f"/proc/{authority.bridge_pid}/ns/net")
    server_namespace = os.readlink(f"/proc/{authority.server_pid}/ns/net")
    if (
        _process_start_time_ticks(authority.bridge_pid) != authority.bridge_start_time_ticks
        or _process_uid(authority.bridge_pid) != authority.bridge_uid
        or bridge_namespace != authority.bridge_network_namespace_id
        or _process_start_time_ticks(authority.server_pid) != authority.server_start_time_ticks
        or _process_uid(authority.server_pid) != authority.server_uid
        or server_namespace != authority.server_network_namespace_id
        or bridge_namespace != server_namespace
        or server_listener_inode(authority.server_pid) != authority.server_listener_inode
    ):
        raise ValueError("Ollama bridge/server process identity changed")
    command = _process_cmdline(authority.bridge_pid)
    expected_command = (
        authority.bridge_python_path,
        *OLLAMA_BRIDGE_ARGS,
        "--socket",
        authority.socket_path,
    )
    if command != expected_command:
        raise ValueError("Ollama bridge command identity changed")
    interpreter = Path(authority.bridge_python_path)
    module = interpreter.parent.parent / authority.bridge_module_origin
    if (
        file_sha256(interpreter) != authority.bridge_python_executable_sha256
        or file_sha256(Path(f"/proc/{authority.bridge_pid}/exe"))
        != authority.bridge_process_executable_sha256
        or module.is_symlink()
        or not module.is_file()
        or file_sha256(module) != authority.bridge_module_sha256
        or file_sha256(Path(f"/proc/{authority.server_pid}/exe"))
        != authority.server_executable_sha256
    ):
        raise ValueError("Ollama bridge/server executable identity changed")
    return path


class UnixHTTPConnection(http.client.HTTPConnection):
    """http.client-compatible connection with a credential-bound AF_UNIX transport."""

    def __init__(self, authority: OllamaBridgeAuthorityV1, timeout: float) -> None:
        super().__init__(OLLAMA_DESTINATION_HOST, OLLAMA_DESTINATION_PORT, timeout=timeout)
        self.authority = authority

    def connect(self) -> None:
        path = validate_ollama_bridge(self.authority)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(self.timeout)
        try:
            client.connect(str(path))
            pid, uid, _ = struct.unpack(
                "3i",
                client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
            )
            if pid != self.authority.bridge_pid or uid != self.authority.bridge_uid:
                raise ValueError("Ollama bridge peer credentials changed")
        except Exception:
            client.close()
            raise
        self.sock = client


def _relay(source: socket.socket, destination: socket.socket) -> None:
    try:
        while chunk := source.recv(64 * 1024):
            destination.sendall(chunk)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def _handle(connection: socket.socket, allowed_uid: int) -> None:
    with connection:
        _, uid, _ = struct.unpack(
            "3i",
            connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
        )
        if uid != allowed_uid:
            return
        with socket.create_connection((OLLAMA_DESTINATION_HOST, OLLAMA_DESTINATION_PORT)) as target:
            upstream = threading.Thread(target=_relay, args=(connection, target), daemon=True)
            upstream.start()
            _relay(target, connection)
            upstream.join(timeout=5)


def serve_fixed_ollama_bridge(socket_path: Path) -> None:
    """Serve only the compiled-in Ollama loopback target from one private Unix socket."""

    if platform.system() != "Linux" or not hasattr(socket, "SO_PEERCRED"):
        raise ValueError("Ollama Unix bridge requires Linux peer credentials")
    path = Path(os.path.abspath(socket_path))
    parent = path.parent
    parent_stat = os.lstat(parent)
    if (
        path.parent == path
        or path.exists()
        or path.is_symlink()
        or not stat.S_ISDIR(parent_stat.st_mode)
        or stat.S_ISLNK(parent_stat.st_mode)
        or parent.resolve(strict=True) != parent
        or parent_stat.st_uid != os.geteuid()
        or stat.S_IMODE(parent_stat.st_mode) != 0o700
        or os.geteuid() == 0
    ):
        raise ValueError("Bridge socket requires an empty path in an owned 0700 directory")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
        path.chmod(0o600)
        listener.listen(8)
        while True:
            connection, _ = listener.accept()
            threading.Thread(target=_handle, args=(connection, os.geteuid()), daemon=True).start()
    finally:
        listener.close()
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", type=Path, required=True)
    args = parser.parse_args()
    serve_fixed_ollama_bridge(args.socket)


if __name__ == "__main__":
    main()
