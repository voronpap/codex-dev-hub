import os
import socket
import sys
import threading
from pathlib import Path
from stat import S_IMODE

import pytest
from pydantic import ValidationError

from devhub.ollama import LocalHTTP, OllamaConfig
from devhub.ollama_transport import (
    OLLAMA_BRIDGE_ARGS,
    OllamaBridgeAuthorityV1,
    _handle,
    validate_ollama_bridge,
)

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux peer credentials required")


def authority(tmp_path: Path, listener: socket.socket) -> OllamaBridgeAuthorityV1:
    parent = tmp_path / "private"
    path = parent / "ollama.sock"
    parent.chmod(0o700)
    path.chmod(0o600)
    observed = path.lstat()
    uid = os.geteuid()
    return OllamaBridgeAuthorityV1(
        socket_path=str(path),
        socket_parent_uid=uid,
        socket_uid=uid,
        socket_device=observed.st_dev,
        socket_inode=observed.st_ino,
        bridge_pid=os.getpid(),
        bridge_start_time_ticks=100,
        bridge_uid=uid,
        bridge_network_namespace_id="net:[123]",
        bridge_python_path="/opt/devhub/bin/python",
        bridge_python_executable_sha256="1" * 64,
        bridge_process_executable_sha256="1" * 64,
        bridge_runtime_environment_id="2" * 64,
        bridge_module_origin="lib/python3.12/site-packages/devhub/ollama_transport.py",
        bridge_module_sha256="3" * 64,
        server_pid=os.getpid() + 1,
        server_start_time_ticks=101,
        server_uid=uid,
        server_executable_sha256="4" * 64,
        server_network_namespace_id="net:[123]",
        server_listener_inode=42,
    )


def listening_socket(tmp_path: Path) -> tuple[socket.socket, Path]:
    parent = tmp_path / "private"
    parent.mkdir(mode=0o700)
    path = parent / "ollama.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)
    return listener, path


def test_bridge_authority_rejects_general_target_and_namespace_mismatch(tmp_path):
    listener, _ = listening_socket(tmp_path)
    try:
        value = authority(tmp_path, listener).model_dump(mode="json")
        value["destination_port"] = 11435
        with pytest.raises(ValidationError):
            OllamaBridgeAuthorityV1.model_validate(value)
        value = authority(tmp_path, listener).model_dump(mode="json")
        value["server_network_namespace_id"] = "net:[999]"
        with pytest.raises(ValidationError, match="namespaces differ"):
            OllamaBridgeAuthorityV1.model_validate(value)
    finally:
        listener.close()


def test_validate_bridge_rejects_socket_and_process_substitution(tmp_path, monkeypatch):
    listener, path = listening_socket(tmp_path)
    value = authority(tmp_path, listener)
    monkeypatch.setattr("devhub.ollama_transport.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        "devhub.ollama_transport._process_start_time_ticks",
        lambda pid: 100 if pid == value.bridge_pid else 101,
    )
    monkeypatch.setattr("devhub.ollama_transport._process_uid", lambda _: os.geteuid())
    monkeypatch.setattr(
        "devhub.ollama_transport._process_cmdline",
        lambda _: (
            value.bridge_python_path,
            *OLLAMA_BRIDGE_ARGS,
            "--socket",
            value.socket_path,
        ),
    )
    monkeypatch.setattr("devhub.ollama_transport.os.readlink", lambda _: "net:[123]")
    monkeypatch.setattr("devhub.ollama_transport.server_listener_inode", lambda _: 42)
    monkeypatch.setattr(
        "devhub.ollama_transport.file_sha256",
        lambda path: (
            value.bridge_python_executable_sha256
            if str(path)
            in {
                value.bridge_python_path,
                f"/proc/{value.bridge_pid}/exe",
            }
            else (
                value.bridge_module_sha256
                if str(path).endswith("ollama_transport.py")
                else value.server_executable_sha256
            )
        ),
    )
    original_is_file = Path.is_file
    monkeypatch.setattr(
        Path,
        "is_file",
        lambda self: True if str(self).endswith("ollama_transport.py") else original_is_file(self),
    )
    monkeypatch.setattr(Path, "is_symlink", lambda _: False)
    try:
        assert validate_ollama_bridge(value) == path
        wrong_inode = value.model_copy(update={"socket_inode": value.socket_inode + 1})
        with pytest.raises(ValueError, match="socket identity changed"):
            validate_ollama_bridge(wrong_inode)
        monkeypatch.setattr("devhub.ollama_transport._process_start_time_ticks", lambda _: 999)
        with pytest.raises(ValueError, match="process identity changed"):
            validate_ollama_bridge(value)
    finally:
        listener.close()


def test_bridge_authority_rejects_cmdline_interpreter_and_process_executable_mismatch(tmp_path):
    listener, _ = listening_socket(tmp_path)
    try:
        value = authority(tmp_path, listener).model_dump(mode="json")
        value["bridge_process_executable_sha256"] = "f" * 64
        with pytest.raises(ValidationError, match="process and reviewed interpreter"):
            OllamaBridgeAuthorityV1.model_validate(value)
    finally:
        listener.close()


def test_validate_bridge_rejects_same_namespace_listener_substitution(tmp_path, monkeypatch):
    listener, _ = listening_socket(tmp_path)
    value = authority(tmp_path, listener)
    monkeypatch.setattr("devhub.ollama_transport.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        "devhub.ollama_transport._process_start_time_ticks",
        lambda pid: value.bridge_start_time_ticks if pid == value.bridge_pid else 101,
    )
    monkeypatch.setattr("devhub.ollama_transport._process_uid", lambda _: os.geteuid())
    monkeypatch.setattr("devhub.ollama_transport.os.readlink", lambda _: "net:[123]")
    monkeypatch.setattr("devhub.ollama_transport.server_listener_inode", lambda _: 99)
    try:
        with pytest.raises(ValueError, match="process identity changed"):
            validate_ollama_bridge(value)
    finally:
        listener.close()


def test_local_http_uses_peer_credential_bound_unix_socket(tmp_path, monkeypatch):
    listener, _ = listening_socket(tmp_path)
    value = authority(tmp_path, listener)
    monkeypatch.setattr(
        "devhub.ollama_transport.validate_ollama_bridge", lambda _: Path(value.socket_path)
    )
    request_seen = bytearray()

    def server():
        connection, _ = listener.accept()
        with connection:
            while b"\r\n\r\n" not in request_seen:
                request_seen.extend(connection.recv(4096))
            body = b'{"version":"0.34.2"}'
            connection.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )

    thread = threading.Thread(target=server, daemon=True)
    thread.start()
    config = OllamaConfig(
        endpoint="http://127.0.0.1:11434",
        model="qwen2.5:14b-instruct",
        model_digest="1" * 64,
    )
    try:
        assert LocalHTTP(config, bridge=value).request("/api/version") == {"version": "0.34.2"}
        assert request_seen.startswith(b"GET /api/version HTTP/1.1")
    finally:
        listener.close()


def test_bridge_socket_mode_contract_is_exact(tmp_path):
    listener, path = listening_socket(tmp_path)
    try:
        path.chmod(0o666)
        value = authority(tmp_path, listener)
        assert S_IMODE(path.lstat().st_mode) == 0o600
        assert value.socket_mode == 0o600
    finally:
        listener.close()


def test_bridge_relays_only_to_fixed_ollama_loopback():
    target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        target.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        target.bind(("127.0.0.1", 11434))
    except OSError:
        target.close()
        pytest.skip("Fixed Ollama qualification port is already in use")
    target.listen(1)
    client, bridge_side = socket.socketpair()
    worker = threading.Thread(target=_handle, args=(bridge_side, os.geteuid()), daemon=True)
    worker.start()
    try:
        client.sendall(b"reviewed-request")
        client.shutdown(socket.SHUT_WR)
        upstream, address = target.accept()
        with upstream:
            assert address[0] == "127.0.0.1"
            assert upstream.recv(64) == b"reviewed-request"
            upstream.sendall(b"reviewed-response")
        assert client.recv(64) == b"reviewed-response"
    finally:
        client.close()
        target.close()
        worker.join(timeout=5)
