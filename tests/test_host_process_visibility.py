import importlib.util
import json
import socket
import subprocess
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "qualify_host_process_visibility", ROOT / "scripts/qualify_host_process_visibility.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def rpc(connection: socket.socket, method: str, request_id: int):
    connection.sendall(
        json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": {}}).encode()
        + b"\n"
    )
    with connection.makefile("rb") as reader:
        return json.loads(reader.readline())


def test_catalog_observer_lists_once_and_never_executes_provider() -> None:
    server, client = socket.socketpair()
    catalog = MODULE.CatalogOnly({"type": "object"})
    worker = threading.Thread(target=catalog, args=(server,))
    worker.start()
    try:
        listed = rpc(client, "tools/list", 1)
        called = rpc(client, "tools/call", 2)
    finally:
        client.close()
        worker.join(timeout=5)
    assert listed["result"]["tools"][0]["name"] == "devhub_delegate"
    assert called["result"]["isError"] is True
    assert len(catalog.records) == 1
    assert catalog.records[0]["provider_send"] is False
    assert catalog.tool_calls == 1


def test_default_argument_path_removes_only_stage3g_authority() -> None:
    args = [
        "codex",
        "exec",
        "--devhub-stage3g-host-manifest",
        "/manifest.json",
        "--devhub-stage3g-arm",
        "a",
        "-c",
        "features.apps=false",
        "-",
    ]
    assert MODULE._without_stage3g_authority(args) == [
        "codex",
        "exec",
        "-c",
        "features.apps=false",
        "-",
    ]


def test_observer_file_without_reviewed_stop_marker_is_rejected(tmp_path) -> None:
    observer = tmp_path / "observer.json"
    observer.write_text("{}")
    result = subprocess.CompletedProcess([], 1, stdout=b"different failure", stderr=b"")
    try:
        MODULE._require_reviewed_stop(result, observer, "A")
    except ValueError as error:
        assert "reviewed boundary" in str(error)
    else:
        raise AssertionError("wrong observer stop diagnostic was accepted")


def test_reviewed_stop_requires_exact_exit_marker_and_observer(tmp_path) -> None:
    observer = tmp_path / "observer.json"
    observer.write_text("{}")
    result = subprocess.CompletedProcess([], 1, stdout=MODULE.PRE_SAMPLING_STOP_MARKER, stderr=b"")
    MODULE._require_reviewed_stop(result, observer, "B")
