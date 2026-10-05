"""Minimal guest bootstrap: no fixtures, oracle, evaluator or Dev Hub implementation.

The enclosing OCI container has network=none. Local TCP proxy traffic is forwarded
only to its scoped host Unix proxy. Arm B's stdio MCP bridge has a separate socket.
"""

import base64
import binascii
import hashlib
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

TASK_PAYLOAD_BYTE_LIMIT = 1024 * 1024


def copy_stream(source, destination):
    try:
        while data := source.read1(65536):
            destination.write(data)
            destination.flush()
    except (BrokenPipeError, OSError):
        pass


def mcp():
    with socket.socket(socket.AF_UNIX) as connection:
        connection.connect("/bridge/mcp.sock")
        reader = connection.makefile("rb")
        writer = connection.makefile("wb")
        thread = threading.Thread(target=copy_stream, args=(reader, sys.stdout.buffer), daemon=True)
        thread.start()
        copy_stream(sys.stdin.buffer, writer)
        connection.shutdown(socket.SHUT_WR)
        thread.join(timeout=5)


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        with socket.socket(socket.AF_UNIX) as upstream:
            upstream.connect("/bridge/proxy.sock")
            thread = threading.Thread(
                target=copy_stream,
                args=(self.request.makefile("rb"), upstream.makefile("wb")),
                daemon=True,
            )
            thread.start()
            copy_stream(upstream.makefile("rb"), self.request.makefile("wb"))


def run():
    home = Path(os.environ["CODEX_HOME"])
    home.mkdir(parents=True, exist_ok=False)
    shutil.copyfile("/auth.json", home / "auth.json")
    os.chmod(home / "auth.json", 0o600)
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 18080), Proxy)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    session = json.loads(Path("/control/session.json").read_bytes())
    expected = {
        "codex_argv",
        "session_id",
        "plan_sha256",
        "prompt_sha256",
        "prompt_length",
        "protocol_sha256",
        "bootstrap_sha256",
    }
    if set(session) != expected:
        raise ValueError("Invalid guest session metadata")

    def publish(name, value):
        path = Path("/capture") / name
        temporary = path.with_suffix(path.suffix + ".tmp")
        with temporary.open("xb") as stream:
            stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)

    common = {
        "schema_version": 1,
        "session_id": session["session_id"],
        "plan_sha256": session["plan_sha256"],
        "prompt_sha256": session["prompt_sha256"],
        "prompt_length": session["prompt_length"],
        "protocol_sha256": session["protocol_sha256"],
        "bootstrap_sha256": session["bootstrap_sha256"],
    }
    publish("guest-ready.json", {**common, "kind": "guest_ready"})
    frame_path = Path("/capture/task-frame.json")
    while not frame_path.is_file():
        time.sleep(0.02)
    frame = json.loads(frame_path.read_bytes())
    if (
        set(frame)
        != {
            "schema_version",
            "kind",
            "session_id",
            "prompt_sha256",
            "prompt_length",
            "payload_base64",
        }
        or frame["schema_version"] != 1
        or frame["kind"] != "task_frame"
    ):
        raise ValueError("Invalid task frame")
    try:
        prompt = base64.b64decode(frame["payload_base64"], validate=True)
    except (binascii.Error, TypeError) as error:
        raise ValueError("Invalid task frame encoding") from error
    if (
        frame["session_id"] != session["session_id"]
        or type(frame["prompt_length"]) is not int
        or not 0 < frame["prompt_length"] <= TASK_PAYLOAD_BYTE_LIMIT
        or frame["prompt_length"] != session["prompt_length"]
        or len(prompt) != session["prompt_length"]
        or frame["prompt_sha256"] != session["prompt_sha256"]
        or hashlib.sha256(prompt).hexdigest() != session["prompt_sha256"]
    ):
        raise ValueError("Task frame binding mismatch")
    payload = json.loads(prompt)
    if set(payload) != {"instructions", "task", "input", "session"} or payload["session"] != {
        "project": session["session_id"],
        "task_id": session["session_id"],
        "request_key": session["session_id"],
    }:
        raise ValueError("Task payload identity mismatch")
    for key in ("instructions", "task", "input"):
        if not isinstance(payload[key], str):
            raise ValueError("Task payload text required")
    publish(
        "task-accepted.json",
        {
            "schema_version": 1,
            "kind": "task_accepted",
            "session_id": session["session_id"],
            "prompt_sha256": session["prompt_sha256"],
            "prompt_length": session["prompt_length"],
        },
    )
    packet = Path("/packet")
    for name, key in (
        ("instructions.txt", "instructions"),
        ("task.txt", "task"),
        ("input.txt", "input"),
    ):
        (packet / name).write_text(payload[key], encoding="utf-8")
    # argv comes from the trusted, hash-verified launcher, not task/model output.
    try:
        return subprocess.run(session["codex_argv"], input=prompt, check=False).returncode
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    if sys.argv[1:] == ["mcp"]:
        mcp()
    elif sys.argv[1:] == ["run"]:
        raise SystemExit(run())
    else:
        raise SystemExit("Invalid bootstrap mode")
