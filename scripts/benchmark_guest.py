"""Minimal guest bootstrap: no fixtures, oracle, evaluator or Dev Hub implementation.

The enclosing OCI container has network=none. Local TCP proxy traffic is forwarded
only to its scoped host Unix proxy. Arm B's stdio MCP bridge has a separate socket.
"""

import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
from pathlib import Path


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
    session = json.loads(Path("/packet/session.json").read_bytes())
    # argv comes from the trusted, hash-verified launcher, not model output.
    try:
        return subprocess.call(session["codex_argv"], stdin=sys.stdin.buffer)
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
