import json
import os
import pathlib
import socket
import subprocess
import sys

packet = json.loads(pathlib.Path("/packet/session.json").read_bytes())
argv = packet["codex_argv"]
cfg = []
for i, arg in enumerate(argv):
    if arg == "-c":
        cfg.extend(argv[i : i + 2])
cli = ["codex", "--strict-config", *cfg]
# Exercise the actual bootstrap's tmpfs auth-copy path using CLI --version only.
packet["codex_argv"] = ["codex", "--version"]
# Patch packet reading only in this synthetic metadata probe.
sys.path.insert(0, "/")
import bootstrap  # noqa: E402

original = pathlib.Path.read_bytes


def read(p):
    return json.dumps(packet).encode() if str(p) == "/packet/session.json" else original(p)


pathlib.Path.read_bytes = read
code = bootstrap.run()
features = subprocess.run([*cli, "features", "list"], capture_output=True)
mcp = subprocess.run([*cli, "mcp", "list", "--json"], capture_output=True)
disabled = [
    "shell_tool",
    "unified_exec",
    "apps",
    "multi_agent",
    "goals",
    "hooks",
    "memories",
    "remote_plugin",
    "shell_snapshot",
]
rows = {x.split()[0]: x.split()[-1] for x in features.stdout.decode().splitlines() if x.split()}
tools = json.loads(mcp.stdout) if mcp.returncode == 0 else None
scope = (
    (tools == [])
    if packet["arm"] == "A"
    else (isinstance(tools, list) and len(tools) == 1 and tools[0]["name"] == "devhub_delegate")
)

auth = pathlib.Path(os.environ["CODEX_HOME"]) / "auth.json"
mounts = pathlib.Path("/proc/mounts").read_text()
tmpfs = any(line.split()[1:3] == ["/home/runner", "tmpfs"] for line in mounts.splitlines())
auth_ok = (
    code == 0
    and tmpfs
    and (auth.stat().st_mode & 0o777) == 0o600
    and auth.read_bytes() == pathlib.Path("/auth.json").read_bytes()
)
denied = True
for host in [
    "example.com",
    "10.0.0.1",
    "127.0.0.1",
    "host.docker.internal",
    "api.groq.com",
    "generativelanguage.googleapis.com",
]:
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(4)
        s.connect("/bridge/proxy.sock")
        s.sendall(("CONNECT " + host + ":443 HTTP/1.1\r\n\r\n").encode())
        try:
            response = s.recv(128)
        except (ConnectionResetError, TimeoutError):
            response = b""
        denied = denied and b"200" not in response
print(
    json.dumps(
        {
            "cli_config": features.returncode == 0
            and scope
            and all(rows.get(k) == "false" for k in disabled),
            "auth_tmpfs": auth_ok,
            "egress_runtime": denied,
        }
    )
)
