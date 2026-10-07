import base64
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys

packet = json.loads(pathlib.Path("/control/session.json").read_bytes())
argv = packet["codex_argv"]
cfg = []
for i, arg in enumerate(argv):
    if arg == "-c":
        cfg.extend(argv[i : i + 2])
# --strict-config is exec-only in this exact CLI; metadata commands still load overrides.
cli = ["codex", *cfg]
# Exercise the actual bootstrap's auth and staged-task path using CLI --version only.
prompt = json.dumps(
    {
        "instructions": "synthetic only",
        "task": "synthetic only",
        "input": "synthetic only",
        "session": {
            "project": "config-probe",
            "task_id": "config-probe",
            "request_key": "config-probe",
        },
    },
    sort_keys=True,
    separators=(",", ":"),
).encode()
guest_session = {
    "codex_argv": ["codex", "--version"],
    "session_id": "config-probe",
    "plan_sha256": "0" * 64,
    "prompt_sha256": hashlib.sha256(prompt).hexdigest(),
    "prompt_length": len(prompt),
    "protocol_sha256": "0" * 64,
    "bootstrap_sha256": "0" * 64,
}
pathlib.Path("/capture/task-frame.json").write_text(
    json.dumps(
        {
            "schema_version": 1,
            "kind": "task_frame",
            "session_id": "config-probe",
            "prompt_sha256": guest_session["prompt_sha256"],
            "prompt_length": len(prompt),
            "payload_base64": base64.b64encode(prompt).decode(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
)
# Patch packet reading only in this synthetic metadata probe.
sys.path.insert(0, "/")
import bootstrap  # noqa: E402

original = pathlib.Path.read_bytes


def read(p):
    return json.dumps(guest_session).encode() if str(p) == "/control/session.json" else original(p)


pathlib.Path.read_bytes = read
code = bootstrap.run()
features = subprocess.run([*cli, "features", "list"], capture_output=True)
mcp = subprocess.run([*cli, "mcp", "list", "--json"], capture_output=True)
disabled = [
    "shell_tool",
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

from tool_gate import tool_surface  # noqa: E402

version = subprocess.run(["codex", "--version"], capture_output=True, text=True)
surface = tool_surface(rows, version.stdout.strip())

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
            and all(rows.get(k) == "false" for k in disabled)
            and surface["forbidden_execution_tools_absent"],
            "tool_surface": surface,
            "auth_tmpfs": auth_ok,
            "config_error": "reserved_builtin_provider_override"
            if b"reserved built-in provider IDs" in features.stderr
            else None,
            "egress_runtime": denied,
            "config_diagnostics": {
                "features_exit_code": features.returncode,
                "mcp_list_exit_code": mcp.returncode,
                "mcp_scope_matches": scope,
                "required_feature_states": {key: rows.get(key) for key in disabled},
            },
        }
    )
)
