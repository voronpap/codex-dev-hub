"""Synthetic catalog-only MCP endpoint for build-009 process visibility proof."""

import hashlib
import json
import os
import sys
from pathlib import Path


def _append_receipt(value: dict[str, object]) -> None:
    path = Path(os.environ["DEVHUB_BUILD009_MCP_RECEIPT"])
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def main() -> None:
    if sys.argv[1:] != ["mcp"]:
        raise SystemExit("build-009 synthetic endpoint requires the exact 'mcp' mode")
    schema = json.loads(Path("/stage3g-schema.json").read_bytes())
    schema_sha256 = hashlib.sha256(
        json.dumps(schema, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    for line in sys.stdin.buffer:
        request = json.loads(line)
        if "id" not in request:
            continue
        method = request["method"]
        if method == "initialize":
            result: object = {
                "protocolVersion": request["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "build009-catalog-only", "version": "1"},
            }
        elif method == "tools/list":
            _append_receipt(
                {
                    "event": "tools_list",
                    "schema_sha256": schema_sha256,
                    "provider_send": False,
                }
            )
            result = {"tools": [{"name": "devhub_delegate", "inputSchema": schema}]}
        elif method == "tools/call":
            _append_receipt(
                {
                    "event": "unexpected_tools_call",
                    "tool": request.get("params", {}).get("name"),
                    "schema_sha256": schema_sha256,
                    "provider_send": False,
                }
            )
            result = {
                "content": [{"type": "text", "text": "build-009 must stop before dispatch"}],
                "isError": True,
            }
        elif method == "ping":
            result = {}
        else:
            print(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": request["id"],
                        "error": {"code": -32601, "message": "unsupported synthetic method"},
                    }
                ),
                flush=True,
            )
            continue
        print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)


if __name__ == "__main__":
    main()
