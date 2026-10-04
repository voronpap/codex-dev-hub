"""Synthetic stdio MCP process for admission proof; no model/provider code."""

import hashlib
import json
import sys
from pathlib import Path

schema = json.loads(Path(sys.argv[1]).read_bytes())
receipt = Path(sys.argv[2])
identity = sys.argv[3]
for line in sys.stdin.buffer:
    request = json.loads(line)
    if "id" not in request:
        continue
    method = request["method"]
    if method == "initialize":
        result = {
            "protocolVersion": request["params"]["protocolVersion"],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "synthetic-approved-mcp", "version": "1"},
        }
    elif method == "tools/list":
        result = {"tools": [{"name": "devhub_delegate", "inputSchema": schema}]}
    elif method == "tools/call":
        record = {
            "endpoint_identity": identity,
            "raw_tool": request["params"]["name"],
            "schema_hash": hashlib.sha256(
                json.dumps(
                    schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode()
            ).hexdigest(),
            "arguments": request["params"]["arguments"],
        }
        # Every attempted synthetic send leaves a line, including unexpected repeats.
        with receipt.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record) + "\n")
        result = {"content": [{"type": "text", "text": json.dumps(record)}]}
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
