"""Synthetic stdio MCP process for admission proof; no model/provider code."""

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
        record = {"endpoint_identity": identity, "raw_tool": request["params"]["name"]}
        with receipt.open("x", encoding="utf-8") as stream:
            json.dump(record, stream)
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
