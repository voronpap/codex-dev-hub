"""Offline checks for proof inputs; these do not certify production admission."""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from devhub.delegate import DelegationRequest

REPO = Path(__file__).resolve().parents[1]
SCHEMA = REPO / "docs/evidence/stage3g-production-router/delegate-input-schema.json"
APPROVED = "0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"
PAYLOAD = REPO / "patches/stage3g-approved-call/synthetic-payload.json"


def test_synthetic_payload_matches_real_wire_contract() -> None:
    request = DelegationRequest.model_validate_json(PAYLOAD.read_bytes())
    assert request.privacy == "local_only"
    assert request.allow_cloud is False


def test_real_delegate_schema_still_matches_reviewed_identity() -> None:
    actual = DelegationRequest.model_json_schema()
    assert actual == json.loads(SCHEMA.read_bytes())
    canonical = json.dumps(actual, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert hashlib.sha256(canonical.encode()).hexdigest() == APPROVED


def test_synthetic_process_reports_its_own_dispatch_receipt(tmp_path: Path) -> None:
    receipt = tmp_path / "receipt.json"
    requests = [
        {"id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
        {"id": 2, "method": "tools/list"},
        {
            "id": 3,
            "method": "tools/call",
            "params": {"name": "devhub_delegate", "arguments": json.loads(PAYLOAD.read_bytes())},
        },
    ]
    run = subprocess.run(
        [
            sys.executable,
            str(REPO / "scripts/synthetic_approved_mcp.py"),
            str(SCHEMA),
            str(receipt),
            "synthetic-only",
        ],
        input="".join(json.dumps({"jsonrpc": "2.0", **r}) + "\n" for r in requests),
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=10,
        env={k: v for k, v in os.environ.items() if k.upper() in {"SYSTEMROOT", "TEMP", "TMP"}},
        check=True,
    )
    assert not run.stderr
    responses = [json.loads(line) for line in run.stdout.splitlines()]
    assert [r["id"] for r in responses] == [1, 2, 3]
    assert responses[1]["result"]["tools"][0]["inputSchema"] == json.loads(SCHEMA.read_bytes())
    observed = json.loads(receipt.read_bytes())
    assert observed == {
        "endpoint_identity": "synthetic-only",
        "raw_tool": "devhub_delegate",
        "schema_hash": APPROVED,
        "arguments": json.loads(PAYLOAD.read_bytes()),
    }
    assert json.loads(responses[2]["result"]["content"][0]["text"]) == observed
