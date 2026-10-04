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
    assert len(responses[1]["result"]["tools"]) == 1
    assert responses[1]["result"]["tools"][0]["name"] == "devhub_delegate"
    assert responses[1]["result"]["tools"][0]["inputSchema"] == json.loads(SCHEMA.read_bytes())
    observed = json.loads(receipt.read_bytes())
    assert observed == {
        "endpoint_identity": "synthetic-only",
        "raw_tool": "devhub_delegate",
        "schema_hash": APPROVED,
        "arguments": json.loads(PAYLOAD.read_bytes()),
    }
    assert json.loads(responses[2]["result"]["content"][0]["text"]) == observed


def test_proof_harness_uses_pinned_extension_constructor() -> None:
    harness = (REPO / "scripts/production_router_test.rs").read_text(encoding="utf-8")
    assert "ExtensionData::default()" not in harness
    assert harness.count('ExtensionData::new("devhub-proof")') == 5


def test_diagnostic_precedes_initial_router_admission() -> None:
    harness = (REPO / "scripts/production_router_test.rs").read_text(encoding="utf-8")
    assert harness.index('stage("initial_binding_before_first_approve")') < harness.index(
        'stage("initial_router_admission")'
    )
    assert '"DEVHUB_BINDING_DIAGNOSTIC={}"' in harness
    assert '"DEVHUB_SERVER_DIAGNOSTIC={}"' in harness
    assert harness.count("c.mcp_servers =") == 1
    assert '"devhub_delegate".to_string(),\n                server.clone(),' in harness


def test_permission_materialization_precedes_runtime_publication() -> None:
    harness = (REPO / "scripts/production_router_test.rs").read_text(encoding="utf-8")
    assert harness.index("config.set_server_permission_profiles(") < harness.index(
        "runtime.replace(input()).await"
    )
    assert "environment.permission_profile_with_workspace_roots()" in harness
    assert "assert!(present)" in harness
    assert '"DEVHUB_PERMISSION_DIAGNOSTIC={}"' in harness


def test_build008_diagnostic_contract_is_single_build_and_reusable() -> None:
    runner = (REPO / "scripts/build_production_router_proof.py").read_text(encoding="utf-8")
    assert '"build_id": "build-008"' in runner
    assert runner.count('"cargo",\n        "test"') == 1
    assert "--no-run" in runner
    assert 'binary_dir = args.output.parent / "binaries"' in runner
    assert "runner-manifest.json" in runner
    runner += (REPO / "scripts/run_production_diagnostics.py").read_text(encoding="utf-8")
    assert "--exact" in runner
    assert "RUST_BACKTRACE" in runner
    assert "RUST_MIN_STACK" in runner
    assert "handler-large-stack" in runner
    assert "devhub_production_admission_path_catalog" in runner


def test_build008_inner_checkpoint_plan_is_implemented() -> None:
    instrumentation = (REPO / "scripts/instrument_approval_proof.py").read_text(encoding="utf-8")
    for marker in [
        "preparation_closure_entered",
        "approval_application_enter",
        "approval_application_exit",
        "memory_pollution_enter",
        "memory_pollution_exit",
        "rewrite_args_enter",
        "rewrite_args_exit",
        "request_meta_build_enter",
        "request_meta_build_exit",
        "request_ids_enter",
        "request_ids_exit",
        "sandbox_meta_enter",
        "sandbox_meta_exit",
        "trace_enter",
        "trace_exit",
        "add_request_meta_enter",
        "add_request_meta_exit",
        "trusted_access_context_enter",
        "trusted_access_context_exit",
        "transport_call_enter",
        "transport_call_return",
    ]:
        assert marker in instrumentation


def test_build008_receipts_are_persistent_and_fsynced() -> None:
    adversarial = (REPO / "scripts/production_router_adversarial_test.rs").read_text(
        encoding="utf-8"
    )
    catalog = (REPO / "scripts/production_catalog_test.rs").read_text(encoding="utf-8")
    synthetic = (REPO / "scripts/synthetic_approved_mcp.py").read_text(encoding="utf-8")
    assert 'std::env::var("DEVHUB_RECEIPT_PATH")' in adversarial
    assert 'std::env::var("DEVHUB_RECEIPT_PATH")' in catalog
    assert "os.fsync(stream.fileno())" in synthetic
