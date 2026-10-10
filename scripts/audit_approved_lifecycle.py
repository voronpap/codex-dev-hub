"""Offline pinned-anchor, Apps exclusion and lifecycle checks; never compile/send."""

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from devhub.delegate import DelegationRequest

ROOT = Path(__file__).resolve().parents[1]


def audit(source: Path, disposable: Path, output: Path) -> None:
    constructor_path = "codex-rs/ext/extension-api/src/state.rs"
    constructor_raw = (source / constructor_path).read_bytes()
    constructor_hash = hashlib.sha256(constructor_raw).hexdigest()
    assert constructor_hash == "b7b6064ab9df274fcb52e5457c5e05b2b9cad92f188714939864164f022b49a1"
    constructor = constructor_raw.decode("utf-8")
    assert "pub fn new(level_id: impl Into<String>) -> Self" in constructor
    assert "Self::new_with_init(level_id, ExtensionDataInit::default())" in constructor
    harness = (ROOT / "scripts/production_router_test.rs").read_bytes()
    assert b"ExtensionData::default()" not in harness
    assert harness.count(b'ExtensionData::new("devhub-proof")') == 5
    manifest = json.loads(
        (ROOT / "patches/stage3g-approved-call/candidate.sources.json").read_bytes()
    )
    disposable.mkdir(parents=True, exist_ok=False)
    for name, identity in manifest["files"].items():
        if identity["upstream_sha256"]:
            raw = (source / name).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == identity["upstream_sha256"], name
            destination = disposable / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
    patch = (ROOT / "patches/stage3g-approved-call/candidate.patch").read_bytes()
    for flags in (["--check"], []):
        subprocess.run(
            ["git", "-c", "core.autocrlf=false", "apply", *flags, "-"],
            cwd=disposable,
            input=patch,
            check=True,
        )
    for name, identity in manifest["files"].items():
        assert (
            hashlib.sha256((disposable / name).read_bytes()).hexdigest()
            == identity["patched_sha256"]
        ), name
    runtime = (disposable / "codex-rs/codex-mcp/src/runtime.rs").read_text()
    upstream = (source / "codex-rs/codex-mcp/src/runtime.rs").read_text()
    marker = """    pub fn reconnect_on_next_refresh(&self) {
        self.reconnect_pending.store(true, Ordering::Release);
    }"""
    assert marker in runtime and marker in upstream
    assert "codex-rs/core/src/session/handlers.rs" not in manifest["files"]
    assert runtime.count("self.current.store(") == 1
    shutdown = runtime.split("    pub async fn shutdown(&self) {", 1)[1].split("\n    }", 1)[0]
    assert (
        shutdown.index("admission_publication.lock().await")
        < shutdown.index("let current = self.current.load_full()")
        < shutdown.index("current.admission_generation.invalidate().await")
        < shutdown.index("current.connections.shutdown().await")
    )
    assert "latest_connections" not in shutdown
    client = (source / "codex-rs/codex-mcp/src/rmcp_client.rs").read_text()
    constants = (source / "codex-rs/codex-mcp/src/mcp/mod.rs").read_text()
    assert 'CODEX_APPS_MCP_SERVER_NAME: &str = "codex_apps"' in constants
    assert "let is_codex_apps_mcp_server = server_name == CODEX_APPS_MCP_SERVER_NAME;" in client
    assert "let startup_reconnect = is_codex_apps_mcp_server.then(||" in client
    assert "state.current_client = Some(client);" in client
    assert "codex-rs/codex-mcp/src/rmcp_client.rs" not in manifest["files"]
    policy = (disposable / "codex-rs/core/src/approved_delegate.rs").read_text()
    assert (
        '"devhub_delegate",\n            "devhub_delegate",\n'
        '            "mcp__devhub_delegate",\n            "devhub_delegate",' in policy
    )
    binding = (disposable / "codex-rs/codex-mcp/src/binding.rs").read_text()
    assert "crate::McpServerSource::Config" in binding
    assert "registration.config() == expected_server" in binding
    assert "info.server_name == server" in binding
    assert "Some(generation) => Some(generation.lease().await?)" in binding
    assert "run_with_snapshot(&self.catalog_snapshot" in binding
    assert (
        "captured.admission_generation = Some(Arc::clone(&current.admission_generation))" in runtime
    )
    schema = DelegationRequest.model_json_schema()
    assert schema == json.loads(
        (ROOT / "docs/evidence/stage3g-production-router/delegate-input-schema.json").read_bytes()
    )
    schema_hash = hashlib.sha256(
        json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    assert schema_hash == "0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"
    payload = (ROOT / "patches/stage3g-approved-call/synthetic-payload.json").read_bytes()
    DelegationRequest.model_validate_json(payload)
    # Standalone proof test rustfmt check is separate; copy for the same cheap formatter pass.
    shutil.copyfile(ROOT / "scripts/production_router_test.rs", disposable / "proof.rs")
    receipt = {
        "scope": "source-level only; no compiled result",
        "pinned_source": manifest["pinned_source"],
        "constructor_source_hash": constructor_hash,
        "constructor_regression_check": True,
        "test_hash": hashlib.sha256(harness).hexdigest(),
        "patch_hash": hashlib.sha256(patch).hexdigest(),
        "source_and_patched_hashes": manifest["files"],
        "anchor_and_apply_checks": True,
        "sync_marker_unchanged": True,
        "shutdown_single_snapshot": True,
        "apps_reconnect_path_observed": True,
        "apps_reconnect_relevant_to_devhub_delegate": False,
        "reason": "exact reserved Apps server path cannot satisfy approved delegate server binding",
        "apps_lifecycle_modified": False,
        "schema_hash": schema_hash,
        "synthetic_payload_valid": True,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "production_classification": "UNKNOWN",
        "execution_ready": False,
        "real_codex_executions": 0,
        "provider_sends": 0,
    }
    output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n")
    print("Pinned anchors, patch application, Apps exclusion, sync lifecycle and wire schema: PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--disposable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    audit(args.source, args.disposable, args.output)
