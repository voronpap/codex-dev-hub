"""Pinned source-derived approval chain; not a runtime timeout diagnosis."""

import argparse
import hashlib
import json
from pathlib import Path

import jsonschema


def audit(source: Path, output: Path) -> None:
    manifest = json.loads((source / "source-manifest.json").read_bytes())
    names = [
        "codex-rs/config/src/mcp_types.rs",
        "codex-rs/codex-mcp/src/server.rs",
        "codex-rs/codex-mcp/src/binding.rs",
        "codex-rs/core/src/mcp_tool_call.rs",
        "codex-rs/core/config.schema.json",
    ]
    texts = {}
    hashes = {}
    for name in names:
        raw = (source / name).read_bytes()
        hashes[name] = hashlib.sha256(raw).hexdigest()
        assert hashes[name] == manifest["files"][name]
        texts[name] = raw.decode()
    enum = texts[names[0]]
    assert "#[default]\n    Auto," in enum
    assert '#[serde(rename_all = "snake_case")]\npub enum AppToolApproval' in enum
    metadata = texts[names[1]]
    assert ".or(self.default_tools_approval_mode)\n            .unwrap_or_default()" in metadata
    binding = texts[names[2]]
    assert ".tool_approval_mode(&self.tool_info.tool.name)" in binding
    handler = texts[names[3]]
    assert "AppToolApproval::Auto => requires_mcp_tool_approval(annotations)" in handler
    assert "AppToolApproval::Approve => false" in handler
    assert "destructive_hint.unwrap_or(true)" in handler
    assert (
        ".and_then(|annotations| annotations.open_world_hint)\n            .unwrap_or(true)"
        in handler
    )
    assert (
        "if !strict_auto_review && !requires_mcp_tool_approval_for_mode(annotations, policy.mode)"
        in handler
    )
    original = {
        "command": "python3",
        "args": [
            "synthetic_approved_mcp.py",
            "schema.json",
            "receipt.jsonl",
            "approved-adversarial-endpoint",
        ],
        "required": True,
    }
    corrected = dict(
        original,
        enabled_tools=["devhub_delegate"],
        tools={"devhub_delegate": {"approval_mode": "approve"}},
    )
    schema = json.loads(texts[names[4]])
    for server in [original, corrected]:
        jsonschema.validate({"mcp_servers": {"devhub_delegate": server}}, schema)
    repo = Path(__file__).resolve().parents[1]
    synthetic = (repo / "scripts/synthetic_approved_mcp.py").read_text()
    assert '"tools": [{"name": "devhub_delegate", "inputSchema": schema}]' in synthetic
    assert '"annotations"' not in synthetic
    patch_hash = hashlib.sha256(
        (repo / "patches/stage3g-approved-call/candidate.patch").read_bytes()
    ).hexdigest()
    assert patch_hash == "d2e27068ca8020f014c7cd3bea2cc73181b1b892d8e6869814680d2076eb3e36"
    result = dict(
        scope="source-derived only; compiled observations pending",
        pinned_source=manifest["commit"],
        source_hashes=hashes,
        original_mode="Auto",
        original_annotations=None,
        original_required_by_mode=True,
        corrected_mode="Approve",
        corrected_required_by_mode=False,
        corrected_policy={"enabled_tools": ["devhub_delegate"], "tools": corrected["tools"]},
        pinned_config_schema_validation=True,
        patch_hash=patch_hash,
        build006_root_cause_runtime_proven=False,
        execution_ready=False,
        real_codex_executions=0,
        provider_sends=0,
    )
    with output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(
        "Pinned approval chain, synthetic config schema, absent annotations, unchanged patch: PASS"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    audit(args.source, args.output)
