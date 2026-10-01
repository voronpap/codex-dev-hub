"""Pinned source audit and isolated Rust method-slice proof; no Codex process."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from check_mutation_audit import verify_sources

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "docs/evidence/stage3g-allowed-tools"


def block(source, marker):
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end]


def rust_source(bindings):
    """Production method bodies verbatim; synthetic storage/runtime/logging scaffolding.

    BTreeMap replaces IndexMap: proves membership, not insertion order or full router.
    ToolName serde derives omitted; naming/matching methods unchanged.
    """
    snippets = {key: value["excerpt"] for key, value in bindings.items()}
    code = r"""
#![allow(dead_code)]
use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::Arc;
use std::fmt;
extern crate self as tracing;
#[macro_export] macro_rules! warn { ($($t:tt)*) => {}; }
fn error_or_panic(message: String) { panic!("{}", message); }
const DEFAULT_FUNCTION_NAMESPACE: &str = "functions";
const LEGACY_MCP_TOOL_NAME_PREFIX: &str = "mcp__";
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ToolName { pub name: String, pub namespace: Option<String> }
"""
    code += block(snippets["tool_name"], "impl ToolName")
    code += block(snippets["tool_name"], "impl fmt::Display for ToolName")
    code += "\n#[derive(Clone, Debug, Default)] pub struct AllowedTools(pub Vec<ToolName>);\n"
    code += block(snippets["allowed"], "impl AllowedTools")
    code += block(snippets["mcp_prefix"], "fn callable_namespace_with_prefix")
    code += block(snippets["code_mode_name"], "pub fn code_mode_name_for_tool_name")
    code += r"""
#[derive(Clone, Copy)] enum ToolExposure { Direct }
trait CoreToolRuntime { fn tool_name(&self) -> ToolName;
 fn exposure(&self) -> ToolExposure { ToolExposure::Direct } }
struct Synthetic(ToolName);
impl CoreToolRuntime for Synthetic { fn tool_name(&self) -> ToolName { self.0.clone() } }
struct RegisteredTool { runtime: Arc<dyn CoreToolRuntime>, exposure: ToolExposure }
#[derive(Default)] struct ToolMap(BTreeMap<ToolName, RegisteredTool>);
impl ToolMap {
 fn entry(&mut self, n: ToolName) -> Entry<'_, ToolName, RegisteredTool> { self.0.entry(n) }
 fn contains_key(&self, n: &ToolName) -> bool { self.0.contains_key(n) }
 fn shift_insert(&mut self, _: usize, n: ToolName, v: RegisteredTool) { self.0.insert(n,v); }
}
#[derive(Default)] struct ToolRegistry {
 tools: ToolMap, first_collision: Option<ToolName>, allowed_tools: Option<Arc<AllowedTools>>
}
impl ToolRegistry {
 fn record_collision(&mut self, n: ToolName) { self.first_collision.get_or_insert(n); }
"""
    for name in (
        "with_allowed_tools",
        "register_trusted_with_exposure",
        "prepend_trusted",
        "register_external_with_exposure",
    ):
        code += block(snippets["registry"], f"pub(crate) fn {name}")
    code += "}\n"
    code += (ROOT / "scripts/allowed_tools_synthetic.rs").read_text()
    return code


def validate(bindings, review):
    assert review["classification"] == "UNKNOWN"
    assert review["effects_based_policy"] == "NOT_ACCEPTED"
    assert review["v3_created"] is False and review["launcher_changed"] is False
    assert review["execution_ready"] is False
    assert review["real_codex_executions"] == review["provider_sends"] == 0
    assert review["canonical_b"] == {"namespace": "mcp__devhub_delegate", "name": "devhub_delegate"}
    assert review["full_core_registry_proof"] is None
    assert "allowed.namespace == tool.namespace" in bindings["allowed"]["excerpt"]
    assert "hosted_specs.retain" in bindings["hosted_filter"]["excerpt"]
    assert "thread_extension_init" not in bindings["in_process_args"]["excerpt"]
    assert "AllowedTools" not in bindings["server_start"]["excerpt"]
    assert "CodeModeOnly" in bindings["code_mode_visibility"]["excerpt"]
    rust_source(bindings)  # Missing/truncated source blocks fail before compilation.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-upstream", action="store_true")
    parser.add_argument("--compile-proof", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    bindings = json.loads((EVIDENCE / "source-bindings.json").read_bytes())
    review = json.loads((EVIDENCE / "review.json").read_bytes())
    validate(bindings, review)
    verified = verify_sources(bindings) if args.verify_upstream else 0
    if args.compile_proof:
        with tempfile.TemporaryDirectory(prefix="allowed-tools-synthetic-") as directory:
            root = Path(directory)
            code = rust_source(bindings).encode()
            (root / "probe.rs").write_bytes(code)
            binary = root / "probe"
            subprocess.run(
                ["rustc", "--edition=2021", "--test", str(root / "probe.rs"), "-o", str(binary)],
                check=True,
                timeout=60,
            )
            result = subprocess.run([str(binary)], capture_output=True, check=True, timeout=30)
            receipt = {
                "kind": "exact_source_method_slice_with_synthetic_scaffolding",
                "source_files_verified": verified,
                "generated_rust_sha256": hashlib.sha256(code).hexdigest(),
                "compiler": subprocess.check_output(["rustc", "--version"]).decode().strip(),
                "stdout": result.stdout.decode(),
                "full_core_registry_proof": None,
                "A_membership": [],
                "B_membership": [review["canonical_b"]],
                "model_visible_B_verified": None,
                "host_wrapper_compiled": False,
                "real_codex_executions": 0,
                "provider_sends": 0,
            }
            if args.output:
                with args.output.open("x", encoding="utf-8") as stream:
                    json.dump(receipt, stream, indent=2)
                    stream.write("\n")
            print(json.dumps(receipt))


if __name__ == "__main__":
    main()
