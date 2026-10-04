"""Assemble the opt-in admission patch in a disposable pinned source tree."""

# ruff: noqa: E501
# Rust source strings preserve upstream anchors and are formatted in the proof tree.

import argparse
import difflib
import hashlib
import json
import subprocess
from pathlib import Path

PIN = "4607249e430dac1c961df4dc615beae88e33cec8"
ROOT = Path(__file__).resolve().parents[1]


def build(source: Path, output: Path, rustfmt: str | None = None) -> None:
    changes: dict[str, tuple[str, str]] = {}

    def edit(name: str, old: str, new: str, count: int = 1) -> None:
        before, text = changes.get(name, (None, None))
        if before is None:
            before = text = (source / name).read_text(encoding="utf-8")
        assert text is not None and text.count(old) == count, (name, old)
        changes[name] = (before, text.replace(old, new))

    module = "codex-rs/codex-mcp/src/approved_call.rs"
    changes[module] = (
        "",
        (ROOT / "patches/stage3g-approved-call/approved_call.rs").read_text(encoding="utf-8-sig"),
    )
    edit(
        "codex-rs/codex-mcp/src/lib.rs",
        "mod binding;",
        "mod approved_call;\npub use approved_call::ApprovedMcpCall;\nmod binding;",
    )
    binding = "codex-rs/codex-mcp/src/binding.rs"
    edit(
        binding,
        "pub struct McpBinding {",
        "pub struct McpBinding {\n    pub(crate) admission_generation: Option<Arc<crate::approved_call::AdmissionGeneration>>,",
    )
    edit(
        binding,
        "            connections,\n            clients,",
        "            admission_generation: None,\n            connections,\n            clients,",
    )
    edit(
        binding,
        "pub struct PreparedMcpCall {",
        "pub struct PreparedMcpCall {\n    admission_generation: Option<Arc<crate::approved_call::AdmissionGeneration>>,",
    )
    edit(
        binding,
        "        Some(Self {\n            connections,",
        "        Some(Self {\n            admission_generation: None,\n            connections,",
    )
    edit(
        binding,
        "        let effective_timeout = match",
        "        // Opt-in only: retain authority through preparation and send.\n        let _admission_lease = match &self.admission_generation {\n            Some(generation) => Some(generation.lease().await?),\n            None => None,\n        };\n        let effective_timeout = match",
    )
    method = """    /// Host-only admission from the exact frozen binding. Metadata alone cannot
    /// manufacture an executable client. Expected values come from reviewed host
    /// startup data, never model arguments or an MCP response.
    pub fn approve_call(
        &self,
        server: &str,
        raw_name: &str,
        canonical_namespace: &str,
        canonical_name: &str,
        expected_server: &codex_config::McpServerConfig,
        expected_schema: &serde_json::Value,
    ) -> anyhow::Result<crate::ApprovedMcpCall> {
        anyhow::ensure!(self.tools.len() == 1, "approved binding must contain exactly one tool");
        let generation = self.admission_generation.as_ref()
            .ok_or_else(|| anyhow::anyhow!("binding has no runtime generation"))?;
        let registration = self.config.mcp_server_catalog.server(server)
            .ok_or_else(|| anyhow::anyhow!("reviewed server missing"))?;
        anyhow::ensure!(matches!(registration.source(), crate::McpServerSource::Config)
            && registration.config() == expected_server, "reviewed server binding mismatch");
        let mut call = self.prepare_call(server, raw_name)
            .ok_or_else(|| anyhow::anyhow!("reviewed call missing"))?;
        let info = call.tool_info();
        anyhow::ensure!(info.server_name == server && info.tool.name.as_ref() == raw_name
            && info.callable_namespace == canonical_namespace
            && info.callable_name == canonical_name
            && serde_json::to_value(&info.tool.input_schema)? == *expected_schema,
            "approved identity/schema mismatch");
        anyhow::ensure!(self.tools[0] == *info, "catalog/dispatch identity mismatch");
        call.admission_generation = Some(Arc::clone(generation));
        Ok(crate::ApprovedMcpCall { call })
    }

"""
    edit(
        binding,
        "    pub fn has_servers(&self) -> bool {",
        method + "    pub fn has_servers(&self) -> bool {",
    )
    runtime = "codex-rs/codex-mcp/src/runtime.rs"
    edit(
        runtime,
        "pub struct McpRuntime {",
        "pub struct McpRuntime {\n    admission_publication: tokio::sync::Mutex<()>,",
    )
    edit(
        runtime,
        "            current: ArcSwap::from_pointee(PublishedMcpRuntime {",
        "            admission_publication: tokio::sync::Mutex::new(()),\n            current: ArcSwap::from_pointee(PublishedMcpRuntime {",
    )
    edit(
        runtime,
        "    async fn publish(&self, input: McpRuntimeInput, previous: Option<&McpConnectionSet>) {",
        "    async fn publish(&self, input: McpRuntimeInput, previous: Option<&McpConnectionSet>) {\n        let _publication = self.admission_publication.lock().await;",
    )

    edit(
        runtime,
        "struct PublishedMcpRuntime {",
        "struct PublishedMcpRuntime {\n    admission_generation: Arc<crate::approved_call::AdmissionGeneration>,",
    )
    edit(
        runtime,
        "cached_binding: Mutex::new(None),",
        "cached_binding: Mutex::new(None),\n                admission_generation: Arc::new(crate::approved_call::AdmissionGeneration::new()),",
        count=(source / runtime).read_text().count("cached_binding: Mutex::new(None),"),
    )
    edit(
        runtime,
        "        let (publish, publication_gate) = McpPublicationGate::pending();",
        "        // Publication, not the synchronous reconnect marker, replaces authority.\n        let current = self.current.load_full();\n        current.admission_generation.invalidate().await;\n        let (publish, publication_gate) = McpPublicationGate::pending();",
    )
    edit(
        runtime,
        "        let binding = Arc::new(\n            current",
        "        let mut captured = current",
    )
    edit(
        runtime,
        "                .await,\n        );\n        if let Some(catalog_revisions) = stable_catalog_revisions",
        "                .await;\n        captured.admission_generation = Some(Arc::clone(&current.admission_generation));\n        let binding = Arc::new(captured);\n        if let Some(catalog_revisions) = stable_catalog_revisions",
    )
    edit(
        runtime,
        "    pub async fn shutdown(&self) {\n        self.latest_connections().shutdown().await;",
        "    pub async fn shutdown(&self) {\n        let _publication = self.admission_publication.lock().await;\n        let current = self.current.load_full();\n        current.admission_generation.invalidate().await;\n        current.connections.shutdown().await;",
    )
    handler = "codex-rs/core/src/tools/handlers/mcp.rs"
    edit(
        handler,
        "pub struct McpHandler {",
        "pub struct McpHandler {\n    approved_call: Option<codex_mcp::ApprovedMcpCall>,",
    )
    edit(
        handler,
        "impl McpHandler {",
        "impl McpHandler {\n    pub fn new_approved(call: codex_mcp::ApprovedMcpCall) -> Result<Self, serde_json::Error> {\n        let mut handler = Self::new(call.tool_info().clone())?;\n        handler.approved_call = Some(call);\n        Ok(handler)\n    }",
        count=2,
    )
    # The constructor belongs only in the first implementation block.
    before, text = changes[handler]
    constructor = "    pub fn new_approved(call: codex_mcp::ApprovedMcpCall) -> Result<Self, serde_json::Error> {\n        let mut handler = Self::new(call.tool_info().clone())?;\n        handler.approved_call = Some(call);\n        Ok(handler)\n    }"
    second = text.rfind(constructor)
    text = text[:second] + text[second:].replace(constructor, "", 1)
    changes[handler] = (before, text)
    edit(
        handler,
        "        Ok(Self {\n            tool_info,",
        "        Ok(Self {\n            approved_call: None,\n            tool_info,",
    )
    edit(
        handler,
        "        let prepared_mcp_call = invocation",
        "        let prepared_mcp_call = if let Some(approved) = &self.approved_call {\n            Some(approved.prepared_call())\n        } else { invocation",
    )
    edit(
        handler,
        "            .await;\n        // Use the executed call's binding",
        "            .await };\n        // Use the executed call's binding",
    )
    policy = "codex-rs/core/src/approved_delegate.rs"
    changes[policy] = (
        "",
        (ROOT / "patches/stage3g-approved-call/approved_delegate.rs").read_text(
            encoding="utf-8-sig"
        ),
    )
    edit(
        "codex-rs/core/src/lib.rs",
        "pub use codex_thread::CodexThread;",
        "mod approved_delegate;\npub use approved_delegate::ApprovedDelegatePolicy;\npub use codex_thread::CodexThread;",
    )
    edit(
        "codex-rs/core/src/tools/spec_plan.rs",
        "    let mut registry = ToolRegistry::with_allowed_tools(session.allowed_tools.clone());\n    add_core_tool_sources(&context, &mut registry);",
        """    let mut registry = ToolRegistry::with_allowed_tools(session.allowed_tools.clone());
    if let Some(policy) = session.services.thread_extension_data.get::<crate::ApprovedDelegatePolicy>() {
        if model_info.tool_mode != Some(ToolMode::CodeModeOnly)
            || !turn_context.config.tool_registry.error_on_tool_collisions
            || turn_context.config.code_mode.direct_only_tool_namespaces != ["mcp__devhub_delegate"] {
            return Err(CodexErrorDetails::InvalidRequest("approved delegate config mismatch".into()).into());
        }
        policy.register(mcp, &mut registry).map_err(|e|
            CodexErrorDetails::InvalidRequest(e.to_string()))?;
        return finalize_tool_router(turn_context, model_info, registry, vec![],
            &session.services.tool_search_handler_cache);
    }
    add_core_tool_sources(&context, &mut registry);""",
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    patch = ""
    audit = {}
    for name, (before, after) in changes.items():
        if rustfmt:
            after = subprocess.run(
                [
                    rustfmt,
                    "--edition",
                    "2024",
                    "--config",
                    "skip_children=true",
                    "--emit",
                    "stdout",
                ],
                input=after,
                text=True,
                capture_output=True,
                check=True,
            ).stdout
        audit[name] = {
            "upstream_sha256": hashlib.sha256((source / name).read_bytes()).hexdigest()
            if before
            else None,
            "patched_sha256": hashlib.sha256(after.encode()).hexdigest(),
        }
        patch += "".join(
            difflib.unified_diff(
                before.splitlines(True),
                after.splitlines(True),
                fromfile="a/" + name if before else "/dev/null",
                tofile="b/" + name,
            )
        )
    output.write_text(patch, encoding="utf-8", newline="\n")
    output.with_suffix(".sources.json").write_text(
        json.dumps(
            {"pinned_source": PIN, "files": audit, "rustfmt_applied": bool(rustfmt)}, indent=2
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Generated {len(changes)}-file patch; no source tree modified")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rustfmt")
    args = parser.parse_args()
    build(args.source, args.output, args.rustfmt)
