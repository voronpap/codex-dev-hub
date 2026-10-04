//! Opt-in host startup policy. Not CLI TOML, MCP input, or model-controlled state.
use std::sync::{Arc, Mutex};
use codex_config::McpServerConfig;
use codex_mcp::McpBinding;
use crate::tools::handlers::McpHandler;
use crate::tools::registry::{ToolRegistry, ToolExposure};

pub struct ApprovedDelegatePolicy {
    server: Option<McpServerConfig>,
    schema: serde_json::Value,
    admitted: Mutex<Option<(Arc<McpBinding>, Arc<McpHandler>)>>,
}

impl ApprovedDelegatePolicy {
    pub fn no_tools() -> Self {
        Self { server: None, schema: serde_json::Value::Null, admitted: Mutex::new(None) }
    }

    /// The host must supply the reviewed launch configuration and real schema.
    /// This does not read these values from MCP metadata or user/model arguments.
    pub fn delegate(server: McpServerConfig, schema: serde_json::Value) -> Self {
        Self { server: Some(server), schema, admitted: Mutex::new(None) }
    }

    pub(crate) fn register(
        &self, binding: &Arc<McpBinding>, registry: &mut ToolRegistry,
    ) -> anyhow::Result<()> {
        let expected = if self.server.is_some() {
            vec![codex_tools::ToolName::namespaced("mcp__devhub_delegate", "devhub_delegate")]
        } else { vec![] };
        anyhow::ensure!(registry.allowed_tools.as_ref().is_some_and(|x| x.0 == expected),
            "approved delegate requires exact host startup AllowedTools");
        let Some(server) = &self.server else {
            anyhow::ensure!(!binding.has_servers() && binding.tools().is_empty(),
                "Arm A must not configure MCP");
            return Ok(());
        };
        // Repeat metadata verification even when a cached handler exists. Duplicate
        // entries and schema drift never get hidden by canonical-name caching.
        let call = binding.approve_call("devhub_delegate", "devhub_delegate",
            "mcp__devhub_delegate", "devhub_delegate", server, &self.schema)?;
        let mut admitted = self.admitted.lock().map_err(|_| anyhow::anyhow!("admission poisoned"))?;
        let handler = if let Some((prior, handler)) = admitted.as_ref() {
            anyhow::ensure!(Arc::ptr_eq(prior, binding), "new binding requires new host admission");
            Arc::clone(handler)
        } else {
            let handler = Arc::new(McpHandler::new_approved(call)?);
            *admitted = Some((Arc::clone(binding), Arc::clone(&handler)));
            handler
        };
        anyhow::ensure!(registry.entries().next().is_none(), "unexpected runtime before admission");
        anyhow::ensure!(registry.register_external_with_exposure(handler, ToolExposure::Direct),
            "approved delegate collision");
        Ok(())
    }
}
