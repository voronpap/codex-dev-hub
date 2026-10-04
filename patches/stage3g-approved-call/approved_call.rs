//! Opt-in authority for one host-admitted MCP call.
//!
//! The runtime owns invalidation. Callers cannot construct the generation token.
use std::sync::Arc;
use tokio::sync::{OwnedRwLockReadGuard, RwLock};

#[derive(Default)]
pub(crate) struct AdmissionGeneration {
    // Per published MCP runtime, never a global execution lock.
    active: Arc<RwLock<bool>>,
}

impl AdmissionGeneration {
    pub(crate) fn new() -> Self {
        Self {
            active: Arc::new(RwLock::new(true)),
        }
    }

    pub(crate) async fn invalidate(&self) {
        // Existing admitted calls finish first. The writer excludes new calls;
        // after this returns no old approval may start irreversible preparation.
        *self.active.write().await = false;
    }

    pub(crate) async fn lease(&self) -> anyhow::Result<OwnedRwLockReadGuard<bool>> {
        let lease = Arc::clone(&self.active).read_owned().await;
        anyhow::ensure!(*lease, "approved MCP generation invalidated");
        Ok(lease)
    }
}

/// Opaque authority minted from a frozen runtime binding after host verification.
/// It exposes no constructor and never resolves a server name at dispatch.
#[derive(Clone)]
pub struct ApprovedMcpCall {
    pub(crate) call: crate::PreparedMcpCall,
}

impl ApprovedMcpCall {
    pub fn tool_info(&self) -> &crate::ToolInfo {
        self.call.tool_info()
    }

    /// The cloned prepared call retains the admission generation and its exact
    /// client/catalog. Execution takes a lease before irreversible preparation.
    pub fn prepared_call(&self) -> crate::PreparedMcpCall {
        self.call.clone()
    }
}
