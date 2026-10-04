// Appended only to disposable binding.rs: private access injects a catalog refresh,
// while admission and execution use the actual production methods.
#[cfg(test)]
#[tokio::test]
async fn devhub_production_admission_path_catalog() -> anyhow::Result<()> {
    use crate::{McpRuntime, McpRuntimeContext, McpRuntimeInput, McpStartupPolicy};
    use tokio_util::sync::CancellationToken;
    let temp = tempfile::tempdir()?;
    let receipt = std::path::PathBuf::from(std::env::var("DEVHUB_PROOF_RECEIPT")?);
    if let Some(parent) = receipt.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&receipt, b"")?;
    let schema: serde_json::Value = serde_json::from_str(include_str!("devhub_real_schema.json"))?;
    let payload: serde_json::Value =
        serde_json::from_str(include_str!("devhub_synthetic_payload.json"))?;
    let server: codex_config::McpServerConfig = serde_json::from_value(serde_json::json!({
        "command":"python3", "args":[std::env::var("DEVHUB_SYNTHETIC_MCP")?,std::env::var("DEVHUB_REAL_SCHEMA")?,receipt,"catalog-endpoint"],"required":true
    }))?;
    let mut config = crate::mcp::tests::test_mcp_config(temp.path().to_path_buf());
    let mut catalog = crate::ResolvedMcpCatalog::builder();
    catalog.register(crate::McpServerRegistration::from_config(
        "devhub_delegate".into(),
        server.clone(),
    ));
    config.mcp_server_catalog = catalog.build();
    let effective = crate::effective_mcp_servers(&config, None);
    config.set_server_permission_profiles(
        &effective,
        [("local".to_string(), config.permission_profile.clone())],
    );
    let runtime = McpRuntime::empty(true);
    runtime
        .replace(McpRuntimeInput {
            startup_policy: McpStartupPolicy::Eager,
            config: Arc::new(config),
            plugins_available: false,
            ready_selected_capability_roots: vec![],
            mcp_servers: effective,
            submit_id: String::new(),
            tx_event: None,
            startup_cancellation_token: CancellationToken::new(),
            runtime_context: McpRuntimeContext::new(
                Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
                temp.path().to_path_buf(),
            ),
            codex_apps_tools_cache: Default::default(),
            tool_catalog_cache: Default::default(),
            codex_apps_tools_cache_key: crate::codex_apps_tools_cache_key(None),
            client_mcp_extensions: codex_protocol::mcp::ClientMcpExtensions::default(),
            auth: None,
            auth_manager: None,
            elicitation_reviewer: None,
            elicitation_lifecycle: None,
        })
        .await;
    let binding = runtime
        .current_binding_for_call("devhub_delegate")
        .await
        .expect("ready synthetic binding");
    assert_eq!(binding.tools().len(), 1);
    let approved = binding.approve_call(
        "devhub_delegate",
        "devhub_delegate",
        "mcp__devhub_delegate",
        "devhub_delegate",
        &server,
        &schema,
    )?;
    let call = approved.prepared_call();
    call.call(Some(payload.clone()), None, None).await?;
    let before = std::fs::read(&receipt)?;
    assert_eq!(String::from_utf8(before.clone())?.lines().count(), 1);
    // Even identical tool bytes explicitly refreshed on the exact retained client
    // must invalidate the older prepared snapshot. No runtime generation swap.
    let tools = binding.tools().to_vec();
    call.client
        .tool_catalog
        .refresh(|| async { Ok((tools, ())) }, |_, ()| ())
        .await?;
    let error = call
        .call(Some(payload), None, None)
        .await
        .expect_err("stale prepared call denied");
    assert_eq!(std::fs::read(&receipt)?, before, "stale call must not send");
    runtime.shutdown().await;
    println!(
        "DEVHUB_CATALOG_PROOF={}",
        serde_json::json!({"catalog_refresh_after_preparation":true,"receipt_count":1,"stale_error":error.to_string(),"real_codex_executions":0,"provider_sends":0})
    );
    Ok(())
}
