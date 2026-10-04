// Calls the patched production router construction, not a separate registry composition.
#[tokio::test]
async fn devhub_production_admission_path() -> anyhow::Result<()> {
    use codex_extension_api::{AllowedTools, ExtensionData};
    use codex_mcp::{McpRuntime, McpRuntimeInput, McpRuntimeContext, McpStartupPolicy};
    use codex_protocol::mcp::ClientMcpExtensions;
    use tokio_util::sync::CancellationToken;
    use std::collections::HashMap;
    let schema: serde_json::Value = serde_json::from_str(include_str!("devhub_real_schema.json"))?;
    let mut arms = vec![];
    for arm_b in [false, true] {
        let (mut session, mut turn) = make_session_and_context().await;
        use_chatgpt_auth(&mut turn);
        update_turn_settings_for_test(&mut turn, |s| Arc::make_mut(&mut s.model_info).tool_mode = Some(ToolMode::CodeModeOnly));
        update_config(&mut turn, |c| {
            c.code_mode.direct_only_tool_namespaces = vec!["mcp__devhub_delegate".into()];
            c.tool_registry.error_on_tool_collisions = true;
        });
        session.allowed_tools = Some(Arc::new(AllowedTools(if arm_b {
            vec![ToolName::namespaced("mcp__devhub_delegate", "devhub_delegate")]
        } else { vec![] })));
        let temp = tempfile::tempdir()?;
        let receipt = temp.path().join("receipt.json");
        let runtime = McpRuntime::empty(true);
        let binding;
        let mut approved_server = None;
        if arm_b {
            let script = std::env::var("DEVHUB_SYNTHETIC_MCP")?;
            let schema_path = std::env::var("DEVHUB_REAL_SCHEMA")?;
            let server: codex_config::McpServerConfig = serde_json::from_value(json!({
                "command":"python3", "args":[script, schema_path, receipt.to_str().unwrap(), "approved-endpoint"],
                "required":true
            }))?;
            update_config(&mut turn, |c| c.mcp_servers = codex_config::Constrained::allow_any(
                HashMap::from([("devhub_delegate".to_string(), server.clone())])));
            let config = mcp_config_for_test(&turn.config);
            runtime.replace(McpRuntimeInput {
                startup_policy:McpStartupPolicy::Eager,
                config:Arc::clone(&config), plugins_available:false, ready_selected_capability_roots:vec![],
                mcp_servers:codex_mcp::effective_mcp_servers(&config, None), submit_id:String::new(), tx_event:None,
                startup_cancellation_token:CancellationToken::new(),
                runtime_context:McpRuntimeContext::new(Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()), temp.path().to_path_buf()),
                codex_apps_tools_cache:Default::default(), tool_catalog_cache:Default::default(),
                codex_apps_tools_cache_key:codex_mcp::codex_apps_tools_cache_key(None),
                client_mcp_extensions:ClientMcpExtensions::default(),auth:None,auth_manager:None,
                elicitation_reviewer:None,elicitation_lifecycle:None,
            }).await;
            binding = runtime.current_binding_for_call("devhub_delegate").await.expect("synthetic server startup");
            session.services.thread_extension_data.insert(crate::ApprovedDelegatePolicy::delegate(server.clone(),schema.clone()));
            approved_server = Some(server);
        } else {
            binding = Arc::new(codex_mcp::McpBinding::empty(mcp_config_for_test(&turn.config)));
            session.services.thread_extension_data.insert(crate::ApprovedDelegatePolicy::no_tools());
        }
        let router = crate::tools::spec_plan::build_tool_router(&session,&turn,turn.model_info(),None,
            &turn.environments,&binding,false,&ExtensionData::default(),None)?;
        let probe = ToolPlanProbe::from_router(router);
        assert_eq!(probe.tool_mode,ToolMode::CodeModeOnly);
        assert!(probe.code_mode_tool_names.is_empty());
        assert_eq!(probe.visible_specs.len(),usize::from(arm_b));
        if let Some(server) = approved_server {
            let approved = binding.approve_call("devhub_delegate","devhub_delegate","mcp__devhub_delegate",
                "devhub_delegate",&server,&schema)?;
            let call = approved.prepared_call();
            assert_eq!(call.server_name(),"devhub_delegate");
            assert_eq!(call.tool_info().tool.name.as_ref(),"devhub_delegate");
            let wrong_schema = json!({"type":"object"});
            assert!(binding.approve_call("devhub_delegate","devhub_delegate","mcp__devhub_delegate",
                "devhub_delegate",&server,&wrong_schema).is_err());
            call.call(Some(json!({})),None,None).await?;
            let observed:serde_json::Value=serde_json::from_slice(&std::fs::read(&receipt)?)?;
            assert_eq!(observed,json!({"endpoint_identity":"approved-endpoint","raw_tool":"devhub_delegate"}));
            let frozen_receipt = std::fs::read(&receipt)?;
            runtime.reconnect_on_next_refresh().await;
            assert!(call.call(Some(json!({})),None,None).await.is_err());
            assert_eq!(std::fs::read(&receipt)?,frozen_receipt);
        }
        arms.push(json!({"arm":if arm_b {"B"} else {"A"},"visible":probe.visible_specs,
            "registered":probe.registered_names,"nested":probe.code_mode_tool_names,"mode":probe.tool_mode}));
        runtime.shutdown().await;
    }
    println!("DEVHUB_ROUTER_PROOF={}",json!({"classification":"UNKNOWN","scope":"partial production admission path",
        "arms":arms,"production_modified":true,"shipping_runtime_modified":false,
        "execution_ready":false,"real_codex_executions":0,"provider_sends":0}));
    Ok(())
}
