// Actual patched router construction and PreparedMcpCall lifecycle; no model request.
#[tokio::test]
async fn devhub_production_admission_path() -> anyhow::Result<()> {
    use codex_extension_api::{AllowedTools, ExtensionData};
    use codex_mcp::{McpRuntime, McpRuntimeContext, McpRuntimeInput, McpStartupPolicy};
    use codex_protocol::mcp::ClientMcpExtensions;
    use std::collections::HashMap;
    use tokio_util::sync::CancellationToken;

    let schema: serde_json::Value = serde_json::from_str(include_str!("devhub_real_schema.json"))?;
    let payload: serde_json::Value =
        serde_json::from_str(include_str!("devhub_synthetic_payload.json"))?;
    let schema_hash = "0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be";
    let mut arms = vec![];
    let mut receipts = vec![];
    for arm_b in [false, true] {
        let (mut session, mut turn) = make_session_and_context().await;
        use_chatgpt_auth(&mut turn);
        update_turn_settings_for_test(&mut turn, |s| {
            Arc::make_mut(&mut s.model_info).tool_mode = Some(ToolMode::CodeModeOnly)
        });
        update_config(&mut turn, |c| {
            c.code_mode.direct_only_tool_namespaces = vec!["mcp__devhub_delegate".into()];
            c.tool_registry.error_on_tool_collisions = true;
        });
        session.allowed_tools = Some(Arc::new(AllowedTools(if arm_b {
            vec![ToolName::namespaced(
                "mcp__devhub_delegate",
                "devhub_delegate",
            )]
        } else {
            vec![]
        })));
        let temp = tempfile::tempdir()?;
        let receipt = temp.path().join("receipt.jsonl");
        let runtime = McpRuntime::empty(true);
        let empty = Arc::new(codex_mcp::McpBinding::empty(mcp_config_for_test(
            &turn.config,
        )));
        if !arm_b {
            // No opt-in policy: run the ordinary upstream construction path.
            let ordinary = crate::tools::spec_plan::build_tool_router(
                &session,
                &turn,
                turn.model_info(),
                None,
                &turn.environments,
                &empty,
                false,
                &ExtensionData::new("devhub-proof"),
                None,
            )?;
            assert!(
                ToolPlanProbe::from_router(ordinary)
                    .visible_specs
                    .is_empty()
            );
            session
                .services
                .thread_extension_data
                .insert(crate::ApprovedDelegatePolicy::no_tools());
            let router = crate::tools::spec_plan::build_tool_router(
                &session,
                &turn,
                turn.model_info(),
                None,
                &turn.environments,
                &empty,
                false,
                &ExtensionData::new("devhub-proof"),
                None,
            )?;
            let probe = ToolPlanProbe::from_router(router);
            assert_eq!(probe.tool_mode, ToolMode::CodeModeOnly);
            assert!(probe.visible_specs.is_empty());
            assert!(probe.registered_names.is_empty());
            assert!(probe.code_mode_tool_names.is_empty());
            arms.push(json!({"arm":"A","visible":probe.visible_specs,"registered":probe.registered_names,"nested":probe.code_mode_tool_names,"mode":probe.tool_mode}));
            continue;
        }
        let script = std::env::var("DEVHUB_SYNTHETIC_MCP")?;
        let schema_path = std::env::var("DEVHUB_REAL_SCHEMA")?;
        let server: codex_config::McpServerConfig = serde_json::from_value(json!({
            "command":"python3", "args":[script, schema_path, receipt.to_str().unwrap(), "approved-endpoint"],
            "required":true
        }))?;
        update_config(&mut turn, |c| {
            c.mcp_servers = codex_config::Constrained::allow_any(HashMap::from([(
                "devhub_delegate".to_string(),
                server.clone(),
            )]))
        });
        let config = mcp_config_for_test(&turn.config);
        let input = || McpRuntimeInput {
            startup_policy: McpStartupPolicy::Eager,
            config: Arc::clone(&config),
            plugins_available: false,
            ready_selected_capability_roots: vec![],
            mcp_servers: codex_mcp::effective_mcp_servers(&config, None),
            submit_id: String::new(),
            tx_event: None,
            startup_cancellation_token: CancellationToken::new(),
            runtime_context: McpRuntimeContext::new(
                Arc::new(codex_exec_server::EnvironmentManager::default_for_tests()),
                temp.path().to_path_buf(),
            ),
            codex_apps_tools_cache: Default::default(),
            tool_catalog_cache: Default::default(),
            codex_apps_tools_cache_key: codex_mcp::codex_apps_tools_cache_key(None),
            client_mcp_extensions: ClientMcpExtensions::default(),
            auth: None,
            auth_manager: None,
            elicitation_reviewer: None,
            elicitation_lifecycle: None,
        };
        runtime.replace(input()).await;
        let binding = runtime
            .current_binding_for_call("devhub_delegate")
            .await
            .expect("synthetic startup");
        session
            .services
            .thread_extension_data
            .insert(crate::ApprovedDelegatePolicy::delegate(
                server.clone(),
                schema.clone(),
            ));
        let router = crate::tools::spec_plan::build_tool_router(
            &session,
            &turn,
            turn.model_info(),
            None,
            &turn.environments,
            &binding,
            false,
            &ExtensionData::new("devhub-proof"),
            None,
        )?;
        let probe = ToolPlanProbe::from_router(router);
        assert_eq!(probe.tool_mode, ToolMode::CodeModeOnly);
        assert!(probe.code_mode_tool_names.is_empty());
        assert_eq!(probe.visible_specs.len(), 1);
        assert_eq!(probe.registered_names.len(), 1);
        let approve = |b: &Arc<codex_mcp::McpBinding>| {
            b.approve_call(
                "devhub_delegate",
                "devhub_delegate",
                "mcp__devhub_delegate",
                "devhub_delegate",
                &server,
                &schema,
            )
        };
        let call = approve(&binding)?.prepared_call();
        assert_eq!(call.server_name(), "devhub_delegate");
        assert_eq!(call.tool_info().tool.name.as_ref(), "devhub_delegate");
        assert_eq!(
            serde_json::to_value(&call.tool_info().tool.input_schema)?,
            schema
        );
        assert!(
            binding
                .approve_call(
                    "devhub_delegate",
                    "devhub_delegate",
                    "mcp__devhub_delegate",
                    "devhub_delegate",
                    &server,
                    &json!({"type":"object"})
                )
                .is_err()
        );
        // Exact server key remains authority: canonical strings do not admit Apps.
        assert!(
            binding
                .approve_call(
                    "codex_apps",
                    "devhub_delegate",
                    "mcp__devhub_delegate",
                    "devhub_delegate",
                    &server,
                    &schema
                )
                .is_err()
        );
        call.call(Some(payload.clone()), None, None).await?;
        runtime.reconnect_on_next_refresh();
        // The sync request marker does not replace an executable binding.
        call.call(Some(payload.clone()), None, None).await?;

        // Hold the actual generation+catalog leases during preparation. Poll the
        // real publisher once: it must be pending at invalidation, not a sleep.
        let (release, ready) = tokio::sync::oneshot::channel::<()>();
        let entered = std::sync::atomic::AtomicBool::new(false);
        let active = call.call_with_preparation(None, || async {
            entered.store(true, std::sync::atomic::Ordering::SeqCst);
            ready.await?;
            Ok((Some(payload.clone()), None))
        });
        tokio::pin!(active);
        assert!(futures::poll!(active.as_mut()).is_pending());
        assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
        let publishing = runtime.replace(input());
        tokio::pin!(publishing);
        assert!(futures::poll!(publishing.as_mut()).is_pending());
        release.send(()).unwrap();
        active.await?;
        publishing.await;
        let frozen = std::fs::read(&receipt)?;
        let err = call
            .call(Some(payload.clone()), None, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("approved MCP generation invalidated")
        );
        assert_eq!(std::fs::read(&receipt)?, frozen);
        let next = runtime
            .current_binding_for_call("devhub_delegate")
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&binding, &next));
        // Existing host admission cannot follow a fresh binding by name.
        assert!(
            crate::tools::spec_plan::build_tool_router(
                &session,
                &turn,
                turn.model_info(),
                None,
                &turn.environments,
                &next,
                false,
                &ExtensionData::new("devhub-proof"),
                None
            )
            .is_err()
        );
        session
            .services
            .thread_extension_data
            .insert(crate::ApprovedDelegatePolicy::delegate(
                server.clone(),
                schema.clone(),
            ));
        crate::tools::spec_plan::build_tool_router(
            &session,
            &turn,
            turn.model_info(),
            None,
            &turn.environments,
            &next,
            false,
            &ExtensionData::new("devhub-proof"),
            None,
        )?;
        let fresh_call = approve(&next)?.prepared_call();

        let (release, ready) = tokio::sync::oneshot::channel::<()>();
        let entered = std::sync::atomic::AtomicBool::new(false);
        let active = fresh_call.call_with_preparation(None, || async {
            entered.store(true, std::sync::atomic::Ordering::SeqCst);
            ready.await?;
            Ok((Some(payload.clone()), None))
        });
        tokio::pin!(active);
        assert!(futures::poll!(active.as_mut()).is_pending());
        assert!(entered.load(std::sync::atomic::Ordering::SeqCst));
        let shutdown = runtime.shutdown();
        tokio::pin!(shutdown);
        assert!(futures::poll!(shutdown.as_mut()).is_pending());
        release.send(()).unwrap();
        active.await?;
        shutdown.await;
        let frozen = std::fs::read(&receipt)?;
        let err = fresh_call
            .call(Some(payload.clone()), None, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("approved MCP generation invalidated")
        );
        assert_eq!(std::fs::read(&receipt)?, frozen);
        // No permanent closed state. Republish can create fresh authority only.
        runtime.reconnect_on_next_refresh();
        runtime.replace(input()).await;
        let newest = runtime
            .current_binding_for_call("devhub_delegate")
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&next, &newest));
        assert!(call.call(Some(payload.clone()), None, None).await.is_err());
        assert!(
            fresh_call
                .call(Some(payload.clone()), None, None)
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(&receipt)?, frozen);
        approve(&newest)?
            .prepared_call()
            .call(Some(payload.clone()), None, None)
            .await?;
        let records: Vec<serde_json::Value> = std::fs::read_to_string(&receipt)?
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(records.len(), 5);
        for record in &records {
            assert_eq!(record["endpoint_identity"], "approved-endpoint");
            assert_eq!(record["raw_tool"], "devhub_delegate");
            assert_eq!(record["schema_hash"], schema_hash);
            assert_eq!(record["arguments"], payload);
        }
        receipts = records;
        runtime.shutdown().await;
        arms.push(json!({"arm":"B","visible":probe.visible_specs,"registered":probe.registered_names,"nested":probe.code_mode_tool_names,"mode":probe.tool_mode}));
    }
    println!(
        "DEVHUB_ROUTER_PROOF={}",
        json!({
            "classification":"UNKNOWN", "scope":"partial actual production construction and retained-call lifecycle",
            "arms":arms, "synthetic_receipts":receipts, "schema_hash":schema_hash,
            "tests":{"ordinary_no_policy_empty_ceiling":true,"sync_marker_preserves_call":true,
                "publication_waits_for_call":true,"publication_wins_old_call_denied":true,
                "fresh_binding_requires_fresh_host_admission":true,"shutdown_waits_for_call":true,
                "shutdown_wins_old_call_denied":true,"republish_does_not_revive_old_call":true,
                "expected_schema_mismatch":true,"absent_apps_server_rejected":true,
                "wrong_origin_only":null,"wrong_first":null,"approved_first":null,
                "forged_runtime":null,"catalog_refresh_after_preparation":null,
                "extra_mcp":null,"dynamic_hosted_adversarial":null,"handler_dispatch":null},
            "dispatch_binding":{"server":"devhub_delegate","raw_tool":"devhub_delegate",
                "generation_identity":"scenario-local G0/G1/G2, behavior checked; no runtime ID exported",
                "prepared_call_path":true,"handler_path":false,"endpoint_identity":"approved-endpoint"},
            "process_proof":null,"production_modified":true,"shipping_runtime_modified":false,
            "execution_ready":false,"real_codex_executions":0,"provider_sends":0
        })
    );
    Ok(())
}
