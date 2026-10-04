// Actual patched router construction and PreparedMcpCall lifecycle; no model request.
#[tokio::test]
async fn devhub_production_admission_path() -> anyhow::Result<()> {
    use codex_extension_api::{AllowedTools, ExtensionData};
    use codex_mcp::{McpRuntime, McpRuntimeContext, McpRuntimeInput, McpStartupPolicy};
    use codex_protocol::mcp::ClientMcpExtensions;
    use std::collections::HashMap;
    use tokio_util::sync::CancellationToken;
    fn stage(name: &str) {
        println!("DEVHUB_STAGE={name}");
        std::io::Write::flush(&mut std::io::stdout()).expect("flush diagnostic stage");
    }
    fn diagnostic(binding: &codex_mcp::McpBinding) {
        let mut tools = binding
            .tools()
            .iter()
            .map(|tool| {
                json!({
                    "server_name":tool.server_name,"raw_tool":tool.tool.name,
                    "callable_namespace":tool.callable_namespace,"callable_name":tool.callable_name,
                    "server_origin":tool.server_origin,
                    "model_visible":codex_mcp::tool_is_model_visible(tool),
                    "ui_visibility":tool.tool.meta.as_deref().and_then(|meta| meta.get("ui"))
                        .and_then(|ui| ui.get("visibility"))
                })
            })
            .collect::<Vec<_>>();
        tools.sort_by_key(|tool| tool.to_string());
        println!(
            "DEVHUB_BINDING_DIAGNOSTIC={}",
            json!({
                "tools_len":binding.tools().len(),"tools":tools,
                "has_servers":binding.has_servers(),
                "target_tool_info_present":binding.tool_info("devhub_delegate","devhub_delegate").is_some(),
                "target_prepare_call_present":binding.prepare_call("devhub_delegate","devhub_delegate").is_some()
            })
        );
        std::io::Write::flush(&mut std::io::stdout()).expect("flush binding diagnostic");
    }

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
            stage("A_assertions_completed");
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
        let mut config = (*mcp_config_for_test(&turn.config)).clone();
        let effective_servers = codex_mcp::effective_mcp_servers(&config, None);
        let environment_profiles = turn
            .environments
            .turn_environments()
            .map(|environment| {
                (
                    environment.selection.environment_id.clone(),
                    environment.permission_profile_with_workspace_roots(),
                )
            })
            .collect::<Vec<_>>();
        let explicit_environment = environment_profiles
            .iter()
            .any(|(id, _)| id == &server.environment_id);
        let registration = config
            .mcp_server_catalog
            .server("devhub_delegate")
            .expect("configured server");
        let configured_origin = matches!(registration.source(), codex_mcp::McpServerSource::Config);
        let enabled = effective_servers
            .get("devhub_delegate")
            .expect("effective server")
            .enabled();
        let authority_source = if explicit_environment {
            "turn_environment_profile"
        } else if server.is_local_environment() {
            "runtime_permission_profile_local_branch"
        } else {
            "unresolved"
        };
        let before = config
            .permission_profile_for_server("devhub_delegate")
            .is_some();
        config.set_server_permission_profiles(&effective_servers, environment_profiles);
        let present = config
            .permission_profile_for_server("devhub_delegate")
            .is_some();
        println!(
            "DEVHUB_PERMISSION_DIAGNOSTIC={}",
            json!({
                "present_before_materialization":before,"present_before_replace":present,
                "enabled":enabled,"server_source":if configured_origin { "Config" } else { "unexpected" },
                "environment_id":server.environment_id,"is_local_environment":server.is_local_environment(),
                "authority_source":authority_source,"explicit_environment_match":explicit_environment
            })
        );
        stage("permission_materialized");
        assert!(enabled && configured_origin && server.is_local_environment());
        assert_eq!(
            server.environment_id,
            codex_config::DEFAULT_MCP_SERVER_ENVIRONMENT_ID
        );
        assert!(present);
        let config = Arc::new(config);
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
        let mut configured_keys = turn
            .config
            .mcp_servers
            .get()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        configured_keys.sort();
        let mut catalog_keys = codex_mcp::configured_mcp_servers(&config)
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        catalog_keys.sort();
        let effective = codex_mcp::effective_mcp_servers(&config, None);
        let mut effective_keys = effective.keys().cloned().collect::<Vec<_>>();
        effective_keys.sort();
        let mut plugin_keys = effective
            .iter()
            .filter(|(_, server)| server.is_agent_plugin())
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        plugin_keys.sort();
        println!(
            "DEVHUB_SERVER_DIAGNOSTIC={}",
            json!({
                "configured_keys":configured_keys,"materialized_catalog_keys":catalog_keys,"effective_keys":effective_keys,
                "apps_present":effective.contains_key("codex_apps"),"plugin_keys":plugin_keys,
                "other_keys":effective_keys.iter().filter(|name| name.as_str() != "devhub_delegate").collect::<Vec<_>>(),
                "expected_keys":["devhub_delegate"]
            })
        );
        stage("B_runtime_replace");
        runtime.replace(input()).await;
        let binding = runtime
            .current_binding_for_call("devhub_delegate")
            .await
            .expect("synthetic startup");
        stage("initial_binding_before_first_approve");
        diagnostic(&binding);
        stage("initial_router_admission");
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
        stage("B_visibility_completed");
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
        stage("initial_approve");
        let call = approve(&binding)?.prepared_call();
        assert_eq!(call.server_name(), "devhub_delegate");
        assert_eq!(call.tool_info().tool.name.as_ref(), "devhub_delegate");
        assert_eq!(
            serde_json::to_value(&call.tool_info().tool.input_schema)?,
            schema
        );
        stage("initial_approve_completed");
        stage("schema_mismatch_probe");
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
        stage("schema_mismatch_completed");
        stage("apps_rejection_probe");
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
        stage("initial_synthetic_call");
        call.call(Some(payload.clone()), None, None).await?;
        runtime.reconnect_on_next_refresh();
        stage("sync_marker_call");
        // The sync request marker does not replace an executable binding.
        call.call(Some(payload.clone()), None, None).await?;

        stage("sync_marker_completed");
        stage("publication_race");
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
        stage("stale_call_after_publish");
        let err = call
            .call(Some(payload.clone()), None, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("approved MCP generation invalidated")
        );
        assert_eq!(std::fs::read(&receipt)?, frozen);
        stage("publication_completed_old_call_denied");
        let next = runtime
            .current_binding_for_call("devhub_delegate")
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&binding, &next));
        stage("old_host_admission_rejection");
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
        stage("old_host_admission_rejected");
        stage("fresh_router_admission");
        diagnostic(&next);
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
        stage("fresh_binding_approve");
        diagnostic(&next);
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
        stage("shutdown_race");
        let shutdown = runtime.shutdown();
        tokio::pin!(shutdown);
        assert!(futures::poll!(shutdown.as_mut()).is_pending());
        release.send(()).unwrap();
        active.await?;
        shutdown.await;
        let frozen = std::fs::read(&receipt)?;
        stage("stale_call_after_shutdown");
        let err = fresh_call
            .call(Some(payload.clone()), None, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("approved MCP generation invalidated")
        );
        assert_eq!(std::fs::read(&receipt)?, frozen);
        stage("shutdown_completed_old_call_denied");
        stage("republish");
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
        stage("newest_binding_approve");
        diagnostic(&newest);
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
    stage("all_subset_assertions_completed");
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
