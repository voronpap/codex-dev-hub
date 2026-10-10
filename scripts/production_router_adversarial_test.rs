// Additional production-path authority scenarios; synthetic stdio only.
#[tokio::test]
async fn devhub_production_admission_path_adversarial() -> anyhow::Result<()> {
    use crate::tools::registry::ToolRegistry;
    use codex_extension_api::{AllowedTools, ExtensionData};
    use codex_mcp::{McpRuntime, McpRuntimeContext, McpRuntimeInput, McpStartupPolicy};
    use codex_protocol::mcp::ClientMcpExtensions;
    use std::collections::HashMap;
    use tokio_util::sync::CancellationToken;
    fn checkpoint(name: &str) {
        println!("DEVHUB_ADVERSARIAL_STAGE={name}");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
    }
    async fn capture(
        turn: &TurnContext,
        servers: HashMap<String, codex_config::McpServerConfig>,
        cwd: &std::path::Path,
    ) -> anyhow::Result<(McpRuntime, Arc<codex_mcp::McpBinding>)> {
        let mut configured = (*turn.config).clone();
        configured.mcp_servers = codex_config::Constrained::allow_any(servers);
        let mut config = (*mcp_config_for_test(&configured)).clone();
        let effective = codex_mcp::effective_mcp_servers(&config, None);
        config.set_server_permission_profiles(
            &effective,
            turn.environments.turn_environments().map(|e| {
                (
                    e.selection.environment_id.clone(),
                    e.permission_profile_with_workspace_roots(),
                )
            }),
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
                    cwd.to_path_buf(),
                ),
                codex_apps_tools_cache: Default::default(),
                tool_catalog_cache: Default::default(),
                codex_apps_tools_cache_key: codex_mcp::codex_apps_tools_cache_key(None),
                client_mcp_extensions: ClientMcpExtensions::default(),
                auth: None,
                auth_manager: None,
                elicitation_reviewer: None,
                elicitation_lifecycle: None,
            })
            .await;
        let binding = runtime
            .current_binding_for_call("devhub_delegate")
            .await
            .expect("synthetic ready");
        Ok((runtime, binding))
    }
    let schema: serde_json::Value = serde_json::from_str(include_str!("devhub_real_schema.json"))?;
    let payload: serde_json::Value =
        serde_json::from_str(include_str!("devhub_synthetic_payload.json"))?;
    let (mut session, mut turn) = make_session_and_context().await;
    use_chatgpt_auth(&mut turn);
    update_turn_settings_for_test(&mut turn, |s| {
        Arc::make_mut(&mut s.model_info).tool_mode = Some(ToolMode::CodeModeOnly)
    });
    update_config(&mut turn, |c| {
        c.code_mode.direct_only_tool_namespaces = vec!["mcp__devhub_delegate".into()];
        c.tool_registry.error_on_tool_collisions = true;
    });
    let name = ToolName::namespaced("mcp__devhub_delegate", "devhub_delegate");
    let allowed = Arc::new(AllowedTools(vec![name.clone()]));
    session.allowed_tools = Some(Arc::clone(&allowed));
    let temp = tempfile::tempdir()?;
    let receipt = std::path::PathBuf::from(std::env::var("DEVHUB_RECEIPT_PATH")?);
    let script = std::env::var("DEVHUB_SYNTHETIC_MCP")?;
    let schema_path = std::env::var("DEVHUB_REAL_SCHEMA")?;
    let server: codex_config::McpServerConfig = serde_json::from_value(json!({
        "command":"python3","args":[script,schema_path,receipt.to_str().unwrap(),"approved-adversarial-endpoint"],"required":true,
        "enabled_tools":["devhub_delegate"],"tools":{"devhub_delegate":{"approval_mode":"approve"}}
    }))?;
    update_config(&mut turn, |c| {
        c.mcp_servers = codex_config::Constrained::allow_any(HashMap::from([(
            "devhub_delegate".into(),
            server.clone(),
        )]))
    });
    let (runtime, binding) = capture(
        &turn,
        HashMap::from([("devhub_delegate".into(), server.clone())]),
        temp.path(),
    )
    .await?;
    assert_eq!(binding.tools().len(), 1);
    let approve = |b: &codex_mcp::McpBinding| {
        b.approve_call(
            "devhub_delegate",
            "devhub_delegate",
            "mcp__devhub_delegate",
            "devhub_delegate",
            &server,
            &schema,
        )
    };

    // Reconstruct build-006 host policy, observe actual mode/helper without calling.
    let mut legacy_json = serde_json::to_value(&server)?;
    legacy_json.as_object_mut().unwrap().remove("tools");
    legacy_json.as_object_mut().unwrap().remove("enabled_tools");
    let legacy: codex_config::McpServerConfig = serde_json::from_value(legacy_json)?;
    let (legacy_runtime, legacy_binding) = capture(
        &turn,
        HashMap::from([("devhub_delegate".into(), legacy.clone())]),
        temp.path(),
    )
    .await?;
    let legacy_call = legacy_binding
        .approve_call(
            "devhub_delegate",
            "devhub_delegate",
            "mcp__devhub_delegate",
            "devhub_delegate",
            &legacy,
            &schema,
        )?
        .prepared_call();
    assert_eq!(
        legacy_call.tool_approval_mode(),
        codex_config::AppToolApproval::Auto
    );
    assert!(legacy_call.tool_info().tool.annotations.is_none());
    assert!(crate::mcp_tool_call::devhub_proof_requires_approval(
        None,
        legacy_call.tool_approval_mode()
    ));
    println!(
        "DEVHUB_APPROVAL_BASELINE={}",
        json!({"mode":"Auto","annotations":null,"required_by_mode":true,"executed":false})
    );
    legacy_runtime.shutdown().await;

    checkpoint("wrong_origin_only");
    let wrong: codex_config::McpServerConfig = serde_json::from_value(json!({
        "command":"python3","args":[script,schema_path,temp.path().join("wrong.jsonl"),"wrong-endpoint"],"required":true
    }))?;
    let (wrong_runtime, wrong_binding) = capture(
        &turn,
        HashMap::from([("devhub_delegate".into(), wrong)]),
        temp.path(),
    )
    .await?;
    assert_eq!(wrong_binding.tools()[0].canonical_tool_name(), name);
    assert!(approve(&wrong_binding).is_err());
    let policy = crate::ApprovedDelegatePolicy::delegate(server.clone(), schema.clone());
    assert!(
        policy
            .register(
                &wrong_binding,
                &mut ToolRegistry::with_allowed_tools(Some(Arc::clone(&allowed)))
            )
            .is_err()
    );
    wrong_runtime.shutdown().await;
    checkpoint("wrong_origin_only_passed");

    let mut forged_info = binding.tools()[0].clone();
    forged_info.server_name = "wrong-origin".into();
    let wrong_handler =
        || Arc::new(McpHandler::new(forged_info.clone()).unwrap()) as Arc<dyn CoreToolRuntime>;
    checkpoint("wrong_first");
    let mut registry = ToolRegistry::with_allowed_tools(Some(Arc::clone(&allowed)));
    assert!(registry.register_external(wrong_handler()));
    assert!(
        crate::ApprovedDelegatePolicy::delegate(server.clone(), schema.clone())
            .register(&binding, &mut registry)
            .is_err()
    );
    checkpoint("wrong_first_passed");
    checkpoint("approved_first");
    let mut registry = ToolRegistry::with_allowed_tools(Some(Arc::clone(&allowed)));
    crate::ApprovedDelegatePolicy::delegate(server.clone(), schema.clone())
        .register(&binding, &mut registry)?;
    assert!(!registry.register_external(wrong_handler()));
    assert!(
        super::finalize_tool_router(
            &turn,
            turn.model_info(),
            registry,
            vec![],
            &Default::default()
        )
        .is_err()
    );
    checkpoint("approved_first_passed");

    checkpoint("forged_runtime");
    let empty = codex_mcp::McpBinding::empty(Arc::clone(binding.config()));
    assert!(approve(&empty).is_err());
    // Same public metadata cannot mint an approved runtime: it occupies the registry
    // but admission requires the exact captured binding and an empty registry.
    let mut registry = ToolRegistry::with_allowed_tools(Some(Arc::clone(&allowed)));
    assert!(registry.register_external(Arc::new(McpHandler::new(binding.tools()[0].clone())?)));
    assert!(
        crate::ApprovedDelegatePolicy::delegate(server.clone(), schema.clone())
            .register(&binding, &mut registry)
            .is_err()
    );
    checkpoint("forged_runtime_passed");

    checkpoint("extra_mcp");
    let (extra_runtime, extra_binding) = capture(
        &turn,
        HashMap::from([
            ("devhub_delegate".into(), server.clone()),
            ("extra_server".into(), server.clone()),
        ]),
        temp.path(),
    )
    .await?;
    println!("DEVHUB_EXTRA_IDENTITIES={}",json!(extra_binding.tools().iter().map(|t|json!({"server":t.server_name,"raw":t.tool.name,"namespace":t.callable_namespace,"name":t.callable_name})).collect::<Vec<_>>()));
    assert_eq!(extra_binding.tools().len(), 2);
    assert!(
        crate::ApprovedDelegatePolicy::delegate(server.clone(), schema.clone())
            .register(
                &extra_binding,
                &mut ToolRegistry::with_allowed_tools(Some(Arc::clone(&allowed)))
            )
            .is_err()
    );
    extra_runtime.shutdown().await;
    checkpoint("extra_mcp_passed");

    checkpoint("dynamic_hosted");
    set_web_search_mode(&mut turn, WebSearchMode::Live);
    update_turn_settings_for_test(&mut turn, |s| {
        let m = Arc::make_mut(&mut s.model_info);
        m.supports_search_tool = true;
        m.use_responses_lite = false;
    });
    let mut registry = ToolRegistry::with_allowed_tools(Some(Arc::clone(&allowed)));
    crate::ApprovedDelegatePolicy::delegate(server.clone(), schema.clone())
        .register(&binding, &mut registry)?;
    let hosted = append_source_tools(
        &turn,
        turn.model_info(),
        &mut registry,
        vec![],
        [Arc::new(DeferredExtensionTool)
            as Arc<
                dyn for<'call> ToolExecutor<ExtensionToolCall<'call>>,
            >],
        &[dynamic_tool(None, "adversarial_dynamic", false)],
    );
    assert!(
        !hosted.is_empty(),
        "hosted candidate must actually be supplied"
    );
    let filtered = super::finalize_tool_router(
        &turn,
        turn.model_info(),
        registry,
        hosted,
        &Default::default(),
    )?;
    assert!(filtered.tool_runtime(&name).is_some());
    let probe = ToolPlanProbe::from_router(filtered);
    assert_eq!(probe.registered_names.len(), 1);
    assert_eq!(probe.visible_specs.len(), 1);
    assert!(probe.code_mode_tool_names.is_empty());
    checkpoint("dynamic_hosted_passed");

    checkpoint("handler_dispatch");
    session
        .services
        .thread_extension_data
        .insert(crate::ApprovedDelegatePolicy::delegate(
            server.clone(),
            schema.clone(),
        ));
    let router = super::build_tool_router(
        &session,
        &turn,
        turn.model_info(),
        None,
        &turn.environments,
        &binding,
        false,
        &ExtensionData::new("devhub-adversarial"),
        None,
    )?;
    let handler = router
        .tool_runtime(&name)
        .expect("approved runtime in actual router");
    // Session's ordinary MCP runtime has no server: success requires retained authority,
    // not generic runtime name lookup. Do not install this standalone runtime on Session.
    assert!(
        session
            .services
            .mcp_runtime
            .current_binding_for_call("devhub_delegate")
            .await
            .is_none()
    );
    let observed = approve(&binding)?.prepared_call();
    let annotations = observed.tool_info().tool.annotations.as_ref();
    assert_eq!(
        observed.tool_approval_mode(),
        codex_config::AppToolApproval::Approve
    );
    assert!(!crate::mcp_tool_call::devhub_proof_requires_approval(
        annotations,
        observed.tool_approval_mode()
    ));
    assert!(
        session.active_turn.lock().await.is_none(),
        "fixture has no active strict review turn"
    );
    println!(
        "DEVHUB_APPROVAL_CONFIG={}",
        json!({
            "mode":format!("{:?}",observed.tool_approval_mode()),
            "read_only_hint":annotations.and_then(|a|a.read_only_hint),
            "destructive_hint":annotations.and_then(|a|a.destructive_hint),
            "open_world_hint":annotations.and_then(|a|a.open_world_hint),
            "global_approval_policy":format!("{:?}",observed.config().approval_policy.value()),
            "permission_profile_present":observed.config().permission_profile_for_server("devhub_delegate").is_some(),
            "strict_auto_review":false,
            "required_by_mode":crate::mcp_tool_call::devhub_proof_requires_approval(annotations, observed.tool_approval_mode())
        })
    );
    let turn = Arc::new(turn);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        handler.handle(crate::tools::context::ToolInvocation {
            session: Arc::new(session),
            turn: Arc::clone(&turn),
            step_context: crate::session::step_context::StepContext::for_test(Arc::clone(&turn)),
            cancellation_token: CancellationToken::new(),
            tracker: Arc::new(tokio::sync::Mutex::new(
                crate::turn_diff_tracker::TurnDiffTracker::new(),
            )),
            call_id: "synthetic-handler-only".into(),
            tool_name: name,
            source: crate::tools::context::ToolCallSource::Direct,
            payload: crate::tools::context::ToolPayload::Function {
                arguments: serde_json::to_string(&payload)?,
            },
        }),
    )
    .await??;
    checkpoint("handler_return");
    assert!(result.success_for_logging());
    let records = std::fs::read_to_string(&receipt)?
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["arguments"], payload);
    assert_eq!(
        records[0]["endpoint_identity"],
        "approved-adversarial-endpoint"
    );
    assert_eq!(records[0]["raw_tool"], "devhub_delegate");
    assert_eq!(
        records[0]["schema_hash"],
        "0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be"
    );
    checkpoint("synthetic_receipt_seen");
    checkpoint("handler_dispatch_passed");
    runtime.shutdown().await;
    println!(
        "DEVHUB_ADVERSARIAL_PROOF={}",
        json!({
            "wrong_origin_only":true,"wrong_first":true,"approved_first":true,"forged_runtime":true,
            "extra_mcp":true,"dynamic_hosted_adversarial":true,"handler_dispatch":true,
            "catalog_refresh_after_preparation":null,"process_proof":null,
            "collision_behavior":"wrong-first admission rejected; approved-first duplicate rejected and router finalization fatal",
            "forged_runtime_scope":"public empty binding and metadata-only McpHandler substitution denied",
            "synthetic_process_dispatch":true,"receipts":records,"real_codex_executions":0,"provider_sends":0
        })
    );
    Ok(())
}
