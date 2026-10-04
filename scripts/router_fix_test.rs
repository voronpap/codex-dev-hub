// Investigation only: appended to pinned spec_plan_tests.rs, never production.
// Candidate B: existing DirectModelOnly namespace setting + prototype trusted ingress.
fn devhub_fix_admit(
    registry: &mut crate::tools::registry::ToolRegistry,
    arm_b: bool,
    trusted_channel: &str,
    info: ToolInfo,
) -> Option<Arc<dyn CoreToolRuntime>> {
    let canonical = ToolName::namespaced("mcp__devhub_delegate", "devhub_delegate");
    if !arm_b || trusted_channel != "devhub_delegate"
        || info.server_name != trusted_channel
        || info.tool.name.as_ref() != "devhub_delegate"
        || info.canonical_tool_name() != canonical {
        return None;
    }
    // Construct the runtime here, not from an arbitrary caller-supplied executor.
    let runtime: Arc<dyn CoreToolRuntime> = Arc::new(McpHandler::new(info).unwrap());
    if !registry.register_external_with_exposure(Arc::clone(&runtime), ToolExposure::Direct) {
        return None;
    }
    Some(runtime)
}

fn devhub_fix_origin_seal(
    registry: &crate::tools::registry::ToolRegistry,
    approved: Option<&Arc<dyn CoreToolRuntime>>,
) -> bool {
    let tools = registry.entries().collect::<Vec<_>>();
    match approved {
        None => tools.is_empty() && registry.first_collision().is_none(),
        Some(expected) => tools.len() == 1 && registry.first_collision().is_none()
            && tools[0].runtime.tool_name()
                == ToolName::namespaced("mcp__devhub_delegate", "devhub_delegate")
            && tools[0].runtime.mcp_server_name() == Some("devhub_delegate")
            && Arc::ptr_eq(&tools[0].runtime, expected),
    }
}

#[tokio::test]
async fn devhub_review_router_fix() {
    use codex_extension_api::AllowedTools;
    use crate::tools::registry::ToolRegistry;
    use crate::tools::spec_plan::finalize_tool_router;
    let metadata: serde_json::Value = serde_json::from_str(include_str!("devhub_metadata.json")).unwrap();
    let selected = &metadata["selected"];
    let canonical = ToolName::namespaced("mcp__devhub_delegate", "devhub_delegate");
    let mut records = Vec::new();
    for arm in ["A", "B"] {
        let (_, mut turn) = make_session_and_context().await;
        use_chatgpt_auth(&mut turn);
        for feature in [Feature::ShellTool, Feature::Apps, Feature::Collab, Feature::Goals,
            Feature::CodexHooks, Feature::MemoryTool, Feature::RemotePlugin, Feature::ShellSnapshot] {
            set_feature(&mut turn, feature, false);
        }
        set_feature(&mut turn, Feature::UnifiedExec, true); // pinned managed normalization
        set_web_search_mode(&mut turn, WebSearchMode::Disabled);
        update_turn_settings_for_test(&mut turn, |settings| {
            let model = Arc::make_mut(&mut settings.model_info);
            model.slug = selected["slug"].as_str().unwrap().to_string();
            model.tool_mode = Some(serde_json::from_value(selected["tool_mode"].clone()).unwrap());
            model.apply_patch_tool_type = serde_json::from_value(selected["apply_patch_tool_type"].clone()).unwrap();
            model.shell_type = serde_json::from_value(selected["shell_type"].clone()).unwrap();
            model.supports_search_tool = selected["supports_search_tool"].as_bool().unwrap();
            model.use_responses_lite = selected["use_responses_lite"].as_bool().unwrap();
        });
        update_config(&mut turn, |config| {
            config.code_mode.direct_only_tool_namespaces = vec!["mcp__devhub_delegate".to_string()];
            config.tool_registry.error_on_tool_collisions = true;
        });
        assert_eq!(crate::tools::effective_tool_mode(&turn, turn.model_info()), ToolMode::CodeModeOnly);
        let allowed = if arm == "B" { vec![canonical.clone()] } else { vec![] };
        let mut registry = ToolRegistry::with_allowed_tools(Some(Arc::new(AllowedTools(allowed))));
        // Exercise pinned core source planning, then admit its real runtimes through the ceiling.
        let mcp = codex_mcp::McpBinding::empty(mcp_config_for_test(&turn.config));
        let core = build_core_tool_registry(&turn, turn.model_info(), &turn.environments, &mcp, None, None);
        for entry in core.entries() {
            registry.register_trusted_with_exposure(Arc::clone(&entry.runtime), entry.exposure);
        }
        assert!(registry.entries().next().is_none());
        // Wrong origin attempts the same canonical identity FIRST. It never enters registry.
        let wrong = mcp_tool("wrong_origin", "mcp__devhub_delegate", "devhub_delegate");
        assert!(devhub_fix_admit(&mut registry, arm == "B", "wrong_origin", wrong).is_none());
        let spoof = mcp_tool("devhub_delegate", "mcp__devhub_delegate", "devhub_delegate");
        assert!(devhub_fix_admit(&mut registry, arm == "B", "wrong_origin", spoof).is_none());
        let mut raw_alias = mcp_tool("devhub_delegate", "mcp__devhub_delegate", "devhub_delegate");
        raw_alias.tool.name = "different_raw_operation".into();
        assert!(devhub_fix_admit(&mut registry, arm == "B", "devhub_delegate", raw_alias).is_none());
        let alias = mcp_tool("devhub_delegate", "mcp__devhub-delegate", "devhub_delegate");
        assert!(devhub_fix_admit(&mut registry, arm == "B", "devhub_delegate", alias).is_none());
        let approved = devhub_fix_admit(&mut registry, arm == "B", "devhub_delegate",
            mcp_tool("devhub_delegate", "mcp__devhub_delegate", "devhub_delegate"));
        assert_eq!(approved.is_some(), arm == "B");
        let mut hosted = append_source_tools(&turn, turn.model_info(), &mut registry,
            vec![mcp_runtime("extra", "mcp__devhub_delegate", "diagnostic", ToolExposure::Direct)],
            [Arc::new(DeferredExtensionTool) as Arc<dyn for<'call> ToolExecutor<ExtensionToolCall<'call>>>],
            &[dynamic_tool(None, "late_dynamic", false)]);
        let (_, mut hosted_turn) = make_session_and_context().await;
        use_chatgpt_auth(&mut hosted_turn);
        set_web_search_mode(&mut hosted_turn, WebSearchMode::Live);
        hosted.extend(append_source_tools(&hosted_turn, hosted_turn.model_info(), &mut ToolRegistry::default(),
            vec![], std::iter::empty::<Arc<dyn for<'call> ToolExecutor<ExtensionToolCall<'call>>>>(), &[]));
        assert!(devhub_fix_origin_seal(&registry, approved.as_ref()));
        let router = finalize_tool_router(&turn, turn.model_info(), registry, hosted, &Default::default()).unwrap();
        let probe = ToolPlanProbe::from_router(router);
        assert_eq!(probe.tool_mode, ToolMode::CodeModeOnly);
        assert!(probe.code_mode_tool_names.is_empty());
        if arm == "A" {
            assert!(probe.registered_names.is_empty() && probe.visible_specs.is_empty());
        } else {
            assert_eq!(probe.registered_names, vec![canonical.to_string()]);
            assert_eq!(probe.visible_specs.len(), 1);
            assert_eq!(probe.namespace_functions,
                BTreeMap::from([("mcp__devhub_delegate".to_string(), vec!["devhub_delegate".to_string()])]));
            assert_eq!(probe.exposure(&canonical.to_string()), ToolExposure::DirectModelOnly);
        }
        records.push(json!({"arm":arm,"registered_tools":probe.registered_names,
            "visible_specs":probe.visible_specs,"namespace_functions":probe.namespace_functions,
            "code_mode_map":probe.code_mode_tool_names,"tool_mode":probe.tool_mode,
            "hosted_specs_exposed":[],"origin_seal_passed":true}));
        // Adversarial bypass of the ingress guard: wrong first survives registry, but cannot seal
        // or finalize. This is fail-closed, not collision logging alone.
        let mut poisoned = ToolRegistry::with_allowed_tools(Some(Arc::new(AllowedTools(vec![canonical.clone()]))));
        let wrong = mcp_runtime("wrong_origin", "mcp__devhub_delegate", "devhub_delegate", ToolExposure::Direct);
        assert!(poisoned.register_external_with_exposure(wrong.runtime, wrong.exposure));
        assert!(!devhub_fix_origin_seal(&poisoned, approved.as_ref()));
        let duplicate = mcp_runtime("devhub_delegate", "mcp__devhub_delegate", "devhub_delegate", ToolExposure::Direct);
        assert!(!poisoned.register_external_with_exposure(duplicate.runtime, duplicate.exposure));
        assert!(finalize_tool_router(&turn, turn.model_info(), poisoned, vec![], &Default::default()).is_err());
        // Even a forged runtime claiming the correct server fails exact object binding.
        let mut forged = ToolRegistry::with_allowed_tools(Some(Arc::new(AllowedTools(vec![canonical.clone()]))));
        let spoof = mcp_runtime("devhub_delegate", "mcp__devhub_delegate", "devhub_delegate", ToolExposure::Direct);
        forged.register_external_with_exposure(spoof.runtime, spoof.exposure);
        assert!(!devhub_fix_origin_seal(&forged, approved.as_ref()));
    }
    println!("DEVHUB_ROUTER_PROOF={}", json!({"classification":"ROUTER_FIX_FEASIBLE",
        "candidate":"B_direct_model_only_namespace_plus_trusted_ingress_seal",
        "arms":records,"wrong_origin_first_rejected":true,"raw_name_mismatch_rejected":true,
        "spoofed_channel_rejected":true,"namespace_alias_rejected":true,
        "forged_runtime_rejected":true,"bypassed_guard_collision_finalization_failed":true,
        "origin_scope":"test-local typed ingress and exact runtime object seal; production host not implemented",
        "actual_pinned_router_code":true,"method_slice_only":false,"production_modified":false,
        "execution_ready":false,"real_codex_executions":0,"provider_sends":0}));
}
