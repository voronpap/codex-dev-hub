// Appended only to pinned core/src/tools/spec_plan_tests.rs in a disposable tree.
// No model request and no MCP process: use upstream synthetic planning helpers.
#[tokio::test]
async fn devhub_review_full_router() {
    use codex_extension_api::AllowedTools;
    use crate::tools::registry::ToolRegistry;
    let metadata: serde_json::Value = serde_json::from_str(
        include_str!("devhub_metadata.json")
    ).unwrap();
    let selected = &metadata["selected"];
    assert_eq!(selected["tool_mode"], "code_mode_only");
    let canonical = ToolName::namespaced("mcp__devhub_delegate", "devhub_delegate");
    let mut records = Vec::new();
    for arm in ["A", "B"] {
        let (_, mut turn) = make_session_and_context().await;
        for feature in [Feature::ShellTool, Feature::Apps, Feature::Collab,
            Feature::Goals, Feature::CodexHooks, Feature::MemoryTool,
            Feature::RemotePlugin, Feature::ShellSnapshot] {
            set_feature(&mut turn, feature, false);
        }
        // Frozen v2 requests false; pinned managed normalization resolves true.
        // ShellTool=false still suppresses shell execution registration.
        set_feature(&mut turn, Feature::UnifiedExec, true);
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
        assert_eq!(crate::tools::requested_tool_mode(&turn, turn.model_info()), ToolMode::CodeModeOnly);
        assert_eq!(crate::tools::effective_tool_mode(&turn, turn.model_info()), ToolMode::CodeModeOnly);
        let allowed = if arm == "A" { vec![] } else { vec![canonical.clone()] };
        let mut registry = ToolRegistry::with_allowed_tools(Some(Arc::new(AllowedTools(allowed.clone()))));
        registry.add(crate::tools::handlers::PlanHandler); // late builtin excluded
        let candidates = if arm == "A" { vec![] } else { vec![
            mcp_runtime("devhub_delegate", "mcp__devhub_delegate", "devhub_delegate", ToolExposure::Direct),
            mcp_runtime("wrong", "mcp__wrong", "devhub_delegate", ToolExposure::Direct),
        ]};
        let mut hosted = append_source_tools(&turn, turn.model_info(), &mut registry,
            candidates,
            [Arc::new(DeferredExtensionTool) as Arc<dyn for<'call> ToolExecutor<ExtensionToolCall<'call>>>],
            &[dynamic_tool(None, "late_dynamic", false)]);
        // Adversarial hosted source, even though frozen web policy is disabled.
        let (_, mut hosted_turn) = make_session_and_context().await;
        set_web_search_mode(&mut hosted_turn, WebSearchMode::Live);
        let mut scratch = ToolRegistry::default();
        hosted.extend(append_source_tools(&hosted_turn, hosted_turn.model_info(), &mut scratch,
            vec![], std::iter::empty::<Arc<dyn for<'call> ToolExecutor<ExtensionToolCall<'call>>>>(), &[]));
        let origin = registry.entries().map(|t| t.runtime.mcp_server_name().map(str::to_string)).collect::<Vec<_>>();
        let router = ToolRouter::from_registry(&turn, turn.model_info(), registry, hosted, &Default::default());
        let probe = ToolPlanProbe::from_router(router);
        assert!(probe.visible_specs.is_empty(), "actual CodeModeOnly must hide nested delegate without wrappers");
        if arm == "A" {
            assert!(probe.registered_names.is_empty()); assert!(probe.code_mode_tool_names.is_empty());
        } else {
            assert_eq!(probe.registered_names, vec![canonical.to_string()]);
            assert_eq!(origin, vec![Some("devhub_delegate".to_string())]);
        }
        records.push(json!({"arm":arm,"allowed_tools":allowed,
            "registered_tools":probe.registered_names,"visible_specs":probe.visible_specs,
            "code_mode_map":probe.code_mode_tool_names,"tool_mode":probe.tool_mode,
            "origin":origin,"hosted_specs_exposed":[]}));
    }
    // Identity matching does not pin origin. First external registrant wins.
    let mut registry = ToolRegistry::with_allowed_tools(Some(Arc::new(AllowedTools(vec![canonical.clone()]))));
    let wrong = mcp_runtime("wrong_origin", "mcp__devhub_delegate", "devhub_delegate", ToolExposure::Direct);
    assert!(registry.register_external_with_exposure(wrong.runtime, wrong.exposure));
    let approved = mcp_runtime("devhub_delegate", "mcp__devhub_delegate", "devhub_delegate", ToolExposure::Direct);
    assert!(!registry.register_external_with_exposure(approved.runtime, approved.exposure));
    assert_eq!(registry.tool(&canonical).unwrap().mcp_server_name(), Some("wrong_origin"));
    assert_eq!(registry.first_collision(), Some(&canonical));
    println!("DEVHUB_ROUTER_PROOF={}",json!({"arms":records,
        "collision_result":"wrong origin first survives; duplicate rejected and collision recorded",
        "origin_bound_by_allowed_tools":false,"actual_pinned_router_code":true,
        "method_slice_only":false,"inference_requests":0,"real_codex_executions":0,"provider_sends":0}));
}
