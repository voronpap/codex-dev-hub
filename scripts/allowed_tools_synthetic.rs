// Test scaffold only; generated production methods are supplied by the audit.
fn delegate() -> ToolName {
    ToolName::namespaced(callable_namespace_with_prefix("devhub_delegate", true), "devhub_delegate")
}
fn candidates() -> Vec<ToolName> {
    vec![delegate(), ToolName::plain("apply_patch"), ToolName::plain("exec"),
         ToolName::plain("wait"), ToolName::plain("update_plan"),
         ToolName::namespaced("notes", "write_file"),
         ToolName::namespaced("image_gen", "imagegen"),
         ToolName::plain("request_plugin_install"), ToolName::plain("future_tool")]
}
fn offer(registry: &mut ToolRegistry) {
    for name in candidates() {
        registry.register_external_with_exposure(Arc::new(Synthetic(name.clone())), ToolExposure::Direct);
        // Distinct sources all pass through the same ceiling.
        if !registry.tools.contains_key(&name.clone().with_default_namespace()) {
            registry.register_trusted_with_exposure(Arc::new(Synthetic(name.clone())), ToolExposure::Direct);
        }
        if name != delegate() { registry.prepend_trusted(Arc::new(Synthetic(name))); }
    }
}
#[test] fn arm_a_empty() {
    let mut r=ToolRegistry::with_allowed_tools(Some(Arc::new(AllowedTools(vec![]))));
    offer(&mut r); assert!(r.tools.0.is_empty());
}
#[test] fn arm_b_one_canonical_name() {
    let mut r=ToolRegistry::with_allowed_tools(Some(Arc::new(AllowedTools(vec![delegate()]))));
    offer(&mut r); assert_eq!(r.tools.0.keys().cloned().collect::<Vec<_>>(), vec![delegate()]);
}
#[test] fn namespace_mismatch_and_unknown_deny() {
    for wrong in [ToolName::plain("devhub_delegate"), ToolName::namespaced("devhub_delegate", "devhub_delegate"),
                  ToolName::plain("mcp__devhub_delegate__devhub_delegate"), ToolName::plain("unknown")] {
        let mut r=ToolRegistry::with_allowed_tools(Some(Arc::new(AllowedTools(vec![wrong]))));
        assert!(!r.register_external_with_exposure(Arc::new(Synthetic(delegate())),ToolExposure::Direct));
        assert!(r.tools.0.is_empty());
    }
}
#[test] fn default_namespace_equivalence_only() {
    let a=AllowedTools(vec![ToolName::plain("x")]);
    assert!(a.contains(&ToolName::namespaced("functions","x")));
    assert!(a.contains(&ToolName::namespaced("","x")));
    assert!(!a.contains(&ToolName::namespaced("notes","x")));
}
#[test] fn duplicate_external_name_records_collision_not_replacement() {
    let mut r=ToolRegistry::with_allowed_tools(Some(Arc::new(AllowedTools(vec![delegate(),delegate()]))));
    assert!(r.register_external_with_exposure(Arc::new(Synthetic(delegate())),ToolExposure::Direct));
    assert!(!r.register_external_with_exposure(Arc::new(Synthetic(delegate())),ToolExposure::Direct));
    assert_eq!(r.tools.0.len(),1); assert_eq!(r.first_collision,Some(delegate()));
}
#[test] fn late_registration_cannot_widen_ceiling() {
    let mut r=ToolRegistry::with_allowed_tools(Some(Arc::new(AllowedTools(vec![delegate()]))));
    offer(&mut r);
    assert!(!r.register_external_with_exposure(Arc::new(Synthetic(ToolName::plain("new_dynamic"))),ToolExposure::Direct));
    assert_eq!(r.tools.0.len(),1);
}
#[test] fn code_mode_alias_is_not_allowlist_identity() {
    assert_eq!(code_mode_name_for_tool_name(&delegate()), "mcp__devhub_delegate__devhub_delegate");
    assert!(!AllowedTools(vec![ToolName::plain(code_mode_name_for_tool_name(&delegate()))]).contains(&delegate()));
}
