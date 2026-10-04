"""Disposable test-only observations; never edit the shipping Candidate B patch."""

# ruff: noqa: E501

import hashlib
from pathlib import Path


def instrument(root: Path) -> dict[str, str]:
    hashes = {}

    def edit(name, pairs, suffix=""):
        path = root / name
        text = path.read_text()
        for anchor, replacement in pairs:
            assert text.count(anchor) == 1, (name, anchor)
            text = text.replace(anchor, replacement)
        path.write_text(text + suffix, encoding="utf-8", newline="\n")
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()

    def marker(label):
        return '#[cfg(test)] println!("DEVHUB_HANDLER_STAGE=' + label + '");\n'

    edit(
        "core/src/tools/handlers/mcp.rs",
        [
            (
                "        let prepared_mcp_call = if let Some(approved) = &self.approved_call {",
                "        "
                + marker("handler_entry")
                + "        let prepared_mcp_call = if let Some(approved) = &self.approved_call {",
            ),
            (
                "        // Use the executed call's binding;",
                "        "
                + marker("prepared_approved_call_selected")
                + "        // Use the executed call's binding;",
            ),
            (
                "        notify_tool_start(&invocation, mcp_tool.as_ref()).await;",
                "        notify_tool_start(&invocation, mcp_tool.as_ref()).await;\n        "
                + marker("notify_tool_start_completed"),
            ),
            (
                "        let originating_call = invocation.originating_call().await;",
                "        let originating_call = invocation.originating_call().await;\n        "
                + marker("originating_call_completed"),
            ),
        ],
    )
    edit(
        "core/src/mcp_tool_call.rs",
        [
            (
                "    let approvals_reviewer = connectors::mcp_approvals_reviewer_from_layers(",
                '    #[cfg(test)] println!("DEVHUB_APPROVAL_PATH={{\\"mode\\":\\"{:?}\\",\\"strict_auto_review\\":{},\\"required_by_mode\\":{}}}", policy.mode, strict_auto_review, requires_mcp_tool_approval_for_mode(metadata.annotations.as_ref(), policy.mode));\n    '  # noqa: E501
                + marker("approval_decision_path")
                + "    let approvals_reviewer = connectors::mcp_approvals_reviewer_from_layers(",
            ),
            (
                "    approval_application: McpToolApprovalApplication,\n) -> HandledMcpToolCall {",
                "    approval_application: McpToolApprovalApplication,\n) -> HandledMcpToolCall {\n    "  # noqa: E501
                + marker("handle_approved_mcp_tool_call_entered"),
            ),
            (
                "            let mut result = prepared_call\n                .call_with_preparation(",  # noqa: E501
                "            "
                + marker("prepared_execution_entered")
                + "            let mut result = prepared_call\n                .call_with_preparation(",  # noqa: E501
            ),
            (
                "                .call_with_preparation(/*requested_timeout*/ None, || async {\n",
                "                .call_with_preparation(/*requested_timeout*/ None, || async {\n                    "
                + marker("preparation_closure_entered"),
            ),
            (
                "                    if let McpToolApprovalApplication::Apply { decision, policy } =\n",
                "                    "
                + marker("approval_application_enter")
                + "                    if let McpToolApprovalApplication::Apply { decision, policy } =\n",
            ),
            (
                "                        .await;\n                    }\n                    maybe_mark_thread_memory_mode_polluted",
                "                        .await;\n                    }\n                    "
                + marker("approval_application_exit")
                + "                    "
                + marker("memory_pollution_enter")
                + "                    maybe_mark_thread_memory_mode_polluted",
            ),
            (
                "                    maybe_mark_thread_memory_mode_polluted(sess, turn_context, &prepared_call)\n                        .await;\n",
                "                    maybe_mark_thread_memory_mode_polluted(sess, turn_context, &prepared_call)\n                        .await;\n                    "
                + marker("memory_pollution_exit")
                + "                    "
                + marker("rewrite_args_enter"),
            ),
            (
                "                    .await\n                    .map_err(anyhow::Error::msg)?;\n",
                "                    .await\n                    .map_err(anyhow::Error::msg)?;\n                    "
                + marker("rewrite_args_exit"),
            ),
            (
                "                    let request_meta = build_mcp_tool_call_request_meta(\n                        step_context,\n                        &server,\n                        call_id,\n                        Some(&metadata),\n                    );",
                "                    "
                + marker("request_meta_build_enter")
                + "                    let request_meta = build_mcp_tool_call_request_meta(\n                        step_context,\n                        &server,\n                        call_id,\n                        Some(&metadata),\n                    );\n                    "
                + marker("request_meta_build_exit"),
            ),
            (
                "                    let request_meta = with_mcp_tool_call_ids_meta(\n                        request_meta,\n                        &sess.thread_id.to_string(),\n                        &sess.session_id().to_string(),\n                        originating_call,\n                    );",
                "                    "
                + marker("request_ids_enter")
                + "                    let request_meta = with_mcp_tool_call_ids_meta(\n                        request_meta,\n                        &sess.thread_id.to_string(),\n                        &sess.session_id().to_string(),\n                        originating_call,\n                    );\n                    "
                + marker("request_ids_exit"),
            ),
            (
                "                    let request_meta = augment_mcp_tool_request_meta_with_sandbox_state(\n                        step_context,\n                        &prepared_call,\n                        request_meta,\n                    )\n                    .await?;",
                "                    "
                + marker("sandbox_meta_enter")
                + "                    let request_meta = augment_mcp_tool_request_meta_with_sandbox_state(\n                        step_context,\n                        &prepared_call,\n                        request_meta,\n                    )\n                    .await?;\n                    "
                + marker("sandbox_meta_exit"),
            ),
            (
                "                    let mcp_call_trace = sess\n                        .services\n                        .rollout_thread_trace\n                        .start_mcp_call_trace(call_id);",
                "                    "
                + marker("trace_enter")
                + "                    let mcp_call_trace = sess\n                        .services\n                        .rollout_thread_trace\n                        .start_mcp_call_trace(call_id);\n                    "
                + marker("trace_exit"),
            ),
            (
                "                    Ok((\n                        rewritten_arguments,\n                        mcp_call_trace.add_request_meta(request_meta),\n                    ))",
                "                    "
                + marker("add_request_meta_enter")
                + "                    let request_meta = mcp_call_trace.add_request_meta(request_meta);\n                    "
                + marker("add_request_meta_exit")
                + "                    Ok((rewritten_arguments, request_meta))",
            ),
        ],
        """
#[cfg(test)]
pub(crate) fn devhub_proof_requires_approval(
    annotations: Option<&ToolAnnotations>, mode: AppToolApproval,
) -> bool {
    requires_mcp_tool_approval_for_mode(annotations, mode)
}
""",
    )
    edit(
        "codex-mcp/src/binding.rs",
        [
            (
                "                let add_trusted_access_context = self.connections.add_trusted_access_context(",
                "                "
                + marker("trusted_access_context_enter")
                + "                let add_trusted_access_context = self.connections.add_trusted_access_context(",
            ),
            (
                "                let remaining_timeout = match effective_timeout.zip(timeout_deadline) {",
                "                "
                + marker("trusted_access_context_exit")
                + "                let remaining_timeout = match effective_timeout.zip(timeout_deadline) {",
            ),
            (
                '                self.client\n                    .client\n                    .call_tool(tool_name.clone(), arguments, meta, remaining_timeout)\n                    .await\n                    .with_context(|| format!("tool call failed for `{}/{tool_name}`", self.server_name))',
                "                "
                + marker("transport_call_enter")
                + '                let result = self.client\n                    .client\n                    .call_tool(tool_name.clone(), arguments, meta, remaining_timeout)\n                    .await\n                    .with_context(|| format!("tool call failed for `{}/{tool_name}`", self.server_name));\n                '
                + marker("transport_call_return")
                + "                result",
            ),
        ],
    )
    return hashes
