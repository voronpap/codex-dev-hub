"""Disposable test-only observations; never edit the shipping Candidate B patch."""

import hashlib
from pathlib import Path


def instrument(root: Path) -> dict[str, str]:
    hashes = {}

    def edit(name, pairs, suffix=""):
        path = root / name
        text = path.read_text(encoding="utf-8")
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

    def before(anchor, label):
        return (anchor, marker(label) + anchor)

    def after(anchor, label):
        return (anchor, anchor + "\n" + marker(label))

    edit(
        "core/src/mcp_tool_call.rs",
        [
            after(
                ".call_with_preparation(/*requested_timeout*/ None, || async {",
                "preparation_closure_entered",
            ),
            before(
                "                    if let McpToolApprovalApplication::Apply { decision, policy } =",  # noqa: E501
                "approval_application_enter",
            ),
            before(
                "                    maybe_mark_thread_memory_mode_polluted(sess, turn_context, &prepared_call)",  # noqa: E501
                "approval_application_exit",
            ),
            before(
                "                    maybe_mark_thread_memory_mode_polluted(sess, turn_context, &prepared_call)",  # noqa: E501
                "memory_pollution_enter",
            ),
            after(
                "maybe_mark_thread_memory_mode_polluted(sess, turn_context, &prepared_call)\n                        .await;",  # noqa: E501
                "memory_pollution_exit",
            ),
            before(
                "                    let rewritten_arguments = rewrite_mcp_tool_arguments_for_openai_files(",  # noqa: E501
                "rewrite_args_enter",
            ),
            before(
                "                    if let Some(rewritten_arguments) = rewritten_arguments.as_ref() {",  # noqa: E501
                "rewrite_args_exit",
            ),
            before(
                "                    let request_meta = build_mcp_tool_call_request_meta(",
                "request_meta_build_enter",
            ),
            before(
                "                    let request_meta = with_mcp_tool_call_ids_meta(",
                "request_meta_build_exit",
            ),
            before(
                "                    let request_meta = with_mcp_tool_call_ids_meta(",
                "request_ids_enter",
            ),
            before(
                "                    let request_meta = augment_mcp_tool_request_meta_with_sandbox_state(",  # noqa: E501
                "request_ids_exit",
            ),
            before(
                "                    let request_meta = augment_mcp_tool_request_meta_with_sandbox_state(",  # noqa: E501
                "sandbox_meta_enter",
            ),
            before("                    let mcp_call_trace = sess", "sandbox_meta_exit"),
            before("                    let mcp_call_trace = sess", "trace_enter"),
            after("                        .start_mcp_call_trace(call_id);", "trace_exit"),
            (
                "                    Ok((\n                        rewritten_arguments,\n                        mcp_call_trace.add_request_meta(request_meta),\n                    ))",  # noqa: E501
                marker("add_request_meta_enter")
                + "let request_meta = mcp_call_trace.add_request_meta(request_meta);\n"
                + marker("add_request_meta_exit")
                + "Ok((rewritten_arguments, request_meta))",
            ),
            before(
                "            // Capture trusted server metadata before result callbacks or model-facing rewrites.",  # noqa: E501
                "prepared_execution_returned",
            ),
        ],
    )

    # Dependency codex-mcp is not cfg(test) when linked by codex-core tests.
    # These unconditional static diagnostics exist ONLY in the disposable tree.
    def dep_marker(label):
        return 'println!("DEVHUB_HANDLER_STAGE=' + label + '");\n'

    anchor = "                let add_trusted_access_context = self.connections.add_trusted_access_context("  # noqa: E501
    transport = '                self.client\n                    .client\n                    .call_tool(tool_name.clone(), arguments, meta, remaining_timeout)\n                    .await\n                    .with_context(|| format!("tool call failed for `{}/{tool_name}`", self.server_name))'  # noqa: E501
    edit(
        "codex-mcp/src/binding.rs",
        [
            (anchor, dep_marker("trusted_access_context_enter") + anchor),
            (
                "                let remaining_timeout = match effective_timeout.zip(timeout_deadline) {",  # noqa: E501
                dep_marker("trusted_access_context_exit")
                + "                let remaining_timeout = match effective_timeout.zip(timeout_deadline) {",  # noqa: E501
            ),
            (
                transport,
                dep_marker("transport_call_enter")
                + "let transport_result = "
                + transport.strip()
                + ";\n"
                + dep_marker("transport_call_return")
                + "transport_result",
            ),
        ],
    )
    return hashes
