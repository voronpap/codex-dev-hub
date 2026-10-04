"""Disposable test-only observations; never edit the shipping Candidate B patch."""

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
    return hashes
