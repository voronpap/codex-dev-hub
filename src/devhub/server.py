"""The Stage 1 MCP surface deliberately exposes status only."""

from typing import Any, Literal
from uuid import uuid4

from mcp.server import MCPServer
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, ListToolsResult, ToolAnnotations
from pydantic import ValidationError

from devhub import __version__
from devhub.adapters import FakeAdapter
from devhub.config import HubConfig
from devhub.models import Identifier, StatusRequest, StatusResponse


async def status_contract_boundary(
    ctx: ServerRequestContext[Any, Any], call_next: CallNext
) -> HandlerResult:
    # SDK function signatures otherwise ignore unknown top-level arguments.
    if ctx.method == "tools/call" and ctx.params and ctx.params.get("name") == "devhub_status":
        try:
            StatusRequest.model_validate(ctx.params.get("arguments", {}))
        except ValidationError as exc:
            raise MCPError(INVALID_PARAMS, "Invalid status request") from exc
    result = await call_next(ctx)
    if isinstance(result, ListToolsResult):
        for tool in result.tools:
            if tool.name == "devhub_status":
                tool.input_schema = StatusRequest.model_json_schema()
    return result


def create_server(config: HubConfig) -> MCPServer:
    server = MCPServer(
        "codex-dev-hub",
        version=__version__,
        instructions="Offline Stage 1: status only. Fake resources are synthetic, not routable.",
        middleware=[status_contract_boundary],
    )

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
        ),
    )
    async def devhub_status(
        schema_version: Literal[1] = 1, project_id: Identifier | None = None
    ) -> StatusResponse:
        """Report offline capabilities for locally registered projects, without inference."""
        request = StatusRequest(schema_version=schema_version, project_id=project_id)
        if request.project_id is not None and request.project_id not in config.projects:
            raise ToolError("policy_denied: project is not accessible")
        resources = [await FakeAdapter().status()] if config.fake.enabled else []
        return StatusResponse(
            request_id=uuid4().hex,
            trace_id=uuid4().hex,
            project_id=request.project_id,
            summary="Offline skeleton ready. Inference, routing, research and execution disabled.",
            available_tools=["devhub_status"],
            accessible_projects=(
                [request.project_id] if request.project_id else sorted(config.projects)
            ),
            resources=resources,
            policy=config.policy,
            warnings=["Provider usage and benchmark savings have not been measured."],
        )

    return server
