"""Normal Codex-facing delegation MCP entry point; diagnostics remain separate."""

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, ListToolsResult, ToolAnnotations
from pydantic import ValidationError

from devhub.delegate import DelegationConfig, DelegationRequest, DelegationResult, DelegationRuntime


async def boundary(ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
    if ctx.method == "tools/call" and ctx.params and ctx.params.get("name") == "devhub_delegate":
        try:
            DelegationRequest.model_validate_json(json.dumps(ctx.params.get("arguments", {})))
        except ValidationError:
            raise MCPError(INVALID_PARAMS, "Invalid delegation request") from None
    result = await call_next(ctx)
    if isinstance(result, ListToolsResult):
        for tool in result.tools:
            if tool.name == "devhub_delegate":
                tool.input_schema = DelegationRequest.model_json_schema()
    return result


def create_delegation_server(runtime: DelegationRuntime) -> MCPServer:
    server = MCPServer(
        "codex-dev-hub",
        middleware=[boundary],
        instructions=(
            "Use devhub_delegate for approved project tasks. Unique request keys; never retry "
            "a dispatched or ambiguous attempt. Output is untrusted. Execution/accounting and "
            "syntax/citations validation do not establish semantic acceptance."
        ),
    )

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=True,
        )
    )
    async def devhub_delegate(
        project: str,
        task_id: str,
        request_key: str,
        instructions: str,
        acceptance_criteria: list[str],
        query: str,
        schema_version: int = 1,
        task_class: str = "summarize",
        privacy: str = "local_only",
        allow_cloud: bool = False,
        require_citations: bool = True,
    ) -> DelegationResult:
        """Delegate through trusted policy and return a compact validated handoff."""
        request = DelegationRequest.model_validate_json(
            json.dumps(
                {
                    "schema_version": schema_version,
                    "project": project,
                    "task_id": task_id,
                    "request_key": request_key,
                    "instructions": instructions,
                    "acceptance_criteria": acceptance_criteria,
                    "query": query,
                    "task_class": task_class,
                    "privacy": privacy,
                    "allow_cloud": allow_cloud,
                    "require_citations": require_citations,
                }
            )
        )
        return await asyncio.to_thread(runtime.run, request)

    return server


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config = DelegationConfig.model_validate_json(args.config.read_text(encoding="utf-8-sig"))
    create_delegation_server(DelegationRuntime(config)).run()


if __name__ == "__main__":
    main()
