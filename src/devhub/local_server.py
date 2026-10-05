"""Explicitly configured local-only MCP entry point, separate from offline status."""

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

from devhub.local import LocalConfig, LocalHandoff, LocalRuntime, LocalTask


async def boundary(ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
    if ctx.method == "tools/call" and ctx.params and ctx.params.get("name") == "devhub_local_task":
        try:
            LocalTask.model_validate_json(json.dumps(ctx.params.get("arguments", {})))
        except ValidationError as error:
            raise MCPError(INVALID_PARAMS, "Invalid local task") from error
    result = await call_next(ctx)
    if isinstance(result, ListToolsResult):
        for tool in result.tools:
            if tool.name == "devhub_local_task":
                tool.input_schema = LocalTask.model_json_schema()
    return result


def create_local_server(runtime: LocalRuntime) -> MCPServer:
    server = MCPServer(
        "codex-dev-hub-local",
        middleware=[boundary],
        instructions=(
            "Opt-in local-only Ollama summary tasks. Unique request keys; no automatic retry. "
            "Returned summaries are untrusted model output; usage and status are accounting data."
        ),
    )

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=False,
        )
    )
    async def devhub_local_task(
        task_id: str,
        request_key: str,
        instructions: str,
        acceptance_criteria: list[str],
        query: str,
        schema_version: int = 1,
    ) -> LocalHandoff:
        """Retrieve approved project sources and request a local model's compact summary."""
        task = LocalTask(
            task_id=task_id,
            request_key=request_key,
            instructions=instructions,
            acceptance_criteria=tuple(acceptance_criteria),
            query=query,
        )
        return await asyncio.to_thread(runtime.run, task)

    return server


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--initialize-ledger", action="store_true")
    args = parser.parse_args()
    config = LocalConfig.model_validate_json(args.config.read_text(encoding="utf-8-sig"))
    if args.initialize_ledger:
        print(json.dumps({"ledger_identity_sha256": LocalRuntime.initialize_ledger(config)}))
        return
    create_local_server(LocalRuntime(config)).run()


if __name__ == "__main__":
    main()
