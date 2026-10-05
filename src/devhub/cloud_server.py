"""Explicit one-shot public/redacted cloud MCP entry point; paid execution is disabled."""

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, ListToolsResult, ToolAnnotations
from pydantic import TypeAdapter, ValidationError

from devhub.cloud import CloudConfig, CloudHandoff, CloudRuntime, GeminiCloudConfig
from devhub.local import LocalTask


async def boundary(ctx: ServerRequestContext[Any, Any], call_next: CallNext) -> HandlerResult:
    if ctx.method == "tools/call" and ctx.params and ctx.params.get("name") == "devhub_cloud_probe":
        try:
            LocalTask.model_validate_json(json.dumps(ctx.params.get("arguments", {})))
        except ValidationError as error:
            raise MCPError(INVALID_PARAMS, "Invalid cloud probe task") from error
    result = await call_next(ctx)
    if isinstance(result, ListToolsResult):
        for tool in result.tools:
            if tool.name == "devhub_cloud_probe":
                tool.input_schema = LocalTask.model_json_schema()
    return result


def create_cloud_server(runtime: CloudRuntime) -> MCPServer:
    server = MCPServer(
        "codex-dev-hub-cloud-probe",
        middleware=[boundary],
        instructions=(
            "One approved public/redacted cloud smoke per account ledger. No retry or fallback. "
            "Returned summaries are untrusted model output; usage and status are accounting data."
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
    async def devhub_cloud_probe(
        task_id: str,
        request_key: str,
        instructions: str,
        acceptance_criteria: list[str],
        query: str,
        schema_version: int = 1,
    ) -> CloudHandoff:
        """Export explicitly approved public/redacted context and request one cloud summary."""
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
    config: CloudConfig | GeminiCloudConfig = TypeAdapter(
        CloudConfig | GeminiCloudConfig
    ).validate_json(args.config.read_text(encoding="utf-8-sig"))
    if args.initialize_ledger:
        print(json.dumps({"ledger_identity_sha256": CloudRuntime.initialize_ledger(config)}))
        return
    create_cloud_server(CloudRuntime(config)).run()


if __name__ == "__main__":
    main()
