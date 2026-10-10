"""Normal Codex-facing delegation MCP entry point; diagnostics remain separate."""

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, CallToolResult, ListToolsResult, TextContent, ToolAnnotations
from pydantic import ValidationError

from devhub.delegate import DelegationConfig, DelegationRequest, DelegationResult, DelegationRuntime
from devhub.local import LocalConfig
from devhub.ollama_transport import OllamaBridgeAuthorityV1, validate_ollama_bridge
from devhub.usage import derive_usage
from devhub.usage_render import render_footer


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
    async def response_boundary(
        ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        result = await boundary(ctx, call_next)
        config = getattr(runtime, "config", None)
        mode = config.telemetry_footer if isinstance(config, DelegationConfig) else "off"
        if (
            mode == "off"
            or ctx.method != "tools/call"
            or not ctx.params
            or ctx.params.get("name") != "devhub_delegate"
        ):
            return result
        # SDK middleware may receive an already serialized wire dictionary.
        wire = (
            result
            if isinstance(result, dict)
            else (
                result.model_dump(mode="json", by_alias=True)
                if isinstance(result, CallToolResult)
                else None
            )
        )
        if wire is None or wire.get("isError") or wire.get("structuredContent") is None:
            return result
        handoff = DelegationResult.model_validate_json(json.dumps(wire["structuredContent"]))
        summary = derive_usage(handoff)
        return {
            **wire,
            "content": [
                *wire.get("content", []),
                TextContent(type="text", text=render_footer(summary, mode)).model_dump(
                    mode="json", by_alias=True
                ),
            ],
            "_meta": {
                **(wire.get("_meta") or {}),
                "devfabric_usage": summary.model_dump(mode="json"),
            },
        }

    server = MCPServer(
        "codex-dev-hub",
        middleware=[response_boundary],
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
    parser.add_argument(
        "--ollama-bridge-authority",
        type=Path,
        help="Trusted host-owned Stage 3G bridge authority; never sourced from an MCP request",
    )
    parser.add_argument(
        "--initialize-ledger",
        action="store_true",
        help="Initialize the configured ledger identity and exit; never starts MCP",
    )
    args = parser.parse_args()
    config = DelegationConfig.model_validate_json(args.config.read_text(encoding="utf-8-sig"))
    bridge = None
    if args.ollama_bridge_authority is not None:
        bridge = OllamaBridgeAuthorityV1.model_validate_json(
            args.ollama_bridge_authority.read_bytes()
        )
        if not any(isinstance(profile.config, LocalConfig) for profile in config.profiles):
            parser.error("Ollama bridge authority requires an exact local profile")
        validate_ollama_bridge(bridge)
    if args.initialize_ledger:
        identity_hash = DelegationRuntime.initialize_ledger(config)
        print(json.dumps({"ledger_identity_sha256": identity_hash}, sort_keys=True))
        return
    create_delegation_server(DelegationRuntime(config, ollama_bridge=bridge)).run()


if __name__ == "__main__":
    main()
