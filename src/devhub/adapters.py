"""Replaceable domain ports and an explicitly synthetic offline adapter."""

from typing import Protocol

from devhub.models import CapabilityDescription, ModelResult, ResourceStatus, TaskRequest, Usage


class ProviderAdapter(Protocol):
    async def capabilities(self) -> CapabilityDescription: ...

    async def execute(self, request: TaskRequest) -> ModelResult: ...


class ToolAdapter(Protocol):
    """Reserved port, independent of Tavily/Jina/SearXNG or MCP types.

    Admission tickets and capability-specific DTOs arrive with the resource core.
    There is intentionally no search implementation in Stage 1.
    """

    async def capabilities(self) -> CapabilityDescription: ...


class FakeAdapter:
    async def status(self) -> ResourceStatus:
        return ResourceStatus(resource_id="fake")

    async def capabilities(self) -> CapabilityDescription:
        return CapabilityDescription(resource_id="fake", capabilities=[], synthetic=True)

    async def execute(self, request: TaskRequest) -> ModelResult:
        # Do not echo arbitrary task content into logs or simulate successful reasoning.
        return ModelResult(
            resource_id="fake",
            task_id=request.task_id,
            content="Synthetic fixture response; no model was called and no task was solved.",
            usage=Usage(),
        )
