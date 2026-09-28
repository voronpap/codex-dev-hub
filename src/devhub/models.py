"""Versioned domain DTOs. No MCP or provider SDK types cross this boundary."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Identifier = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")]
ShortText = Annotated[str, Field(min_length=1, max_length=2000)]
TokenCount = Annotated[int, Field(ge=0)]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, validate_default=True)
    schema_version: Literal[1] = 1

    @field_validator("schema_version", mode="before")
    @classmethod
    def integer_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be an integer")
        return value


class Policy(Contract):
    context_token_cap: Annotated[int, Field(ge=1, le=1_000_000)] = 8000
    summary_token_cap: Annotated[int, Field(ge=1, le=100_000)] = 1500
    max_attempts: Annotated[int, Field(ge=1, le=3)] = 3
    deadline_ms: Annotated[int, Field(ge=1, le=120_000)] = 120_000
    paid_mode: Literal["disabled"] = "disabled"


class StatusRequest(Contract):
    project_id: Identifier | None = None


class ResourceStatus(Contract):
    resource_id: Identifier
    kind: Literal["fake"] = "fake"
    availability: Literal["test_only"] = "test_only"
    synthetic: Literal[True] = True
    routable: Literal[False] = False


class CapabilityDescription(Contract):
    resource_id: Identifier
    capabilities: list[Identifier] = Field(max_length=32)
    synthetic: bool


class StatusResponse(Contract):
    request_id: Identifier
    trace_id: Identifier
    project_id: Identifier | None
    status: Literal["succeeded"] = "succeeded"
    stage: Literal["offline_stage1"] = "offline_stage1"
    summary: ShortText
    available_tools: list[Identifier] = Field(max_length=6)
    accessible_projects: list[Identifier] = Field(max_length=64)
    resources: list[ResourceStatus] = Field(max_length=1)
    policy: Policy
    warnings: list[ShortText] = Field(max_length=8)


class TaskRequest(Contract):
    """Offline contract fixture; not an exposed submission endpoint yet."""

    project_id: Identifier
    task_id: Identifier
    instructions: ShortText
    context: Annotated[str, Field(max_length=32_000)] = ""
    privacy: Literal["local_only"] = "local_only"
    max_output_tokens: Annotated[int, Field(ge=1, le=100_000)] = 1500


class Usage(Contract):
    input_tokens: TokenCount | None = None
    output_tokens: TokenCount | None = None
    cost_actual_microusd: Annotated[int, Field(ge=0)] | None = None
    measurement_source: Literal["synthetic"] = "synthetic"
    missing_reason: ShortText = "Fake adapter does not perform inference or measure model usage."


class ModelResult(Contract):
    resource_id: Identifier
    task_id: Identifier
    content: ShortText
    synthetic: Literal[True] = True
    usage: Usage = Field(default_factory=Usage)
