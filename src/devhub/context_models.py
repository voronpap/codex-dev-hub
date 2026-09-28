"""Immutable context contracts. Token estimates are explicitly offline proxies."""

from typing import Annotated, Literal

from pydantic import Field

from devhub.brain_models import Digest, ProjectScope, RelativePath
from devhub.models import Contract, Identifier

Count = Annotated[int, Field(ge=0, le=1_000_000)]
Positive = Annotated[int, Field(ge=1, le=1_000_000)]


class ContextTask(Contract):
    task_id: Identifier
    instructions: Annotated[str, Field(min_length=1, max_length=64_000)]
    acceptance_criteria: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=8000)], ...],
        Field(min_length=1, max_length=16),
    ]
    focus_paths: tuple[RelativePath, ...] = Field(default=(), max_length=32)
    identifiers: tuple[Annotated[str, Field(min_length=1, max_length=100)], ...] = Field(
        default=(), max_length=32
    )
    required_paths: tuple[RelativePath, ...] = Field(default=(), max_length=32)
    token_cap: Positive = 8000


class ContextPolicy(Contract):
    version: Identifier = "context-v1"
    context_token_cap: Positive = 8000
    authoritative_paths: tuple[RelativePath, ...] = Field(default=(), max_length=32)
    min_sources: Annotated[int, Field(ge=0, le=20)] = 1
    ttl_ms: Annotated[int, Field(ge=1, le=900_000)] = 900_000


class ContextLimits(Contract):
    model_identity: Identifier = "offline"
    context_window_tokens: Positive
    max_output_tokens: Positive
    extra_input_tokens: Count = 0
    safety_margin_tokens: Count = 256


class SourceBinding(Contract):
    path: RelativePath
    source_sha256: Digest
    original_chunk_sha256: Digest
    start_line: Annotated[int, Field(ge=1)]
    original_end_line: Annotated[int, Field(ge=1)]
    end_line: Annotated[int, Field(ge=1)]
    trust: Literal["repository_untrusted"] = "repository_untrusted"
    sensitivity: Literal["project_private"] = "project_private"


class ContextItem(Contract):
    text: Annotated[str, Field(min_length=1, max_length=4000)]
    selected_sha256: Digest
    sources: Annotated[tuple[SourceBinding, ...], Field(min_length=1, max_length=128)]
    selection_reason: Literal["exact_path_or_symbol", "authoritative_path", "fts_rank"]
    compacted: bool


class ExcludedSource(Contract):
    path: RelativePath
    start_line: Annotated[int, Field(ge=1)]
    reason: Literal["budget", "compacted"]


class ContextPackage(Contract):
    package_id: Digest
    package_hash: Digest
    scope: ProjectScope
    snapshot_id: Digest
    repo_identity: Digest
    revision: str
    branch: str
    dirty_manifest_hash: Digest
    created_at_ms: Annotated[int, Field(ge=0)]
    expires_at_ms: Annotated[int, Field(ge=1)]
    privacy: Literal["local_only"] = "local_only"
    task: ContextTask
    policy: ContextPolicy
    limits: ContextLimits
    items: tuple[ContextItem, ...] = Field(max_length=128)
    excluded_sources: tuple[ExcludedSource, ...] = Field(max_length=256)
    missing_context: tuple[str, ...] = ()
    input_estimate: Count
    effective_token_cap: Count
    estimator: Literal["utf8_byte_proxy_v1"] = "utf8_byte_proxy_v1"


class ContextResult(Contract):
    status: Literal["ready", "context_insufficient"]
    package: ContextPackage | None = None
    missing_context: tuple[str, ...] = ()
