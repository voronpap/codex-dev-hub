"""Project-scoped, content-bound retrieval DTOs. Excerpts remain untrusted data."""

import hashlib
from typing import Annotated, Literal

from pydantic import Field

from devhub.models import Contract, Identifier

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
RelativePath = Annotated[str, Field(min_length=1, max_length=512)]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ProjectScope(Contract):
    project_id: Identifier
    root_identity: Digest


class SourceRef(Contract):
    path: RelativePath
    content_sha256: Digest | None
    status: Literal["indexed", "missing", "excluded"]
    reason: Literal[
        "approved_tracked_text",
        "missing",
        "untracked",
        "ignored",
        "unsafe_path",
        "unsupported_text",
        "source_too_large",
        "overlong_line",
    ]
    trust: Literal["repository_untrusted"] = "repository_untrusted"
    sensitivity: Literal["project_private"] = "project_private"


class BrainSnapshot(Contract):
    scope: ProjectScope
    repo_identity: Digest
    branch: Annotated[str, Field(min_length=1, max_length=1024)]
    revision: Annotated[str, Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]
    index_version: Literal[1] = 1
    sources: Annotated[tuple[SourceRef, ...], Field(max_length=128)]

    @property
    def snapshot_id(self) -> str:
        # Includes approval manifest, all source hashes/statuses, project/root and Git state.
        return sha256(self.model_dump_json().encode())


class RetrievalHit(Contract):
    scope: ProjectScope
    snapshot_id: Digest
    repo_identity: Digest
    revision: str
    branch: str
    path: RelativePath
    source_sha256: Digest
    start_line: Annotated[int, Field(ge=1)]
    end_line: Annotated[int, Field(ge=1)]
    text: Annotated[str, Field(min_length=1, max_length=4000)]
    chunk_sha256: Digest
    indexed_at_ms: Annotated[int, Field(ge=0)]
    trust: Literal["repository_untrusted"] = "repository_untrusted"
    sensitivity: Literal["project_private"] = "project_private"
    reason: Literal["exact_path", "fts5_bm25"]
    score: float


class SearchResult(Contract):
    snapshot_id: Digest
    status: Literal["ready", "stale_index"]
    hits: tuple[RetrievalHit, ...] = ()


class SearchQuery(Contract):
    text: Annotated[str, Field(min_length=1, max_length=2000)]
    limit: Annotated[int, Field(ge=1, le=20)] = 5
