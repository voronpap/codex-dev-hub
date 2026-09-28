"""Provider-neutral prepared cloud request and HTTP envelope. No credentials."""

from dataclasses import dataclass
from typing import Annotated, Any

from pydantic import Field

from devhub.brain_models import Digest
from devhub.cloud_export import ReleasedPayload
from devhub.models import Contract


@dataclass(frozen=True)
class HTTPResult:
    status: int
    headers: dict[str, str]
    body: dict[str, Any] | None
    latency_ms: int


class ModelEvidence(Contract):
    model: str
    context_tokens: Annotated[int, Field(ge=1, le=10_000_000)]
    max_output_tokens: Annotated[int, Field(ge=1, le=1_000_000)]
    metadata_hash: Digest


@dataclass(frozen=True)
class PreparedCloud:
    payload: ReleasedPayload
    body: bytes
    request_hash: str
    input_estimate: int
    model_input_tokens_preflight: int | None = None
