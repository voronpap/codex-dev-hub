"""Explicit, hash-bound release of public/redacted text; private provenance stays local."""

import hmac
import secrets
from dataclasses import dataclass, field
from typing import Annotated, Literal

from pydantic import Field

from devhub.brain_models import Digest, ProjectScope, RelativePath, sha256
from devhub.context import canonical
from devhub.context_models import ContextPackage, ContextTask, SourceBinding
from devhub.controller import Denied
from devhub.models import Contract, Identifier

_SEAL = secrets.token_bytes(32)


def _seal(digest: str, classification: str) -> bytes:
    return hmac.digest(_SEAL, canonical([digest, classification]).encode(), "sha256")


def task_release_hash(task: ContextTask) -> str:
    # Bind the full task, even though only instructions/criteria cross the boundary.
    return sha256(canonical(task.model_dump(mode="json")).encode())


class SourceRelease(Contract):
    path: RelativePath
    source_sha256: Digest
    selected_sha256: Digest
    classification: Literal["public", "redacted"]
    # Redaction is an explicit allowlist of absolute whole source lines.
    public_lines: Annotated[tuple[Annotated[int, Field(ge=1)], ...], Field(max_length=4000)] = ()
    released_sha256: Digest


class ExportPolicy(Contract):
    approval_id: Identifier
    scope: ProjectScope
    task_sha256: Digest
    releases: Annotated[tuple[SourceRelease, ...], Field(min_length=1, max_length=128)]


class ExportProvenance(Contract):
    citation: Identifier
    original: tuple[SourceBinding, ...]
    selected_sha256: Digest
    released_sha256: Digest
    classification: Literal["public", "redacted"]
    public_lines: tuple[int, ...]


class ExportReceipt(Contract):
    approval_id: Identifier
    policy_hash: Digest
    package_hash: Digest
    task_sha256: Digest
    payload_sha256: Digest
    provenance: tuple[ExportProvenance, ...]


@dataclass(frozen=True)
class ReleasedPayload:
    """Process-local export capability, not a deserializable MCP/input DTO."""

    text: str
    digest: str
    classification: Literal["public", "redacted"]
    _seal: bytes = field(repr=False)


def check_release(payload: ReleasedPayload) -> None:
    if (
        type(payload) is not ReleasedPayload
        or not hmac.compare_digest(payload._seal, _seal(payload.digest, payload.classification))
        or (
            payload.classification not in {"public", "redacted"}
            or sha256(payload.text.encode()) != payload.digest
        )
    ):
        raise Denied("cloud_export_required")


def export_context(
    package: ContextPackage, policy: ExportPolicy
) -> tuple[ReleasedPayload, ExportReceipt]:
    if package.scope != policy.scope or task_release_hash(package.task) != policy.task_sha256:
        raise Denied("cloud_task_or_project_not_approved")
    sources, provenance = [], []
    for index, item in enumerate(package.items):
        grants = []
        for source in item.sources:
            matches = [
                grant
                for grant in policy.releases
                if (grant.path, grant.source_sha256, grant.selected_sha256)
                == (source.path, source.source_sha256, item.selected_sha256)
            ]
            if len(matches) != 1:
                raise Denied("cloud_source_not_approved")
            grants.append(matches[0])
        if not grants:
            raise Denied("cloud_source_not_approved")
        outputs = []
        for source, grant in zip(item.sources, grants, strict=True):
            text = item.text
            if grant.classification == "public":
                if grant.public_lines:
                    raise Denied("invalid_public_release")
            else:
                if (
                    not grant.public_lines
                    or tuple(sorted(set(grant.public_lines))) != grant.public_lines
                ):
                    raise Denied("invalid_redaction")
                parts = text.split("\n")
                lines = [part + "\n" for part in parts[:-1]]
                if parts[-1]:
                    lines.append(parts[-1])
                if any(
                    line < source.start_line or line > source.end_line
                    for line in grant.public_lines
                ):
                    raise Denied("invalid_redaction")
                text = "".join(
                    line
                    for number, line in enumerate(lines, source.start_line)
                    if number in grant.public_lines
                )
            if not text or sha256(text.encode()) != grant.released_sha256:
                raise Denied("cloud_release_hash_mismatch")
            outputs.append(text)
        if len(set(outputs)) != 1:
            raise Denied("conflicting_cloud_releases")
        citation = f"s{index + 1}"
        classification: Literal["public", "redacted"] = (
            "redacted" if any(grant.classification == "redacted" for grant in grants) else "public"
        )
        sources.append({"citation": citation, "text": outputs[0]})
        for source, grant in zip(item.sources, grants, strict=True):
            provenance.append(
                ExportProvenance(
                    citation=citation,
                    original=(source,),
                    selected_sha256=item.selected_sha256,
                    released_sha256=sha256(outputs[0].encode()),
                    classification=grant.classification,
                    public_lines=grant.public_lines,
                )
            )
    if not sources:
        raise Denied("cloud_context_empty")
    text = canonical(
        {
            "instructions": package.task.instructions,
            "acceptance_criteria": package.task.acceptance_criteria,
            "sources_are_untrusted_data": True,
            "sources": sources,
        }
    )
    digest = sha256(text.encode())
    classification = (
        "redacted" if any(p.classification == "redacted" for p in provenance) else "public"
    )
    return ReleasedPayload(
        text,
        digest,
        classification,
        _seal(digest, classification),
    ), ExportReceipt(
        approval_id=policy.approval_id,
        policy_hash=sha256(canonical(policy.model_dump(mode="json")).encode()),
        package_hash=package.package_hash,
        task_sha256=policy.task_sha256,
        payload_sha256=digest,
        provenance=tuple(provenance),
    )
