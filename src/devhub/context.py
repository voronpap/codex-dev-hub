"""Deterministic selection, budget accounting and revalidation over Project Brain."""

import json
import re
from collections.abc import Sequence

from devhub.brain import ProjectBrain
from devhub.brain_models import (
    BoundExcerpt,
    BrainSnapshot,
    ProjectScope,
    RetrievalHit,
    SearchResult,
    sha256,
)
from devhub.brain_store import BrainError
from devhub.context_models import (
    ContextItem,
    ContextLimits,
    ContextPackage,
    ContextPolicy,
    ContextResult,
    ContextTask,
    ExcludedSource,
    SourceBinding,
)


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def render_payload(task: ContextTask, items: Sequence[ContextItem]) -> str:
    """Exact provider-input body; future adapters must count their wrapper separately."""
    return canonical(
        {
            "task": task.model_dump(mode="json"),
            "privacy": "local_only",
            "sources_are_untrusted_data": True,
            "sources": [item.model_dump(mode="json") for item in items],
        }
    )


def estimate(task: ContextTask, items: Sequence[ContextItem]) -> int:
    # Intentionally conservative, NOT a provider token measurement or calibrated tokenizer.
    return len(render_payload(task, items).encode("utf-8"))


def package_digest(package: ContextPackage) -> str:
    return sha256(
        canonical(package.model_dump(mode="json", exclude={"package_id", "package_hash"})).encode()
    )


def effective_cap(task: ContextTask, policy: ContextPolicy, limits: ContextLimits) -> int:
    return max(
        0,
        min(
            task.token_cap,
            policy.context_token_cap,
            limits.context_window_tokens
            - limits.max_output_tokens
            - limits.extra_input_tokens
            - limits.safety_margin_tokens,
        ),
    )


def manifest_digest(snapshot: BrainSnapshot) -> str:
    return sha256(
        canonical([source.model_dump(mode="json") for source in snapshot.sources]).encode()
    )


def _identity(hit: RetrievalHit) -> tuple[str, int, int, str]:
    return hit.path, hit.start_line, hit.end_line, hit.chunk_sha256


def _tier(hit: RetrievalHit, task: ContextTask, policy: ContextPolicy) -> int:
    if hit.path in task.focus_paths or any(
        re.search(r"(?<!\w)" + re.escape(symbol) + r"(?!\w)", hit.text)
        for symbol in task.identifiers
    ):
        return 0
    return 1 if hit.path in policy.authoritative_paths else 2


def _item(hits: Sequence[RetrievalHit], text: str, tier: int) -> ContextItem:
    # Only whole LF-delimited prefix lines can be selected. Original binding survives compaction.
    lines = text.count("\n") + int(not text.endswith("\n"))
    return ContextItem(
        text=text,
        selected_sha256=sha256(text.encode()),
        sources=tuple(
            SourceBinding(
                path=hit.path,
                source_sha256=hit.source_sha256,
                original_chunk_sha256=hit.chunk_sha256,
                start_line=hit.start_line,
                original_end_line=hit.end_line,
                end_line=hit.start_line + lines - 1,
            )
            for hit in sorted(hits, key=_identity)
        ),
        selection_reason=("exact_path_or_symbol", "authoritative_path", "fts_rank")[tier],
        compacted=text != hits[0].text,
    )


def _prefixes(text: str) -> list[str]:
    ends = [index + 1 for index, char in enumerate(text) if char == "\n"]
    return [text[:end] for end in reversed(ends) if end < len(text)]


class ContextBuilder:
    def __init__(self, brain: ProjectBrain) -> None:
        self.brain = brain

    def build(
        self,
        scope: ProjectScope,
        *,
        task: ContextTask,
        snapshot_id: str,
        batches: tuple[SearchResult, ...],
        policy: ContextPolicy,
        limits: ContextLimits,
        now_ms: int,
    ) -> ContextResult:
        def insufficient(reason: str) -> ContextResult:
            return ContextResult(status="context_insufficient", missing_context=(reason,))

        if (
            type(now_ms) is not int
            or now_ms < 0
            or len(batches) > 16
            or sum(len(batch.hits) for batch in batches) > 320
        ):
            return insufficient("invalid_context_request")
        cap = effective_cap(task, policy, limits)
        if estimate(task, ()) > cap:
            return insufficient("essential_instructions_exceed_budget")
        try:
            snapshot = self.brain.current_snapshot(scope)
            if (
                snapshot is None
                or snapshot.snapshot_id != snapshot_id
                or (not self.brain.validate_snapshot(scope, snapshot_id))
            ):
                return insufficient("stale_snapshot")
            if not self.brain.validate_hits(
                scope, snapshot_id, tuple(hit for batch in batches for hit in batch.hits)
            ):
                return insufficient("invalid_or_stale_source")
            candidates: dict[tuple[str, int, int, str], tuple[RetrievalHit, int]] = {}
            for batch in batches:
                if batch.status != "ready" or batch.snapshot_id != snapshot_id:
                    return insufficient("stale_retrieval")
                seen = set()
                for hit in batch.hits:
                    if hit.scope != scope or hit.snapshot_id != snapshot_id:
                        return insufficient("source_scope_or_snapshot_mismatch")
                    identity = _identity(hit)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    rank = len(seen)
                    previous = candidates.get(identity)
                    if previous is None or rank < previous[1]:
                        candidates[identity] = hit, rank
            if len(candidates) > 128:
                return insufficient("candidate_limit")
            # Group identical text once, preserving every distinct provenance reference.
            groups: dict[str, list[RetrievalHit]] = {}
            for hit, _ in candidates.values():
                groups.setdefault(hit.chunk_sha256, []).append(hit)

            def order(hits: list[RetrievalHit]) -> tuple[int, int, tuple[str, int, int, str]]:
                return min(
                    (_tier(hit, task, policy), candidates[_identity(hit)][1], _identity(hit))
                    for hit in hits
                )

            selected: list[ContextItem] = []
            excluded: list[ExcludedSource] = []
            for hits in sorted(
                groups.values(),
                key=lambda hits: (
                    not any(hit.path in task.required_paths for hit in hits),
                    order(hits),
                ),
            ):
                hits = sorted(hits, key=_identity)
                text = hits[0].text
                if any(hit.text != text for hit in hits):
                    return insufficient("content_hash_collision")
                item = _item(hits, text, order(hits)[0])
                if estimate(task, [*selected, item]) > cap:
                    # Required sources stay complete; they must not silently lose essential content.
                    if any(hit.path in task.required_paths for hit in hits):
                        return insufficient("required_source_exceeds_budget")
                    for prefix in _prefixes(text):
                        compact = _item(hits, prefix, order(hits)[0])
                        if estimate(task, [*selected, compact]) <= cap:
                            item = compact
                            break
                    else:
                        excluded.extend(
                            ExcludedSource(
                                path=hit.path, start_line=hit.start_line, reason="budget"
                            )
                            for hit in hits
                        )
                        continue
                selected.append(item)
                if item.compacted:
                    excluded.extend(
                        ExcludedSource(path=hit.path, start_line=hit.start_line, reason="compacted")
                        for hit in hits
                    )
            selected_paths = {source.path for item in selected for source in item.sources}
            if (
                not set(task.required_paths) <= selected_paths
                or len(selected_paths) < policy.min_sources
            ):
                return insufficient("required_context_missing")
            package = ContextPackage(
                package_id="0" * 64,
                package_hash="0" * 64,
                scope=scope,
                snapshot_id=snapshot_id,
                repo_identity=snapshot.repo_identity,
                revision=snapshot.revision,
                branch=snapshot.branch,
                dirty_manifest_hash=manifest_digest(snapshot),
                created_at_ms=now_ms,
                expires_at_ms=now_ms + policy.ttl_ms,
                task=task,
                policy=policy,
                limits=limits,
                items=tuple(selected),
                excluded_sources=tuple(excluded),
                missing_context=("optional_sources_omitted_or_compacted",) if excluded else (),
                input_estimate=estimate(task, selected),
                effective_token_cap=cap,
            )
            digest = package_digest(package)
            package = package.model_copy(update={"package_id": digest, "package_hash": digest})
            if not self.validate_package(
                scope, package, task=task, policy=policy, limits=limits, now_ms=now_ms
            ):
                return insufficient("source_changed_before_seal")
            return ContextResult(status="ready", package=package)
        except BrainError:
            return insufficient("brain_binding_unavailable")

    def validate_package(
        self,
        scope: ProjectScope,
        package: ContextPackage,
        *,
        task: ContextTask,
        policy: ContextPolicy,
        limits: ContextLimits,
        now_ms: int,
    ) -> bool:
        """Call immediately before use/dispatch; hash alone is not a freshness proof."""
        if (
            type(now_ms) is not int
            or now_ms < 0
            or package.scope != scope
            or package.task != task
            or package.policy != policy
            or (package.limits != limits)
            or not package.created_at_ms <= now_ms < package.expires_at_ms
        ):
            return False
        if (
            package.package_id != package.package_hash
            or package_digest(package) != package.package_hash
        ):
            return False
        cap = effective_cap(task, policy, limits)
        if package.effective_token_cap != cap or package.input_estimate != estimate(
            task, package.items
        ):
            return False
        if (
            package.input_estimate > cap
            or package.expires_at_ms != package.created_at_ms + policy.ttl_ms
        ):
            return False
        paths = {source.path for item in package.items for source in item.sources}
        if not set(task.required_paths) <= paths or len(paths) < policy.min_sources:
            return False
        try:
            snapshot = self.brain.current_snapshot(scope)
            if (
                snapshot is None
                or snapshot.snapshot_id != package.snapshot_id
                or (
                    (
                        package.repo_identity,
                        package.revision,
                        package.branch,
                        package.dirty_manifest_hash,
                    )
                    != (
                        snapshot.repo_identity,
                        snapshot.revision,
                        snapshot.branch,
                        manifest_digest(snapshot),
                    )
                )
            ):
                return False
            excerpts = []
            for item in package.items:
                if sha256(item.text.encode()) != item.selected_sha256:
                    return False
                for source in item.sources:
                    if (
                        source.path in task.required_paths
                        and source.end_line != source.original_end_line
                    ):
                        return False
                    excerpts.append(
                        BoundExcerpt(
                            path=source.path,
                            source_sha256=source.source_sha256,
                            chunk_sha256=source.original_chunk_sha256,
                            start_line=source.start_line,
                            original_end_line=source.original_end_line,
                            end_line=source.end_line,
                            text=item.text,
                        )
                    )
            return self.brain.validate_excerpts(scope, package.snapshot_id, tuple(excerpts))
        except BrainError:
            return False
