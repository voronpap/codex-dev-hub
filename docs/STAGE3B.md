# Stage 3B: Context Builder

Status: **CLOSED**, accepted and merged in [PR #13](https://github.com/voronpap/codex-dev-hub/pull/13)
on 2026-09-28 (merge `30f0288`; all Linux/Windows head checks passed). This is an internal,
offline Python API over Stage 3A Brain. MCP still exposes only status. No provider,
network request, embedding service or task-summary ingestion is added.

## Selection contract

`ContextBuilder.build(scope, task, snapshot_id, batches, policy, limits, now_ms)`
accepts strict frozen DTOs. The caller supplies Brain retrieval batches, complete
task instructions and acceptance criteria, trusted authority paths and explicit
model limits. `ContextPolicy.context_token_cap` and `ContextTask.token_cap` default
to 8,000; they are configurable policy values. Existing configuration must be
mapped to these inputs by the future delegation integration.

Every candidate is revalidated against the current Brain snapshot. Stale,
cross-project or fabricated hits fail the request with `context_insufficient` and
no package. Selection first protects explicitly required paths, then ranks:

1. Explicit focus path or exact identifier in the excerpt.
2. A path explicitly designated authoritative by trusted policy.
3. The hit's position within its retrieval result.
4. Stable path, line range and content hash as tie breakers.

FTS5 scores are never compared across queries. Repeated hits use their best
within-result rank; repeated queries do not add votes. Identical excerpt text is
rendered once with all distinct provenance references. Provenance itself consumes
budget. Authority affects selection priority, not trust: all source text remains
`repository_untrusted` and `project_private`, with `local_only` package privacy.

`required_paths` requires a supplied excerpt for each named path and preserves
every retrieved chunk for that path in full. It does **not** assert whole-file
coverage; callers must retrieve the needed sections. Instructions and acceptance
criteria are always complete. Optional excerpts may be shortened only to whole
LF-delimited prefix lines; omissions and compaction are explicit metadata.
Original source/chunk hashes and original/selected line ranges survive compaction.
No generated summary replaces source evidence. Missing required paths, too few
sources or an oversized required excerpt produce explicit `context_insufficient`.

## Budget and exact payload

`render_payload(task, items)` is the canonical JSON provider-input body, including
instructions, acceptance criteria, source text and provenance. Envelope metadata
not in that body is not intended for the model. Future adapters must preserve this
body and account separately for system prompts, tool schemas and chat wrappers.

The effective cap is the nonnegative minimum of:

```text
task cap
policy cap
model context window - maximum output - extra input - safety margin
```

Stage 3B uses `utf8_byte_proxy_v1`: one UTF-8 byte of the exact rendered body counts
as one estimated input unit, including multibyte text and JSON overhead. It is an
offline conservative proxy, **not measured model tokens or a universal tokenizer
bound**. Packages label the estimator and record the estimate and cap. A package
never exceeds that estimated cap. Stage 3C must validate the complete request with
the chosen model's tokenizer/context accounting before dispatch; this offline
proof alone does not authorize an 8k-token provider request or claim savings.

## Sealing and use

The package binds project/root, repository, revision/branch, complete source
manifest, snapshot, task, policy, model limits, selected excerpts, exclusions,
privacy and creation/expiry times. Canonical SHA-256 covers the entire envelope
except its two identical ID/hash fields. Identical inputs and `now_ms` yield an
identical package, independent of query-batch order. Different creation times
deliberately produce different hashes. Nested DTOs and sequences are immutable.

Before returning a package, the builder revalidates every selected excerpt against
its original indexed chunk and current source hashes. Batch validation shares a
source snapshot check and DB transaction without dropping per-source checks.
`validate_package(scope, package, task=..., policy=..., limits=..., now_ms=...)`
must be called again immediately before use/dispatch. It checks expected bindings,
expiry, hash, budget and every excerpt, including compacted prefixes. A hash is
neither authorization nor permanent freshness; filesystem validation remains a
point-in-time check. Future resource reservations must bind the sealed package hash.

## Evidence and limits

`tests/test_context.py` exercises deterministic immutable serialization, score
independence, ranking, deduplication, exact payload accounting, essential overflow,
compaction with provenance, required-source overflow, changed sources before
build/during sealing/after build, project isolation, expiry, expected-contract
changes, fabricated text with a recomputed hash and explicit missing context.

Local verification on Python 3.12: Windows **92 passed, 1 skipped** (the existing
symlink-privilege test); WSL Ubuntu 24.04 **93 passed**. Ruff formatting/lint,
mypy and offline configuration validation pass. Twelve context cases are included
in those totals; existing Brain retrieval and resource-core regressions still pass.

Stage 3A's frozen retrieval fixture, oracle and evidence are unchanged, including
the two paraphrase misses and 10/12 recall. No fixture-specific query expansion is
introduced. Query rewriting and summary ingestion remain future improvements.
Ollama and the local end-to-end smoke remain the next gate before cloud adapters.

## Stage 3C acceptance gate

The owner accepted 3B with these requirements for the next slice:

1. Only explicitly allowlisted local Ollama endpoints and installed models; no automatic pull.
2. Verify model identity and capabilities before reservation.
3. Retain `offline_context_proxy` separately from `actual_model_input_tokens`.
4. Perform a second, model-specific admission check on the complete real request:
   system prompt, template/wrapper, task, context, any tool schemas, reserved output
   and safety margin. Byte-proxy fit alone cannot authorize dispatch.
5. Persist the dispatch marker before HTTP send; a timeout after send means `unknown_usage`.
6. Normalize actual Ollama usage and settle only with complete usage data.
7. Invalid JSON/output shape fails the attempt but does not erase usage accounting.
8. Default to one inference at a time.
9. Prove the real local Codex-to-MCP-to-Brain/Context-to-Router-to-Controller-to-Ollama
   path, settlement/telemetry and compact handoff before implementing Groq.
