# ADR-0008: Git-backed Project Brain with SQLite and lexical retrieval

**Status:** Proposed

**Date:** 2026-09-28

**Scope:** V1; supplements Accepted ADR-0001–0004.

## Context
The Brain needs provenance and isolation, but no measured need yet exists for graph/vector infrastructure.

## Decision
Git is source of truth; per-project SQLite/FTS5 stores decisions, summaries, references and rebuildable excerpts. Context packages are minimal, revision/hash-bound and privacy checked.

## Alternatives considered
PostgreSQL + Qdrant; Graphiti/Mem0/Cognee; whole-repo prompts; tree-sitter first.

## Why this choice
No separate DB service, clear invalidation and low operations burden for a single host.

## Disadvantages and verification
Lexical search misses conceptual matches; SQLite single-writer/local-disk constraints limit scaling. Explicit authority is needed for decision conflicts.

## Replacement and evolution
Export versioned records; replace Retriever or BrainStore independently. Introduce AST/vector/graph only after recall/value measurements.

## Evidence and implementation gate
See [research](../V1_RESEARCH.md), [proposal](../V1_TECHNICAL_PROPOSAL.md),
[contracts](../V1_CONTRACTS.md), [benchmark](../V1_BENCHMARK.md) and
[staged plan](../V1_IMPLEMENTATION_PLAN.md). Adoption is not a claim of implemented
or benchmarked behavior. Record acceptance/revision before Stage 1 coding.
