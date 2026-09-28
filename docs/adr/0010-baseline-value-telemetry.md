# ADR-0010: Baseline-first evaluation and local telemetry

**Status:** Accepted

**Date:** 2026-09-28

**Scope:** V1; supplements Accepted ADR-0001–0004.

## Context
Zero API price alone does not prove a useful delegation; Codex rework may outweigh savings.

## Decision
Structured local events and paired Codex-alone versus Hub runs, quality gates, explicit measurement provenance and weighted Delegation Value. No adaptive router before baseline.

## Alternatives considered
Provider-only token savings; unpaired demos; mandatory Langfuse/Prometheus infrastructure; opaque LLM-only grading.

## Why this choice
Measures total workflow impact including review, retries and human corrections with little infrastructure.

## Disadvantages and verification
Some Codex metrics may be unavailable; economic value then stays unknown. Small pilot samples do not prove broad superiority.

## Replacement and evolution
Keep event/export schema portable; add OTel/Langfuse when analysis demand justifies it, then revisit routing in a new ADR.

## Evidence and implementation gate
See [research](../V1_RESEARCH.md), [proposal](../V1_TECHNICAL_PROPOSAL.md),
[contracts](../V1_CONTRACTS.md), [benchmark](../V1_BENCHMARK.md) and
[staged plan](../V1_IMPLEMENTATION_PLAN.md). Accepted by the repository owner after reviewing PR #1. Acceptance does not
claim implemented or benchmarked behavior; Stage 1 is restricted to offline work.
