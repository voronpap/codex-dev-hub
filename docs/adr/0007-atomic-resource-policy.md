# ADR-0007: Atomic resource admission and deterministic routing

**Status:** Proposed

**Date:** 2026-09-28

**Scope:** V1; supplements Accepted ADR-0001–0004.

## Context
Free-first prose alone does not prevent concurrent overspend, account-pool collisions or repeated bad delegation.

## Decision
Reserve quota and maximum cost atomically in SQLite before each attempt. Unknown usage retains liability. Filter privacy/capability/quality before free-local-paid ranking. Core alone owns retry budgets.

## Alternatives considered
Best-effort counters; gateway-only budgets; optimistic release on timeout; learned routing immediately.

## Why this choice
Makes decisions explainable and testable while preserving ADR-0002 exceptions.

## Disadvantages and verification
Conservative admission may underuse quotas. External account use can defeat local estimates; unknown quota/reset cannot become unlimited.

## Replacement and evolution
Move ledger to transactional PostgreSQL if concurrent writers require it; learned ranking requires baseline evidence and a later ADR.

## Evidence and implementation gate
See [research](../V1_RESEARCH.md), [proposal](../V1_TECHNICAL_PROPOSAL.md),
[contracts](../V1_CONTRACTS.md), [benchmark](../V1_BENCHMARK.md) and
[staged plan](../V1_IMPLEMENTATION_PLAN.md). Adoption is not a claim of implemented
or benchmarked behavior. Record acceptance/revision before Stage 1 coding.
