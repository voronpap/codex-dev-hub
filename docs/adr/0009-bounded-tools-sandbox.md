# ADR-0009: Bounded research and separate sandbox executor

**Status:** Accepted

**Date:** 2026-09-28

**Scope:** V1; supplements Accepted ADR-0001–0004.

## Context
Web content and worker code are untrusted, and a worktree is not execution isolation.

## Decision
One quota-controlled search adapter and safe extraction; separate least-privilege executor for disposable rootless Docker jobs. No daemon socket in core/workers. Model workers return artifacts; Codex integrates.

## Alternatives considered
SearXNG/crawler/browser stack immediately; host-shell execution; VM sandboxes for every task; Cursor/OpenHands as primary orchestrators.

## Why this choice
Meets required V1 tool boundaries without a large service bundle or competing control plane.

## Disadvantages and verification
Search sends queries externally; cloud query privacy must be explicit. Containers share a kernel and are not hostile multi-tenant isolation. Windows requires a tested Linux engine path.

## Replacement and evolution
Swap ToolAdapter for SearXNG or another search provider; use VM executor for stronger isolation; external workers adopt the same bounded contract.

## Evidence and implementation gate
See [research](../V1_RESEARCH.md), [proposal](../V1_TECHNICAL_PROPOSAL.md),
[contracts](../V1_CONTRACTS.md), [benchmark](../V1_BENCHMARK.md) and
[staged plan](../V1_IMPLEMENTATION_PLAN.md). Accepted by the repository owner after reviewing PR #1. Acceptance does not
claim implemented or benchmarked behavior; Stage 1 is restricted to offline work.
