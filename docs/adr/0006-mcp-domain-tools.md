# ADR-0006: Six high-level MCP tools

**Status:** Proposed

**Date:** 2026-09-28

**Scope:** V1; supplements Accepted ADR-0001–0004.

## Context
Existing documents list differing candidate names and lack lifecycle contracts.

## Decision
Use devhub_status/delegate/research/context/remember/sandbox with versioned domain envelopes. Stdio first, durable submit/poll/cancel, no provider schemas exposed.

## Alternatives considered
Provider-specific tools; a second agent UI; Codex-as-server orchestration; immediate remote HTTP service.

## Why this choice
Keeps Codex in control, limits schema overhead and avoids experimental async dependencies.

## Disadvantages and verification
Polling adds calls; local identity boundaries still require enforcement. Codex SDK-client interoperability must be proven in Stage 1.

## Replacement and evolution
Add authenticated Streamable HTTP without changing tool contracts; introduce a new schema version for breaking changes.

## Evidence and implementation gate
See [research](../V1_RESEARCH.md), [proposal](../V1_TECHNICAL_PROPOSAL.md),
[contracts](../V1_CONTRACTS.md), [benchmark](../V1_BENCHMARK.md) and
[staged plan](../V1_IMPLEMENTATION_PLAN.md). Adoption is not a claim of implemented
or benchmarked behavior. Record acceptance/revision before Stage 1 coding.
