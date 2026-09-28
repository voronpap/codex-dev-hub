# ADR-0005: Minimal V1 runtime and adapter boundary

**Status:** Proposed

**Date:** 2026-09-28

**Scope:** V1; supplements Accepted ADR-0001–0004.

## Context
A broad gateway would duplicate the required Hub resource policy before there is evidence of provider-scale demand.

## Decision
Use one Python 3.12 service, official MCP SDK, Pydantic/httpx and direct replaceable adapters. Start Groq, Gemini, Ollama; add OpenRouter free as opt-in. Paid stays disabled.

## Alternatives considered
LiteLLM library/proxy; Bifrost gateway; TypeScript/Go service.

## Why this choice
Small initial deployment and one policy owner; avoids nested retries and hidden fallback. Current evidence and full comparison are in V1_RESEARCH.

## Disadvantages and verification
We own adapter upkeep and normalization. Python throughput and gateway superiority remain unmeasured. Lock tested versions during Stage 1; inventory dependency licenses.

## Replacement and evolution
Wrap LiteLLM/Bifrost behind ProviderAdapter when upkeep or throughput warrants it; keep ResourceController authoritative.

## Evidence and implementation gate
See [research](../V1_RESEARCH.md), [proposal](../V1_TECHNICAL_PROPOSAL.md),
[contracts](../V1_CONTRACTS.md), [benchmark](../V1_BENCHMARK.md) and
[staged plan](../V1_IMPLEMENTATION_PLAN.md). Adoption is not a claim of implemented
or benchmarked behavior. Record acceptance/revision before Stage 1 coding.
