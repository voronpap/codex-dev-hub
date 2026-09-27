# Vision

## Mission
Build a **Codex-first development extension** that makes software development more efficient by giving Codex access to inexpensive compute, reusable project context, research capabilities, and specialist workers without replacing Codex as the primary orchestrator.

## Problem
A strong coding agent can do most work itself, but broad research, large-document reduction, repetitive extraction, repository indexing and independent subtasks can waste scarce context or premium quota. Free cloud tiers, local models and other agents exist, but manual switching fragments context and configuration.

## Product thesis
Codex decides what work matters. Dev Hub helps execute supporting work efficiently.

```text
Developer -> Codex -> Dev Hub -> capability/provider/worker
                   <- compact result/handoff <-
```

## Non-goals
Dev Hub is not a second Codex, a giant shared prompt, a mandatory runtime dependency for applications, a provider-specific product, or a reason to delegate trivial work.

## Design priorities
1. Codex-first.
2. Efficiency-first.
3. Free-first resources.
4. Local control/fallback.
5. Paid by explicit policy.
6. Shared context with selective delivery.
7. Replaceable adapters.
8. Git as source of truth.
9. Safe/sandboxed execution.
10. Observable routing and outcomes.

## Long-term direction
Selected capabilities may later be exposed to applications built with Dev Hub, but the first product is a **development module for Codex**.

## Desired experience
The developer works normally in Codex. Codex can call Dev Hub to research, search/extract the web, use free/local models for bounded work, retrieve project decisions, parse documents, run sandboxed work or delegate isolated coding tasks. Dev Hub returns concise structured results, not full worker transcripts.
