# ADR-0003: Shared Project Brain, selective context

**Status:** Accepted

## Decision
Codex and workers share durable project knowledge through Project Brain, but they do not share one giant conversation/context window.

A Context Builder supplies task-relevant context. Git remains source of truth for code.

## Consequences
Project isolation and provenance are required. Memory stores durable decisions and summaries, not complete copies of source or chat history.
