# ADR-0002: Free-first delegated resources

**Status:** Accepted

## Decision
After Codex decides to delegate work, the default resource preference is:

```text
FREE CLOUD -> LOCAL -> PAID
```

Privacy, required capability, measured quality or latency may override the order.

## Consequences
Quota/health tracking is a core capability. Paid escalation must be policy-controlled. Free-provider assumptions cannot be hard-coded because tiers change.
