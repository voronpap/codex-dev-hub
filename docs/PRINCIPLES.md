# Principles

1. **Codex is the main orchestrator.** Dev Hub extends it; do not rebuild Codex externally without a concrete need.
2. **Efficiency beats maximum delegation.** Short tightly coupled tasks often belong in Codex.
3. **Free-first after delegation.** Default: `FREE CLOUD -> LOCAL -> PAID`, with privacy/capability/quality exceptions.
4. **Shared knowledge is not shared prompt history.** Use Project Brain + Context Builder.
5. **Git is source of truth for code.** Memory indexes and explains; it does not replace the repository.
6. **Projects are isolated.** Memory, credentials and permissions do not leak across projects.
7. **Providers are disposable.** Free tiers and APIs change; use replaceable adapters.
8. **High-level tools over schema floods.** Prefer progressive discovery.
9. **Workers get bounded tasks.** Explicit scope, context, permissions and acceptance criteria.
10. **Handoffs are compact.** Summary, changes, tests, decisions, warnings; raw logs stay outside default context.
11. **Paid resources are policy-controlled.** Budgets and approvals are explicit.
12. **Measure complexity.** Track quality, latency, quota/tokens, cost and rework.
