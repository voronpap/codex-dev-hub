# DevFabric naming and branding migration

## Terminology

| Role | Name |
| --- | --- |
| Public project name | DevFabric |
| Current GitHub repository | `voronpap/codex-dev-hub` |
| Historical/internal prefix | `devhub` |
| Current primary integration | Codex |
| Future client boundary | Agent Adapter / Client Adapter |
| Model-resource boundary | Provider Adapter |

DevFabric is the public project name. Some internal identifiers retain the
historical `devhub` naming for compatibility and evidence stability.
Cursor and Claude integrations are planned, not implemented. Codex remains the
first and deepest integration; DevFabric itself is not a separate coding agent.

## Branding migration report

This documentation-only change updates README, VISION, ARCHITECTURE, ROADMAP and
the catalog entry page, security/context principles and Codex integration overview. CI policy retains the README maintenance rule and adds
new real coding-agent integrations as an update trigger. The README refresh is
PR #35; this branding PR is stacked on it, independently of runtime proof #34.

Search terms: `Codex Dev Hub`, `codex-dev-hub`, `Dev Hub`, `Codex-first`
(case-insensitive, tracked UTF-8 text; counts are matching lines before this
report was added, not unique word occurrences).

| Occurrence class | Matching lines retained | Action |
| --- | ---: | --- |
| Public-facing pages / compatibility notes | 1 | Public product wording updated; exact repository/compatibility names retained |
| Historical / frozen design and evidence | 62 | Retain; no blanket replacement |
| Retained supporting design / research references | 8 | Retain; no blanket replacement |
| Technical / compatibility-sensitive | 14 | Retain; no blanket replacement |

Classification by role:

- **A — public branding:** top-level positioning uses DevFabric. Architecture and
  roadmap distinguish current Codex from planned Cursor/Claude clients.
- **B — technical identifiers:** repository URLs, `pyproject.toml`, `uv.lock`,
  `src/devhub`, imports, CLI `devhub`, configuration keys and commands stay unchanged.
- **C — historical records:** `docs/STAGE*`, `docs/V1*`, ADRs, evidence, frozen
  benchmark packets/oracles and original titles/quotes retain their historical
  names. Supporting research/runbooks retain their original design terminology;
  this does not override the public naming policy.
- **D — compatibility-sensitive:** `devhub_delegate`, MCP server/canonical names,
  protocol/session IDs, hashes, state/ledger paths and schema fields remain exact.
  In code/tests, retaining old display strings also avoids unreviewed behavior or
  snapshot changes; this PR touches no runtime source.

## Migration boundaries

No GitHub repository rename, Python namespace/package migration, CLI rename,
MCP alias, database migration or protocol revision is authorized by branding.
Stage 3G remains OPEN and execution_ready=false; no new capability or benchmark
result is established. Historical evidence must not be rewritten to the new name.

A separate future review may consider `codex-dev-hub` → `devfabric`, then a
versioned `devhub` → `devfabric` Python/package/CLI migration with compatibility
support. Any future MCP name should use a reviewed compatibility alias rather
than silently replacing `devhub_delegate`; exact origin/schema/protocol bindings
need independent security review. None of these migrations is implemented here.
