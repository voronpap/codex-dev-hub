# Security

## Trust model
DevFabric can touch source code, external providers, credentials and executable environments. Default to least privilege.

## Rules
- Never place secrets in Project Brain or prompts when avoidable.
- Provider credentials belong in environment/secret storage.
- Project permissions are isolated.
- Cross-project context access is denied by default.
- Remote/free providers have explicit privacy/data-use classifications.
- Sensitive/private tasks may force local execution.
- Worker agents receive only required filesystem/tool permissions.
- Risky code runs in a sandbox/worktree/container.
- Production access is disabled by default.
- Destructive Git/GitHub actions require explicit policy.
- Paid escalation obeys budget/approval policy.
- A state path does not establish ledger authority. Open resource ledgers only after
  exact immutable identity validation; missing, foreign, legacy-unclaimed and
  mismatched databases fail closed before domain migration.
- A qualification evidence path does not establish execution authority. New Stage 3G
  execution accepts one final `qualification_manifest_id`, re-hashes its fixed
  context/receipt set, requires one context and environment identity throughout, and
  derives runtime components from that verified authority.
- The delegated Python runtime is a reviewed wheel in a dedicated non-editable
  environment. Isolated invocation, interpreter/wheel/lock hashes, module origin and
  installed RECORD inventory are verified before future task exposure.

## Logging
Telemetry must redact credentials and sensitive payloads. Store enough metadata for audit without turning logs into a copy of private project content.

## Supply chain
Pin important container/package versions, track upstream sources and review updates before automatic adoption.
