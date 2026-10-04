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

## Logging
Telemetry must redact credentials and sensitive payloads. Store enough metadata for audit without turning logs into a copy of private project content.

## Supply chain
Pin important container/package versions, track upstream sources and review updates before automatic adoption.
