# Stage 3C: local Ollama execution

Status: **CLOSED + Local E2E Gate PASSED**, accepted and merged in
[PR #15](https://github.com/voronpap/codex-dev-hub/pull/15) on 2026-09-28
(merge `60d0318`; all Linux/Windows head checks passed).

**Execution/accounting gate passed; semantic quality not yet established.**
The citation misses remain evidence for Stage 3G, not targets for smoke-specific
prompt tuning. This slice adds an explicit
local-only entry point and a compact read/summary task, not general agent execution.
Stage 3B is closed. Groq/Gemini, paid inference, tools, vision and automatic pulls
remain unimplemented. The existing offline status server remains offline.

## Explicit configuration and scope

Run `python -m devhub.local_server --config /absolute/private/local.json` from the
installed Python 3.12 environment. The separate entry point exposes only
`devhub_local_task`; merely starting the ordinary status server cannot enable it.
Configuration is a strict `LocalConfig` JSON document:

```json
{
  "project": "example",
  "root": "/absolute/project",
  "state_root": "/absolute/private/devhub-state",
  "ledger_identity": {
    "family": "devfabric_resource_ledger",
    "format_version": 1,
    "instance_id": "REPLACE_WITH_FRESH_32_LOWERCASE_HEX",
    "authority_scope_kind": "project",
    "authority_scope_id": "example",
    "account_binding_hash": null
  },
  "approved_paths": ["docs/design.md"],
  "authoritative_paths": ["docs/design.md"],
  "ollama": {
    "endpoint": "http://127.0.0.1:11434",
    "model": "qwen2.5:14b-instruct",
    "model_digest": "REPLACE_WITH_APPROVED_64_CHARACTER_MANIFEST_SHA256",
    "context_tokens": 8192,
    "max_output_tokens": 256,
    "safety_tokens": 128,
    "timeout_seconds": 90
  }
}
```

The accepted Stage 3C result is historical. Current runtime startup additionally
requires the reviewed immutable [ledger identity](LEDGER_IDENTITY.md). Explicitly
initialize a new authority once with `local_server --initialize-ledger`; ordinary
startup will not create it. Historical pre-identity databases require a separate
future adoption operation and must not be deleted or silently replaced.

The placeholder digest must be replaced explicitly. The implementation accepts
numeric loopback HTTP addresses with explicit ports, no userinfo/path/query,
no redirects and no environment HTTP proxy. Version 0.34.2 is the qualified
Ollama version. Model name and manifest digest must match installed `/api/tags`
data; `/api/show` must confirm local completion capability and a supported
tokenizer/context. Remote model metadata is rejected. No pull/create/delete or
generic URL-fetch path exists. Checks occur before reservation and the manifest
is checked again before dispatch. A trusted local administrator must not retag
models concurrently: Ollama resolves names at send time, not through an atomic
client-held manifest lease.

The single operator controls configuration and the local Ollama daemon. Model
arguments cannot change endpoint/model/project/path approval. State lives outside
the project; source approval still requires a privacy review. Context packages
are private files under `state_root/packages`; no full context is returned to Codex.
Use one shared state root/ledger for this runtime. Separate ledgers or unrelated
Ollama clients are outside the concurrency boundary.

## Two independent measurements and second admission

The offline `utf8_byte_proxy_v1` remains unchanged and is reported as
`offline_context_proxy`. `model_input_tokens_preflight` is computed separately
from the installed model's vocabulary, merge ranks and special-token metadata.
`tokenizers==0.22.1` performs byte-level BPE with the qwen2 pretokenization pattern;
no tokenizer or model is fetched from Hugging Face. Unsupported families, BOS
behavior or incomplete byte vocabulary fail closed. Transitive package dependencies
are pinned in `uv.lock`; model weights are never package dependencies.

The adapter builds the complete Qwen ChatML prompt itself, including a fixed
system instruction and the unchanged canonical task/context payload. It counts
that exact string, adds reserved output and safety margin, and rejects overflow
before reservation. It sends `/api/generate` with `raw=true`, explicit `num_ctx`
and `num_predict`, `stream=false`, `truncate=false`, `shift=false`, temperature 0
and JSON output grammar. No implicit template, system prompt, tools or hidden
retry is added. Input containing ChatML delimiter syntax is rejected.

After completion, `actual_model_input_tokens` and `actual_model_output_tokens`
come from Ollama's `prompt_eval_count` and `eval_count`. Missing measurements remain
null. A preflight/actual input mismatch records actual usage, fails the attempt and
writes a persistent block requiring operator tokenizer verification before more
inference. The block is not an invitation to discard unresolved accounting.

## Dispatch, accounting and concurrency

```text
verify installed model -> Brain index/retrieval -> Context Builder
 -> exact model-token admission -> capability record -> Router
 -> atomic reservation -> package/model revalidation
 -> durable dispatch marker -> one HTTP inference -> complete usage settlement
 -> bounded JSON summary handoff
```

Live execution is allowed only for non-synthetic local resources and requires an
explicit ResourceController enable flag, default false. Cloud/paid non-synthetic
policies are rejected. Capability records must match policy kind and synthetic
status; transactional outbox events preserve the actual synthetic flag.

`BEGIN IMMEDIATE` admits at most one live local reservation across the ledger.
Reserved, dispatched and unknown-usage attempts occupy that slot. Startup recovery
releases expired pre-send reservations and converts expired dispatches to unknown
usage. Unknown usage remains held until explicit trusted reconciliation; a timeout
does not prove the Ollama runner stopped. No automatic expiry policy is invented.

Every request key can cause at most one send. Repeats, including after restart,
return `request_already_attempted`; this slice does not replay stored answers.
One attempt per task is admitted. Requests/input/output/total-token counters are
settled together only with a complete terminal response for the expected model.
Local counter ceilings are accounting bounds, not fabricated provider quotas or
currency prices. Invalid HTTP/JSON envelopes or missing usage retain liability.
A valid usage envelope with invalid generated JSON, wrong output shape or a length
stop settles actual usage and returns a failed attempt. These are distinct outcomes.

The only accepted output is a bounded summary DTO. The returned summary is
untrusted model output; this server never executes it. Output-schema success is
not semantic task acceptance and is not a benchmark score.

## Evidence

`tests/test_ollama.py` uses a synthetic vocabulary and controlled transport for
admission, marker-before-send, timeout, incomplete usage, invalid JSON/shape,
tokenizer mismatch, replay/restart, live concurrency, strict MCP arguments,
loopback restrictions and no redirects/retries/pulls. Existing resource recovery
and Brain/context suites remain in the full CI matrix. No CI inference requires
an installed model or external credentials.

Local verification: Ruff lint/format, mypy and offline config validation pass.
Initial full verification: Windows Python 3.12 **111 passed, 1 skipped** (existing
symlink privilege check); WSL Ubuntu 24.04 **112 passed**. A subsequent regression
also verifies that a tokenizer mismatch blocks dispatch before releasing the live slot.

The separate real Windows smoke used the already installed `qwen2.5:14b-instruct`
and the implementation captured in commit `d4b3635`; the subsequent race fix only
strengthens the mismatch failure path, covered by the regression suite. Model
manifest: `7cdf5a0187d5c58cc5d369b255592f7841d1c4696d45a8c8a9489440385b22f6`.
A direct run measured proxy 3080, preflight/actual input 919/919 and output 99.
A genuine Codex CLI MCP call traversed the full path and measured proxy 3114,
preflight/actual input 931/931 and output 49, with a settled reservation and three
transactional accounting events. See [machine-readable evidence](evidence/stage3c-local-smoke.json).

The Codex smoke's summary omitted the requested explicit revalidation wording.
Therefore it proves execution, source binding and accounting, **not semantic
acceptance of that answer**. No B-arm benchmark or token savings is claimed.
After the mismatch race fix, a second Codex smoke queried `validate_package`:
proxy **3277**, preflight/actual input **930/930**, output **86**, settled with
three live accounting events. It correctly described revalidation and hash checks
before dispatch, but omitted the requested file citation in the summary. Both
results and limitations are retained in the evidence; neither is a benchmark.
The two Stage 3A paraphrase misses and baseline fixtures remain unchanged.

## Upstream contracts

- [Ollama generate request and usage fields](https://docs.ollama.com/api/generate)
- [Ollama usage metrics](https://docs.ollama.com/api/usage)
- [Qualified server source, v0.34.2](https://github.com/ollama/ollama/blob/v0.34.2/server/routes.go)
- [Byte-level tokenizer components](https://huggingface.co/docs/tokenizers/components)
- [Codex one-run configuration overrides](https://learn.chatgpt.com/docs/config-file/config-advanced)

For the real Codex smoke, an ephemeral CLI run used command-line MCP overrides and
the existing Codex authentication. No persistent Codex configuration was changed.
Codex's own orchestration uses its normal service; only Dev Hub's delegated model
request is local. This is not an air-gapped Codex claim.
