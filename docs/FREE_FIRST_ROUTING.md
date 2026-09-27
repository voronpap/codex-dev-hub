# Free-First Routing

## Two decisions
1. Should Codex delegate?
2. If yes, where should it run?

Free-first applies to decision 2.

## Default
```text
FREE CLOUD -> LOCAL -> PAID
```

Change order for privacy, missing capability, latency or measured quality.

## Track per provider
Capabilities, free-tier type, remaining quota when knowable, reset time, rate limits, recent 429/5xx rate, latency, privacy/data-use class and observed task quality.

## Candidate free pool
Gemini free tier, Groq, NVIDIA NIM, OpenRouter free endpoints, Cloudflare Workers AI, Jina services and other verified tiers.

Limits are runtime/config data, not permanent documentation.

## Local
Local inference gives privacy, predictable availability and no token billing, but may lose on quality/latency. Measure it.

## Paid
Policies: disabled; automatic below budget; approval above threshold; or explicitly requested only. Never silently turn a free workflow into an expensive one.
