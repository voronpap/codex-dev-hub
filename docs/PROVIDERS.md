# Providers

Current evidence and V1 selection: [research](V1_RESEARCH.md). Runtime offer classes
are `CORE_FREE`, `DEV_FREE`, `EVAL_FREE`, `TINY_FREE`, `FREE_CREDITS`,
`TRIAL_CREDIT`, `VERIFY`, `PAID`; renewal and expiry are separate fields.
The catalog's earlier replenishment labels remain research history, not runtime
enums. Proposed adapters: Groq, Gemini, Ollama, then opt-in OpenRouter free;
NVIDIA stays an evaluation candidate. See [contracts](V1_CONTRACTS.md).

## Contract
Projects and Codex-facing tools contain no provider-specific routing logic. Providers implement adapters.

## Classes
### Free cloud
Initial research pool: Gemini, Groq, NVIDIA NIM, OpenRouter free, Cloudflare Workers AI, plus verified Mistral/Hugging Face/other tiers.

### Local
Ollama first; llama.cpp/SGLang/vLLM are future alternatives when useful.

### Paid
Optional fallback: OpenAI, Anthropic, DeepSeek official, Google paid, OpenRouter paid and others.

## Provider state
Each adapter should declare supported modalities/tools, context/output limits, privacy classification, health, latency, rate/quota state when available and pricing/free-tier class.

## Rule
A provider name is never an architectural dependency. Free tiers change; adapters must be easy to add, disable or replace.
