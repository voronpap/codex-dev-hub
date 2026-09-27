# Providers

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
