# Models, Gateways and Agents

## Gateways / routing
- **LiteLLM** — OpenAI-compatible multi-provider gateway; routing/retries/budgets integrations.
- **Bifrost** — gateway alternative; benchmark against LiteLLM; researched load-balancing/failover/cache capabilities.
- **Agentgateway** — broader LLM/MCP/A2A gateway direction.
- **RouteLLM** — smart strong-vs-cheap model routing candidate.
- **Headroom** — context/tool-output compression candidate; validate savings.
- **GPTCache** / gateway-native cache / Redis-Qdrant custom — semantic-cache alternatives.

## Free cloud model pool
Free tiers change and must be runtime/config data:
- Google Gemini free tier;
- Groq free plan;
- NVIDIA NIM / build.nvidia.com;
- OpenRouter `:free` endpoints/free router;
- Cloudflare Workers AI;
- Mistral developer/free allowance/credits where current;
- Hugging Face inference allowance;
- Cerebras developer/free access where current;
- SambaNova developer/free access where current;
- Z.AI/GLM free/developer endpoints where current;
- ModelScope and future verified providers;
- **FreeLLMAPI** as an aggregator/failover concept; evaluate security/maintenance vs direct adapters.

Classify offers as `FREE_PERMANENT`, `FREE_DAILY`, `FREE_MONTHLY`, `FREE_ROLLING`, `FREE_CREDITS`, `TRIAL`, `PAID`.

## Local inference
- **Ollama** — initial/simple runtime.
- **llama.cpp** — lightweight/quantized CPU+GPU/OpenAI-compatible serving.
- **SGLang** — high-performance future serving.
- **vLLM** — high-throughput alternative.
- Qwen Coder-class models are especially relevant; DeepSeek-derived/open models are candidates when hardware allows.

## Paid providers
Optional policy-controlled fallback:
- OpenAI;
- Anthropic;
- Google paid;
- DeepSeek official API;
- OpenRouter paid;
- Mistral paid;
- future providers.

Consumer subscriptions and API billing are separate unless a provider explicitly says otherwise.

## Coding/development workers
Workers, not replacements for Codex:
- **Cursor Agent / Cursor CLI** — explore CLI/ACP/MCP integration and quota behavior.
- **OpenHands** — open-source software-development worker.
- **Claude Code** — optional paid worker.
- Codex worker/parallel paths where supported.
- **Roo Code**, **Cline**, **OpenCode**, **Aider** — clients/workers/integration test targets.
- **useAgent** — workspace/agent execution idea; maturity must be validated.

Common contract: bounded task + context + scope + permissions + tests -> compact structured handoff.
