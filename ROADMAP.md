# Roadmap

## Rule
Build the smallest system that proves Dev Hub improves real Codex development.

## Phase 0 — Specification
- [x] Codex-first vision.
- [x] Free-first delegation policy.
- [x] Project Brain concept.
- [x] Worker-agent role.
- [ ] Validate current Codex MCP surface.
- [ ] Select implementation runtime.
- [ ] Define benchmark tasks and baseline.

## Phase 1 — Minimal usable Dev Hub
Build MCP server, config, provider registry, health checks, a few free-cloud adapters, local adapter, one research tool, telemetry and `devhub_status`.

Start small: Gemini free, Groq, NVIDIA NIM or OpenRouter free, plus Ollama local fallback.

## Phase 2 — Project Brain
Add project namespaces, architecture/decision storage, repo retrieval, Context Builder and compact handoffs. Pilot against existing repositories without rewriting them.

## Phase 3 — Development tools
Add based on measured demand: web extraction, documents, browser, sandbox and Git/GitHub helpers.

## Phase 4 — Worker agents
Integrate one worker first (Cursor or OpenHands): isolated workspace, bounded permissions, structured task package, tests and compact handoff. No automatic main-branch modification by default.

## Phase 5 — Smart routing
Use telemetry for quota-, task-, latency- and quality-aware routing, semantic cache where useful, and controlled paid escalation.

## Phase 6 — Extended capabilities
Candidates: vision/OCR, voice, advanced scraping, computer use, image generation, fine-tuning, workflow engines and production-facing APIs.

## Benchmark
Compare normal Codex vs Codex + Dev Hub on representative tasks: quality, Codex quota/tokens, paid cost, elapsed time, retries, human corrections and context size. Remove features whose complexity does not improve outcomes.
