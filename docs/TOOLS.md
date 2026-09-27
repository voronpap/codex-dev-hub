# Tools

## Goal
Give Codex high-value capabilities without flooding its context with low-level tool schemas.

## Capability groups
- **Research/Search:** source-aware discovery and synthesis.
- **Web extraction:** URL to clean structured content.
- **Crawl/Scrape:** multi-page and structured extraction.
- **Browser:** interactive sites when HTTP extraction is insufficient.
- **Project retrieval:** code/decision/context search.
- **Documents/OCR:** PDFs, office files and images.
- **Sandbox:** bounded command/code execution.
- **Git/GitHub:** repository operations under explicit permissions.

## Candidate implementations
Research already identified SearXNG/Perplexica, Jina Reader/Search, Crawl4AI, ScrapeGraphAI, Browser Use, Docling, PaddleOCR and related projects. These are candidates, not mandatory dependencies.

## Selection rule
Start with one implementation per capability. Add alternatives only for a measured limitation.

## MCP surface
Prefer high-level actions such as `research` or `web_extract`. Internal adapters may use many services, but Codex should not need to know all of them.
