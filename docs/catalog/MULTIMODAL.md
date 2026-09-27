# Multimodal Catalog

## Documents / OCR
- **Docling** — strong PDF/Office/layout/table structured parsing candidate.
- **Microsoft MarkItDown** — lightweight first-pass conversion to Markdown.
- **MinerU** — advanced PDF/document parsing.
- **PaddleOCR / PaddleOCR-VL** — multilingual OCR/document vision.

Suggested escalation: normal parser/MarkItDown -> Docling -> OCR/VLM.

## Vision
- **Qwen-VL / Qwen3-VL** family — local/open image/document reasoning candidate.
- Gemini free vision — cloud free candidate where privacy policy allows.
- Cloudflare/NVIDIA/OpenRouter vision models — dynamic free-pool possibilities.

Potential development uses: screenshots, diagrams, UI inspection, hardware/components and document fallback.

## Speech-to-text
- **faster-whisper** — server local STT.
- **whisper.cpp** — lightweight portable local STT.
- **Groq Whisper** — free-cloud STT candidate.
- Cloudflare speech models — additional cloud candidate.

## Text-to-speech
- **Voicebox** — OpenAI-compatible STT/TTS wrapper concept.
- **Kokoro**, **Piper** — local lightweight TTS.
- **OpenSpeakers** — multi-engine aggregation.
- Other researched families: Qwen TTS, F5-TTS, Chatterbox, CosyVoice, Fish Speech, Dia, Orpheus, Parler.

## Image generation
- **ComfyUI** — primary workflow-engine candidate.
Potential reusable workflows: diagrams, UI mockups, product images, inpaint, background removal, upscale.

## Video understanding
Potential pipeline: FFmpeg scene/keyframes -> VLM; audio -> Whisper; timestamped fusion -> LLM. Useful later for tutorials/demo/reel analysis.

Multimodal is optional for development-first V1; cataloged now so the architecture does not block it later.
