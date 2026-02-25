# 🐕 VulnHound

**AI-powered smart contract auditing agent with historical exploit knowledge.**

VulnHound combines static analysis, 550+ historical DeFi exploit patterns, and LLM reasoning to find vulnerabilities in smart contract repositories. It doesn't just run pattern matching — it understands how past exploits worked and looks for similar compositions in your code.

## Architecture

```
Repo → Parse → Static Analysis → RAG (Exploit KB) → LLM Multi-Pass → Validate → PoC → Report
```

7-stage pipeline. Each stage enriches context for the next.

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/vulnhound.git
cd vulnhound

# Setup
cp .env.example .env
# Fill in your API keys (Anthropic, OpenAI, RPC URLs)

# Install
pip install -e ".[dev]"

# Ingest exploit knowledge base
vulnhound kb ingest

# Run an audit
vulnhound audit https://github.com/user/defi-protocol
vulnhound audit ./contracts --skip-poc
```

## Features

- **Historical Exploit RAG** — 550+ DeFi exploits from DeFiHackLabs, Solodit, Rekt News
- **Multi-tool Static Analysis** — Slither + Aderyn + Mythril + Semgrep
- **Multi-pass LLM Reasoning** — Function audit → Cross-contract → Economic/Business logic
- **Automatic PoC Generation** — Foundry tests that prove the vulnerability is real
- **Cross-chain Specialization** — LayerZero, Stargate, bridge vulnerability patterns
- **Professional Reports** — Markdown/PDF with severity, impact, PoC, and historical references

## Project Structure

```
vulnhound/
├── src/
│   ├── ingester/          # Stage 1: Repo parsing
│   ├── analyzers/         # Stage 2: Static analysis
│   ├── knowledge_base/    # Stage 3: Exploit KB + RAG
│   ├── llm/               # Stage 4: LLM reasoning
│   ├── validator/         # Stage 5: Finding validation
│   ├── poc_gen/           # Stage 6: PoC generation
│   ├── reporter/          # Stage 7: Report generation
│   ├── api/               # FastAPI server
│   ├── cli/               # CLI interface
│   ├── models.py          # Core data models
│   └── config.py          # Configuration
├── knowledge/             # Raw exploit data
├── tests/                 # Unit + integration + benchmarks
├── docker/                # Docker setup
└── pyproject.toml
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Agent Framework | Python, LangGraph, Claude Tool-Use |
| LLM | Claude Sonnet 4 (primary), Opus 4.5 (complex), Haiku 4.5 (fast) |
| Vector DB | ChromaDB (dev), Pinecone (prod) |
| Embeddings | text-embedding-3-large |
| Static Analysis | Slither, Aderyn, Mythril, Semgrep |
| Smart Contracts | Foundry (forge, anvil, cast) |
| API | FastAPI + WebSocket |

## Build Roadmap

| Phase | Weeks | Focus | Status |
|-------|-------|-------|--------|
| 1 | 1-2 | Foundation + KB Ingestion | 🔨 In Progress |
| 2 | 3-4 | Static Analysis + Context Builder | ⏳ |
| 3 | 5-7 | LLM Reasoning Engine | ⏳ |
| 4 | 8-9 | PoC Generation + Reports | ⏳ |
| 5 | 10-12 | Benchmarking + Cross-Chain | ⏳ |
| 6 | 13+ | Productionize | ⏳ |

## License

MIT
