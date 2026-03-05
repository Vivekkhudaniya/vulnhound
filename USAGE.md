# VulnHound — Usage Guide

A step-by-step manual for running the AI smart contract auditing agent from scratch.

---

## Prerequisites

Install these before anything else.

### 1. Python 3.11+

```bash
python --version   # must be 3.11 or higher
```

Download from https://python.org if needed.

### 2. Git

```bash
git --version
```

### 3. Slither (static analyser)

Slither requires Python and solc. Install it globally:

```bash
pip install slither-analyzer
```

Verify:

```bash
slither --version
```

### 4. Aderyn (static analyser)

Aderyn is a Rust binary from Cyfrin. Install via their installer:

```bash
# Option A — via cargo (if you have Rust)
cargo install aderyn

# Option B — download prebuilt binary from:
# https://github.com/Cyfrin/aderyn/releases
# Add the binary to your PATH
```

Verify:

```bash
aderyn --version
```

### 5. Foundry (for PoC scaffolds)

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Verify:

```bash
forge --version
```

---

## Installation

### Step 1 — Clone or navigate to the project

```bash
cd C:/Users/vivek/Downloads/vulnhound-project/vulnhound
```

### Step 2 — Install Python dependencies

```bash
pip install -e ".[dev]"
```

This installs VulnHound in editable mode with all core and dev dependencies (ChromaDB, sentence-transformers, Slither, Anthropic SDK, Rich, Typer, etc.).

> **Windows note:** Always prefix Python commands with `PYTHONUTF8=1` to avoid encoding errors.

### Step 3 — Verify the install

```bash
PYTHONUTF8=1 python -m src.cli.main --help
```

You should see the available commands: `audit`, `analyze`, `kb`.

---

## Environment Setup

### Step 1 — Create your `.env` file

```bash
cp .env.example .env
```

### Step 2 — Open `.env` and fill in your keys

```
# ── Required ──────────────────────────────────────────────────
ANTHROPIC_API_KEY=sk-ant-api03-...     # Your Anthropic API key

# ── Vector DB (default: local ChromaDB, no key needed) ────────
VECTOR_DB_PROVIDER=chromadb
CHROMADB_DIR=./data/chromadb

# ── LLM Models (defaults are already set correctly) ───────────
LLM_MODEL=claude-sonnet-4-6
LLM_MODEL_FAST=claude-haiku-4-5-20251001
LLM_MODEL_HEAVY=claude-opus-4-6

# ── Analysis config ───────────────────────────────────────────
FINDING_CONFIDENCE_THRESHOLD=0.7       # Drop findings below this confidence
MAX_CONCURRENT_ANALYSES=5

# ── Paths (defaults are fine, no changes needed) ──────────────
KNOWLEDGE_BASE_DIR=./knowledge
REPORTS_DIR=./reports
```

> The only required key is `ANTHROPIC_API_KEY`. Everything else has sensible defaults.

### Step 3 — Create output directories

```bash
mkdir -p data/chromadb reports
```

---

## Step 3 — Build the Knowledge Base

The KB gives the AI historical exploit context. Run this once before your first audit.

### Ingest DeFiHackLabs (671+ exploit write-ups — already downloaded)

```bash
PYTHONUTF8=1 python -m src.cli.main kb ingest --source defihacklabs
```

This reads the markdown files from `data/repos/DeFiHackLabs/`, embeds them, and stores them in ChromaDB. Takes 2–5 minutes on first run.

### Ingest built-in vulnerability patterns

```bash
PYTHONUTF8=1 python -m src.cli.main kb ingest --source all
```

### Check KB stats

```bash
PYTHONUTF8=1 python -m src.cli.main kb stats
```

Expected output:

```
Knowledge Base Statistics
  exploit_code        671 vectors
  exploit_patterns    ??? vectors
  exploit_descriptions 671 vectors
```

### Search the KB (optional sanity check)

```bash
PYTHONUTF8=1 python -m src.cli.main kb search "reentrancy flash loan" -k 5
```

---

## Running an Audit

### Option A — Audit a GitHub repo (full 7-stage pipeline)

```bash
PYTHONUTF8=1 python -m src.cli.main audit https://github.com/user/defi-protocol -o reports/report.md
```

VulnHound will:
1. Clone the repo into `data/repos/`
2. Parse all `.sol` files
3. Run Slither + Aderyn
4. Retrieve similar exploits from ChromaDB (RAG)
5. Run 3 Claude passes (function audit, cross-contract, economic)
6. Deduplicate + rescore findings
7. Generate Foundry PoC scaffolds
8. Write the Markdown report to `reports/report.md`

### Option B — Audit a local folder

```bash
PYTHONUTF8=1 python -m src.cli.main audit ./path/to/contracts -o reports/report.md
```

### Option C — Audit the built-in test project (altitude-v2)

```bash
PYTHONUTF8=1 python -m src.cli.main audit ./data/repos/altitude-v2 -o reports/altitude-report.md
```

---

## Audit Command Flags

```
vulnhound audit <target> [OPTIONS]

  <target>              GitHub URL or local path to Solidity project

Options:
  -o, --output PATH     Write report to this file (default: print to terminal)
  -s, --min-severity    Minimum severity to include: critical | high | medium | low | info
                        Default: low  (shows everything)
  --skip-poc            Skip Foundry PoC generation (faster)
  -m, --model TEXT      Override the LLM model for this run
  -v, --verbose         Show detailed logs per stage
```

### Examples

```bash
# Only show HIGH and CRITICAL findings
PYTHONUTF8=1 python -m src.cli.main audit ./contracts -s high -o report.md

# Skip PoC generation (quicker, no Foundry needed)
PYTHONUTF8=1 python -m src.cli.main audit ./contracts --skip-poc -o report.md

# Use Opus for deeper reasoning (costs more)
PYTHONUTF8=1 python -m src.cli.main audit ./contracts -m claude-opus-4-6 -o report.md

# Verbose output (see each stage's progress)
PYTHONUTF8=1 python -m src.cli.main audit ./contracts -v -o report.md
```

---

## Static Analysis Only (no LLM, no API key)

Use this to quickly check a codebase without spending API credits.

```bash
# Run both Slither and Aderyn
PYTHONUTF8=1 python -m src.cli.main analyze ./contracts -t all

# Run Slither only
PYTHONUTF8=1 python -m src.cli.main analyze ./contracts -t slither

# Run Aderyn only
PYTHONUTF8=1 python -m src.cli.main analyze ./contracts -t aderyn
```

Output is a pretty-printed table of findings sorted by severity. No API key needed.

---

## Knowledge Base Commands

```bash
# Ingest all sources
PYTHONUTF8=1 python -m src.cli.main kb ingest --source all

# Ingest a specific source
PYTHONUTF8=1 python -m src.cli.main kb ingest --source defihacklabs
PYTHONUTF8=1 python -m src.cli.main kb ingest --source solodit
PYTHONUTF8=1 python -m src.cli.main kb ingest --source rekt

# Limit number of exploits ingested (useful for testing)
PYTHONUTF8=1 python -m src.cli.main kb ingest --source defihacklabs --limit 50

# Search the KB
PYTHONUTF8=1 python -m src.cli.main kb search "oracle price manipulation" -k 10
PYTHONUTF8=1 python -m src.cli.main kb search "access control bypass" -k 5

# Show vector counts
PYTHONUTF8=1 python -m src.cli.main kb stats
```

---

## Reading the Report

The output is a Markdown file styled after Code4rena audit reports.

### Report structure

```
# VulnHound Audit Report — <Project>

## Executive Summary
  - Total findings, severity breakdown table, key findings list

## Audit Scope
  - Contracts audited, LOC, proxy types, compiler version

## Findings
  ### [H-01] Title of High finding
    - Severity / Category / Location
    - Description
    - Impact
    - Exploit Scenario
    - Vulnerable Code
    - Recommended Fix
    - Similar Historical Exploits (up to 3 with loss amounts)

  ### [M-01] ...
  ### [L-01] ...

  ### Low / Informational (table)

## Methodology
## Disclaimer
```

### Finding ID format

| Prefix | Severity |
|--------|----------|
| `C-01` | Critical |
| `H-01` | High |
| `M-01` | Medium |
| `L-01` | Low |
| `I-01` | Informational |

---

## PoC Scaffolds

For each HIGH/CRITICAL finding, VulnHound generates a Foundry test file:

```
reports/
  poc/
    VH-001_ReentrancyAttack.t.sol
    VH-002_FlashLoanManipulation.t.sol
```

Each file contains:
- An `AttackContract` with interface for the target
- An `attack()` function with TODO steps
- Flash loan callback scaffold (Uniswap V2) if needed
- Invariant assertions

These are **scaffolds, not working exploits** — fill in the TODOs to complete the PoC.

To run a scaffold:

```bash
cd reports/poc
forge test -vvvv --match-path VH-001_ReentrancyAttack.t.sol
```

---

## Troubleshooting

### `UnicodeDecodeError` or encoding errors
Always use `PYTHONUTF8=1` prefix on Windows:
```bash
PYTHONUTF8=1 python -m src.cli.main <command>
```

### `credit balance too low` from Anthropic API
Top up your Anthropic account at https://console.anthropic.com. Credits can take a few minutes to propagate after payment.

### Slither fails: `solc not found`
Install the Solidity compiler matching your project's version:
```bash
pip install solc-select
solc-select install 0.8.20
solc-select use 0.8.20
```

### Slither fails on a Foundry project
Slither needs remappings. Run from the project root where `foundry.toml` exists:
```bash
PYTHONUTF8=1 python -m src.cli.main audit ./data/repos/altitude-v2
```

### ChromaDB collection already exists warning
This is fine — it reuses the existing collection. Use `--limit` to re-ingest a subset.

### `ModuleNotFoundError: No module named 'src'`
You're not in the project root, or forgot `-m`:
```bash
cd C:/Users/vivek/Downloads/vulnhound-project/vulnhound
PYTHONUTF8=1 python -m src.cli.main audit ...
```

---

## Full Example Walkthrough

```bash
# 1. Go to project
cd C:/Users/vivek/Downloads/vulnhound-project/vulnhound

# 2. Set up .env (one-time)
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

# 3. Install deps (one-time)
pip install -e ".[dev]"

# 4. Build the knowledge base (one-time)
PYTHONUTF8=1 python -m src.cli.main kb ingest --source defihacklabs

# 5. Check KB is populated
PYTHONUTF8=1 python -m src.cli.main kb stats

# 6. Quick static check (no API key needed)
PYTHONUTF8=1 python -m src.cli.main analyze ./data/repos/altitude-v2 -t all

# 7. Full AI audit
PYTHONUTF8=1 python -m src.cli.main audit ./data/repos/altitude-v2 -o reports/altitude-report.md -v

# 8. Open the report
cat reports/altitude-report.md
```

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Yes | — | Claude API key |
| `LLM_MODEL` | No | `claude-sonnet-4-6` | Main audit model |
| `LLM_MODEL_FAST` | No | `claude-haiku-4-5-20251001` | Economic pass model |
| `LLM_MODEL_HEAVY` | No | `claude-opus-4-6` | Heavy reasoning model |
| `VECTOR_DB_PROVIDER` | No | `chromadb` | `chromadb` or `pinecone` |
| `CHROMADB_DIR` | No | `./data/chromadb` | Local vector DB path |
| `FINDING_CONFIDENCE_THRESHOLD` | No | `0.7` | Drop findings below this (0–1) |
| `MAX_CONCURRENT_ANALYSES` | No | `5` | Parallel LLM calls |
| `KNOWLEDGE_BASE_DIR` | No | `./knowledge` | Raw exploit data path |
| `REPORTS_DIR` | No | `./reports` | Output reports path |
