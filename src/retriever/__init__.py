"""
VulnHound Retriever — Stage 3: Context Builder + RAG

Entry point: ``build_contract_contexts(scope, findings) -> list[ContractContext]``

Takes Stage 1 (ProjectScope) + Stage 2 (StaticAnalysisFindings) and builds
enriched ContractContext objects ready for Stage 4 (LLM analysis).

For each high-risk contract:
  1. Attach all its Slither findings
  2. Build a search query from the contract's vulnerability profile
  3. Search the exploit KB for the top 5 similar historical exploits
  4. Package full contract source + findings + KB matches into ContractContext

Why contract-level (not function-level)?
  Most DeFi vulnerabilities span multiple functions — you can't reason
  about withdraw() without knowing what deposit() sets up. Giving the LLM
  the full contract gives it the context it needs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import track

from src.models import (
    ContractInfo,
    FunctionInfo,
    ProjectScope,
    RetrievedExploit,
    Severity,
    StaticAnalysisFinding,
)
from src.retriever.risk_scorer import score_functions

console = Console(stderr=True)

__all__ = ["ContractContext", "build_contract_contexts"]


@dataclass
class ContractContext:
    """
    The enriched context package for a single contract.
    This is what gets fed to the LLM for analysis.

    Full contract source + all findings + similar KB exploits.
    """

    contract: ContractInfo
    source_code: str                                      # full .sol file content
    top_functions: list[tuple[FunctionInfo, int]]         # (function, risk_score)
    static_findings: list[StaticAnalysisFinding] = field(default_factory=list)
    similar_exploits: list[RetrievedExploit] = field(default_factory=list)
    cross_contract_deps: list[str] = field(default_factory=list)

    @property
    def contract_name(self) -> str:
        return self.contract.name

    @property
    def has_high_findings(self) -> bool:
        return any(
            f.severity in (Severity.HIGH, Severity.CRITICAL)
            for f in self.static_findings
        )

    @property
    def finding_summary(self) -> str:
        counts: dict[str, int] = {}
        for f in self.static_findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return " | ".join(f"{k.upper()}={v}" for k, v in counts.items())


def build_contract_contexts(
    scope: ProjectScope,
    findings: list[StaticAnalysisFinding],
    top_n_functions: int = 20,
    kb_top_k: int = 5,
    use_kb: bool = True,
) -> list[ContractContext]:
    """
    Build enriched ContractContext objects for the LLM.

    Parameters
    ----------
    scope:
        ProjectScope from Stage 1.
    findings:
        FP-filtered StaticAnalysisFindings from Stage 2.
    top_n_functions:
        Only analyse contracts that contain at least one of the top N
        highest-risk functions.
    kb_top_k:
        Number of similar exploits to retrieve per contract.
    use_kb:
        Set False to skip KB retrieval (faster, for testing).

    Returns
    -------
    list[ContractContext]
        Sorted by risk: contracts with HIGH findings first.
    """
    console.rule("[bold green]VulnHound — Stage 3: Context Builder + RAG[/bold green]")

    # ── Step 1: Score all functions, get top N ────────────────────────────────
    console.log(f"[dim]Scoring functions across {len(scope.contracts)} contracts...[/dim]")
    top_scored = score_functions(scope, findings, top_n=top_n_functions)

    if not top_scored:
        console.log("[yellow]No functions scored — returning empty context list[/yellow]")
        return []

    # ── Step 2: Determine which contracts to analyse ──────────────────────────
    # Include a contract if it has at least one top-scored function
    contracts_to_analyse: dict[str, list[tuple[FunctionInfo, int]]] = {}
    for fn, contract, score in top_scored:
        contracts_to_analyse.setdefault(contract.name, []).append((fn, score))

    console.log(
        f"  Analysing {len(contracts_to_analyse)} contract(s) "
        f"covering {len(top_scored)} high-risk function(s)"
    )

    # ── Step 3: Build per-contract finding map ────────────────────────────────
    finding_map: dict[str, list[StaticAnalysisFinding]] = {}
    for f in findings:
        finding_map.setdefault(f.contract, []).append(f)

    # ── Step 4: Build ContractContext for each selected contract ──────────────
    contract_map: dict[str, ContractInfo] = {c.name: c for c in scope.contracts}
    dep_graph = scope.dependency_graph

    # Optionally load KB
    embedder = None
    store = None
    if use_kb:
        try:
            from src.knowledge_base.embedder import ExploitEmbedder
            from src.knowledge_base.vector_store import ChromaVectorStore
            embedder = ExploitEmbedder()
            store = ChromaVectorStore()
        except Exception as e:
            console.log(f"[yellow]KB unavailable: {e} — skipping RAG[/yellow]")

    contexts: list[ContractContext] = []

    for contract_name, fn_scores in track(
        contracts_to_analyse.items(),
        description="Building contract contexts...",
        console=console,
    ):
        contract = contract_map.get(contract_name)
        if not contract:
            continue

        # Read source file
        source_code = _read_source(contract)

        # Findings for this contract
        contract_findings = finding_map.get(contract_name, [])

        # Cross-contract dependencies
        deps = dep_graph.get(contract_name, [])

        # RAG: search KB for similar exploits
        similar: list[RetrievedExploit] = []
        if embedder and store and (contract_findings or source_code):
            query = _build_rag_query(contract, contract_findings, source_code)
            try:
                vec = embedder.embed_query(query)
                similar = store.search_by_description(vec, top_k=kb_top_k)
                # Also search by pattern for better coverage
                pattern_vec = embedder.embed_query(_build_pattern_query(contract_findings))
                pattern_results = store.search_by_pattern(pattern_vec, top_k=kb_top_k)
                # Merge, deduplicate by exploit_id, keep highest score
                seen: dict[str, RetrievedExploit] = {r.exploit_id: r for r in similar}
                for r in pattern_results:
                    if r.exploit_id not in seen or r.similarity_score > seen[r.exploit_id].similarity_score:
                        seen[r.exploit_id] = r
                similar = sorted(seen.values(), key=lambda x: x.similarity_score, reverse=True)[:kb_top_k]
            except Exception as e:
                console.log(f"[yellow]KB search failed for {contract_name}: {e}[/yellow]")

        ctx = ContractContext(
            contract=contract,
            source_code=source_code,
            top_functions=fn_scores,
            static_findings=contract_findings,
            similar_exploits=similar,
            cross_contract_deps=deps,
        )
        contexts.append(ctx)

    # Sort: contracts with HIGH/CRITICAL findings first
    contexts.sort(key=lambda c: (
        0 if c.has_high_findings else 1,
        -len(c.static_findings),
    ))

    console.rule("[bold green]Stage 3 complete[/bold green]")
    console.log(
        f"  Built {len(contexts)} contract context(s) | "
        f"Total findings: {sum(len(c.static_findings) for c in contexts)} | "
        f"KB matches: {sum(len(c.similar_exploits) for c in contexts)}"
    )

    return contexts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_source(contract: ContractInfo) -> str:
    """Read the contract's source file."""
    try:
        return Path(contract.file_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return f"// Source not found: {contract.file_path}"


def _build_rag_query(
    contract: ContractInfo,
    findings: list[StaticAnalysisFinding],
    source_code: str,
) -> str:
    """
    Build a rich search query from contract context for description-based search.
    Combines: contract name, inheritance, finding types, key patterns.
    """
    parts = [f"smart contract {contract.name}"]

    if contract.inherits_from:
        parts.append(f"inherits {', '.join(contract.inherits_from)}")

    if contract.is_proxy:
        parts.append(f"{contract.proxy_type or 'proxy'} pattern upgradeable")

    # Add unique detector names from findings (HIGH/MEDIUM only)
    detectors = list({
        f.detector_name for f in findings
        if f.severity in (Severity.HIGH, Severity.MEDIUM, Severity.CRITICAL)
    })
    if detectors:
        parts.append("vulnerabilities: " + ", ".join(detectors[:5]))

    # Scan source for known risky patterns
    src_lower = source_code.lower()
    if ".call{" in src_lower or ".call(" in src_lower:
        parts.append("low level call external")
    if "delegatecall" in src_lower:
        parts.append("delegatecall proxy")
    if "flashloan" in src_lower or "flash_loan" in src_lower or "flash loan" in src_lower:
        parts.append("flash loan attack")
    if "getreserves" in src_lower or "getprice" in src_lower:
        parts.append("price oracle manipulation AMM reserves")

    return " ".join(parts)


def _build_pattern_query(findings: list[StaticAnalysisFinding]) -> str:
    """Build a query focused on attack patterns from the findings."""
    if not findings:
        return "smart contract vulnerability exploit"

    # Focus on highest severity findings
    high = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL, Severity.MEDIUM)]
    if not high:
        high = findings[:3]

    parts = []
    for f in high[:3]:
        parts.append(f"{f.detector_name} {f.contract} {f.function or ''}".strip())

    return " | ".join(parts)
