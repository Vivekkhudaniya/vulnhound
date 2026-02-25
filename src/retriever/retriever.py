"""
VulnHound RAG Retriever — Stage 4

Retrieves similar historical exploits from the Knowledge Base for each
function being audited and assembles enriched FunctionContext objects
ready for LLM analysis.

Strategy: Triple-query Reciprocal Rank Fusion
  1. Code query    → embed the function's source code
  2. Pattern query → embed the static findings (detector names + severity)
  3. Semantic query→ natural language risk description of the function

All three are embedded and searched against ChromaDB independently.
Results are merged with Reciprocal Rank Fusion (RRF), which consistently
outperforms weighted score averaging when combining heterogeneous ranked lists.

Public API
----------
    retriever = RAGRetriever()
    ctx = retriever.enrich_context(function_context)  # single function
    ctxs = retriever.enrich_batch(contexts)           # batch
    ctxs = build_function_contexts(scored_fns, findings, scope, retriever)
"""

from __future__ import annotations

from typing import Optional

from rich.console import Console

from src.knowledge_base.embedder import EMBEDDING_MODEL, ExploitEmbedder
from src.knowledge_base.vector_store import VectorStore, get_vector_store
from src.models import (
    ContractInfo,
    FunctionContext,
    FunctionInfo,
    ProjectScope,
    RetrievedExploit,
    Severity,
    StaticAnalysisFinding,
)

console = Console()

# ---------------------------------------------------------------------------
# Tuning constants
# ---------------------------------------------------------------------------

# RRF constant — standard value; higher k → less aggressive rank promotion
_RRF_K = 60

# Minimum RRF-normalised similarity to include in results (noise cutoff)
_MIN_SCORE = 0.20

# Number of results to fetch per collection before fusion (fetch wide, prune tight)
_FETCH_K = 10


# ---------------------------------------------------------------------------
# Public retriever class
# ---------------------------------------------------------------------------


class RAGRetriever:
    """
    Retrieves similar exploits from the KB for functions under audit.

    Lazy-loads the embedding model and vector store on first use so it's
    cheap to construct (important when running tests without a live ChromaDB).
    """

    def __init__(
        self,
        model_name: str = EMBEDDING_MODEL,
        store: Optional[VectorStore] = None,
    ):
        self._model_name = model_name
        self._embedder: Optional[ExploitEmbedder] = None
        self._store = store  # allow injection for testing

    # ------------------------------------------------------------------
    # Lazy properties
    # ------------------------------------------------------------------

    @property
    def embedder(self) -> ExploitEmbedder:
        if self._embedder is None:
            self._embedder = ExploitEmbedder(self._model_name)
        return self._embedder

    @property
    def store(self) -> VectorStore:
        if self._store is None:
            self._store = get_vector_store()
        return self._store

    # ------------------------------------------------------------------
    # Core retrieval
    # ------------------------------------------------------------------

    def retrieve(
        self,
        function: FunctionInfo,
        contract: ContractInfo,
        static_findings: list[StaticAnalysisFinding],
        top_k: int = 5,
    ) -> list[RetrievedExploit]:
        """
        Retrieve similar exploits for a single function.

        Parameters
        ----------
        function:
            The FunctionInfo being analysed.
        contract:
            The ContractInfo containing the function.
        static_findings:
            FP-filtered static analysis findings for this function.
        top_k:
            Maximum number of results to return.

        Returns
        -------
        list[RetrievedExploit] sorted by fused relevance score descending.
        """
        # Build 3 query texts targeting different embedding spaces
        code_query = _build_code_query(function, contract)
        pattern_query = _build_pattern_query(function, static_findings)
        semantic_query = _build_semantic_query(function, contract, static_findings)

        console.print(
            f"[dim]  [RAG] Querying KB for {contract.name}.{function.name}...[/dim]"
        )

        # Embed all 3 queries (each gets the search_query: prefix inside embed_query)
        code_vec = self.embedder.embed_query(code_query)
        pattern_vec = self.embedder.embed_query(pattern_query)
        semantic_vec = self.embedder.embed_query(semantic_query)

        # Search all 3 ChromaDB collections independently
        code_results = self.store.search_by_code(code_vec, top_k=_FETCH_K)
        pattern_results = self.store.search_by_pattern(pattern_vec, top_k=_FETCH_K)
        desc_results = self.store.search_by_description(semantic_vec, top_k=_FETCH_K)

        console.print(
            f"[dim]  [RAG] code={len(code_results)} pattern={len(pattern_results)} "
            f"semantic={len(desc_results)} candidates[/dim]"
        )

        # Fuse with Reciprocal Rank Fusion
        fused = _reciprocal_rank_fusion(
            [code_results, pattern_results, desc_results],
            k=_RRF_K,
        )

        # Apply noise cutoff and return top_k
        filtered = [r for r in fused if r.similarity_score >= _MIN_SCORE]

        console.print(
            f"[dim]  [RAG] → {len(filtered)} exploits after score cutoff "
            f"(returning top {min(top_k, len(filtered))})[/dim]"
        )

        return filtered[:top_k]

    # ------------------------------------------------------------------
    # Context enrichment
    # ------------------------------------------------------------------

    def enrich_context(
        self,
        ctx: FunctionContext,
        top_k: int = 5,
    ) -> FunctionContext:
        """
        Retrieve similar exploits and attach them to a FunctionContext.

        This is the primary API consumed by the LLM engine (Stage 5).
        Returns a new FunctionContext with similar_exploits populated.
        """
        exploits = self.retrieve(
            function=ctx.function,
            contract=ctx.contract,
            static_findings=ctx.static_findings,
            top_k=top_k,
        )
        return ctx.model_copy(update={"similar_exploits": exploits})

    def enrich_batch(
        self,
        contexts: list[FunctionContext],
        top_k: int = 5,
    ) -> list[FunctionContext]:
        """Enrich a list of FunctionContexts. Processes sequentially."""
        enriched = []
        for i, ctx in enumerate(contexts, start=1):
            console.print(
                f"[dim][RAG] Enriching {i}/{len(contexts)}: "
                f"{ctx.contract.name}.{ctx.function.name}[/dim]"
            )
            enriched.append(self.enrich_context(ctx, top_k=top_k))
        return enriched


# ---------------------------------------------------------------------------
# Context builder — wires risk scorer output → FunctionContext list
# ---------------------------------------------------------------------------


def build_function_contexts(
    scored_functions: list[tuple[FunctionInfo, ContractInfo, int]],
    findings: list[StaticAnalysisFinding],
    scope: ProjectScope,
    retriever: Optional[RAGRetriever] = None,
    top_k_exploits: int = 5,
) -> list[FunctionContext]:
    """
    Convert risk-scored functions into enriched FunctionContext objects.

    Takes the output of `risk_scorer.score_functions()` and:
      1. Filters static findings per function
      2. Resolves cross-contract calls from the dependency graph
      3. Optionally enriches each context with KB exploits via RAGRetriever

    Parameters
    ----------
    scored_functions:
        Output of risk_scorer.score_functions() — list of (fn, contract, score).
    findings:
        FP-filtered findings from Stage 2.
    scope:
        ProjectScope from Stage 1 (for dependency graph).
    retriever:
        Optional RAGRetriever. If provided, similar_exploits are populated.
        Pass None to skip KB retrieval (useful for tests or offline mode).
    top_k_exploits:
        How many similar exploits to retrieve per function.

    Returns
    -------
    list[FunctionContext] in risk-score order (highest first).
    """
    # Build finding lookup: (contract_name, fn_name) → [findings]
    finding_map: dict[tuple[str, str], list[StaticAnalysisFinding]] = {}
    for f in findings:
        key = (f.contract, f.function or "")
        finding_map.setdefault(key, []).append(f)

    contexts: list[FunctionContext] = []

    for fn, contract, _score in scored_functions:
        # Collect relevant findings: exact match OR contract-level (fn=None)
        fn_findings = (
            finding_map.get((contract.name, fn.name), [])
            + finding_map.get((contract.name, ""), [])
        )

        # Resolve cross-contract calls from dependency graph
        cross_calls = _resolve_cross_contract_calls(fn, contract, scope)

        ctx = FunctionContext(
            function=fn,
            contract=contract,
            static_findings=fn_findings,
            cross_contract_calls=cross_calls,
            similar_exploits=[],
        )
        contexts.append(ctx)

    # Enrich with KB exploits if retriever is provided
    if retriever is not None and contexts:
        console.print(
            f"[cyan][RAG] Enriching {len(contexts)} functions with KB exploits...[/cyan]"
        )
        contexts = retriever.enrich_batch(contexts, top_k=top_k_exploits)

    return contexts


# ---------------------------------------------------------------------------
# Query builders — private helpers
# ---------------------------------------------------------------------------


def _build_code_query(function: FunctionInfo, contract: ContractInfo) -> str:
    """
    Build a code-focused query from the function's source.

    nomic-embed-text-v1 is trained on code; feeding actual source gives the
    best code-similarity matches against KB snippets.
    """
    header_lines = [
        f"// Contract: {contract.name}",
        f"// Function: {function.name} ({function.visibility})",
    ]
    if function.state_mutability:
        header_lines.append(f"// Mutability: {function.state_mutability}")
    if function.modifiers:
        header_lines.append(f"// Modifiers: {', '.join(function.modifiers)}")

    source = function.source_code[:1500] if function.source_code else "(source unavailable)"
    return "\n".join(header_lines) + "\n" + source


def _build_pattern_query(
    function: FunctionInfo,
    findings: list[StaticAnalysisFinding],
) -> str:
    """
    Build a pattern-focused query from static analysis findings.

    Emphasises detector names + severity to match against pattern embeddings.
    """
    parts = [f"function {function.name}"]

    # Sort findings high → low severity for relevance
    _sev_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFORMATIONAL: 4,
    }
    sorted_findings = sorted(
        findings, key=lambda f: _sev_order.get(f.severity, 5)
    )

    for f in sorted_findings[:5]:  # cap at 5 to avoid dilution
        parts.append(
            f"{f.severity.value} {f.detector_name}: {f.description[:150]}"
        )

    if not findings:
        # No static findings — infer pattern hints from signature
        if function.state_mutability == "payable":
            parts.append("payable function receives ETH")
        if function.visibility in ("public", "external"):
            parts.append("public external function no access control modifier")

    return " | ".join(parts)


def _build_semantic_query(
    function: FunctionInfo,
    contract: ContractInfo,
    findings: list[StaticAnalysisFinding],
) -> str:
    """
    Build a natural language query describing the function's risk profile.

    Targets the description embedding space for broad semantic matching.
    """
    vis = function.visibility
    mut = function.state_mutability or "nonpayable"

    parts = [
        f"Smart contract vulnerability in {contract.name}.{function.name}:"
        f" {vis} {mut} function"
    ]

    # Add severity context
    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities or Severity.HIGH in severities:
        parts.append("with high severity security vulnerability")
    elif Severity.MEDIUM in severities:
        parts.append("with medium severity security issue")

    # Add top finding descriptions
    detectors = [f.detector_name for f in findings[:3]]
    if detectors:
        parts.append(f"involving {', '.join(detectors)}")

    if function.state_mutability == "payable":
        parts.append("that handles native ETH transfers")

    if contract.external_calls:
        parts.append("with external contract calls and potential reentrancy")

    if contract.is_proxy:
        parts.append("in upgradeable proxy contract with delegatecall")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Reciprocal Rank Fusion
# ---------------------------------------------------------------------------


def _reciprocal_rank_fusion(
    ranked_lists: list[list[RetrievedExploit]],
    k: int = 60,
) -> list[RetrievedExploit]:
    """
    Merge multiple ranked exploit lists using Reciprocal Rank Fusion.

    RRF(d) = Σ 1 / (k + rank(d, list_i))  for each list containing d

    The returned similarity_score is the RRF score normalised to [0, 1]
    relative to the theoretical maximum (top rank in all lists).

    References
    ----------
    Cormack, G.V. et al. (2009). Reciprocal rank fusion outperforms condorcet
    and individual rank learning methods. SIGIR 2009.
    """
    # exploit_id → RetrievedExploit (first seen wins for metadata)
    exploit_store: dict[str, RetrievedExploit] = {}
    rrf_scores: dict[str, float] = {}

    for ranked_list in ranked_lists:
        for rank, exploit in enumerate(ranked_list, start=1):
            eid = exploit.exploit_id
            rrf_scores[eid] = rrf_scores.get(eid, 0.0) + 1.0 / (k + rank)
            if eid not in exploit_store:
                exploit_store[eid] = exploit

    # Normalise: max possible score = n_lists / (k + 1)
    n_lists = len(ranked_lists)
    max_rrf = n_lists / (k + 1)

    sorted_ids = sorted(
        rrf_scores.keys(),
        key=lambda eid: rrf_scores[eid],
        reverse=True,
    )

    result = []
    for eid in sorted_ids:
        exploit = exploit_store[eid]
        normalised = round(min(1.0, rrf_scores[eid] / max_rrf), 4)
        result.append(exploit.model_copy(update={"similarity_score": normalised}))

    return result


# ---------------------------------------------------------------------------
# Cross-contract call resolution
# ---------------------------------------------------------------------------


def _resolve_cross_contract_calls(
    function: FunctionInfo,
    contract: ContractInfo,
    scope: ProjectScope,
) -> list[str]:
    """
    Return a list of external functions called by this function,
    resolved via the project dependency graph.

    Format: "ContractName.functionName"
    """
    cross_calls: list[str] = []
    called_contracts = scope.dependency_graph.get(contract.name, [])

    for called_name in called_contracts:
        # We don't have fine-grained call graphs yet (Stage 1 gives contract-level)
        # Report the contract as a cross-contract dependency
        cross_calls.append(called_name)

    return cross_calls
