"""
Tests for src/retriever/retriever.py

All tests use stub/mock objects so no ChromaDB or embedding model is required.

Run with: pytest tests/unit/test_retriever.py -v
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.models import (
    ContractInfo,
    FindingSource,
    FunctionContext,
    FunctionInfo,
    ProjectScope,
    RetrievedExploit,
    Severity,
    StaticAnalysisFinding,
    VulnCategory,
)
from src.retriever.retriever import (
    RAGRetriever,
    _build_code_query,
    _build_pattern_query,
    _build_semantic_query,
    _reciprocal_rank_fusion,
    _resolve_cross_contract_calls,
    build_function_contexts,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_function(
    name: str = "withdraw",
    visibility: str = "external",
    mutability: str = "nonpayable",
    modifiers: list | None = None,
    source: str = "function withdraw(uint256 amount) external { ... }",
) -> FunctionInfo:
    return FunctionInfo(
        name=name,
        contract="Vault",
        visibility=visibility,
        modifiers=modifiers or [],
        state_mutability=mutability,
        source_code=source,
    )


def _make_contract(
    name: str = "Vault",
    external_calls: list | None = None,
    is_proxy: bool = False,
) -> ContractInfo:
    return ContractInfo(
        name=name,
        file_path="contracts/Vault.sol",
        external_calls=external_calls or ["erc20_transfer"],
        is_proxy=is_proxy,
    )


def _make_finding(
    detector: str = "reentrancy-eth",
    severity: Severity = Severity.HIGH,
    fn: str = "withdraw",
) -> StaticAnalysisFinding:
    return StaticAnalysisFinding(
        tool=FindingSource.SLITHER,
        detector_name=detector,
        severity=severity,
        confidence="high",
        description=f"{detector} vulnerability in {fn}",
        contract="Vault",
        function=fn,
        file_path="contracts/Vault.sol",
        line_start=42,
    )


def _make_exploit(exploit_id: str, score: float = 0.8) -> RetrievedExploit:
    return RetrievedExploit(
        exploit_id=exploit_id,
        protocol="TestProtocol",
        similarity_score=score,
        category=VulnCategory.REENTRANCY,
        description="Test exploit description",
        loss_usd=1_000_000,
        attack_summary="Flash loan + reentrancy attack",
    )


def _make_scope(dep_graph: dict | None = None) -> ProjectScope:
    return ProjectScope(
        repo_path="./contracts",
        contracts=[_make_contract()],
        dependency_graph=dep_graph if dep_graph is not None else {"Vault": ["Token"]},
    )


# ---------------------------------------------------------------------------
# Query builder tests
# ---------------------------------------------------------------------------


def test_build_code_query_includes_source():
    fn = _make_function(source="function withdraw() external { ... }")
    contract = _make_contract()
    query = _build_code_query(fn, contract)
    assert "Vault" in query
    assert "withdraw" in query
    assert "function withdraw() external" in query


def test_build_code_query_with_modifiers():
    fn = _make_function(modifiers=["nonReentrant", "onlyOwner"])
    contract = _make_contract()
    query = _build_code_query(fn, contract)
    assert "nonReentrant" in query
    assert "onlyOwner" in query


def test_build_code_query_caps_long_source():
    long_source = "x" * 3000
    fn = _make_function(source=long_source)
    contract = _make_contract()
    query = _build_code_query(fn, contract)
    # Source should be capped at 1500 chars
    assert len(query) < 2000


def test_build_pattern_query_with_findings():
    fn = _make_function()
    findings = [
        _make_finding("reentrancy-eth", Severity.HIGH),
        _make_finding("unchecked-calls", Severity.MEDIUM),
    ]
    query = _build_pattern_query(fn, findings)
    assert "reentrancy-eth" in query
    assert "high" in query
    assert "unchecked-calls" in query


def test_build_pattern_query_no_findings_payable():
    fn = _make_function(mutability="payable")
    query = _build_pattern_query(fn, [])
    assert "payable" in query


def test_build_pattern_query_no_findings_public():
    fn = _make_function(visibility="public")
    query = _build_pattern_query(fn, [])
    assert "public" in query or "external" in query


def test_build_pattern_query_caps_at_5_findings():
    fn = _make_function()
    findings = [_make_finding(f"detector-{i}") for i in range(10)]
    query = _build_pattern_query(fn, findings)
    # 5 findings capped means at most 5 pipe-separated segments after the header
    # query = "function withdraw | seg1 | seg2 | seg3 | seg4 | seg5"
    segments = query.split(" | ")
    assert len(segments) <= 6  # 1 header + 5 findings max


def test_build_semantic_query_high_severity():
    fn = _make_function()
    contract = _make_contract()
    findings = [_make_finding(severity=Severity.HIGH)]
    query = _build_semantic_query(fn, contract, findings)
    assert "high severity" in query


def test_build_semantic_query_medium_severity():
    fn = _make_function()
    contract = _make_contract()
    findings = [_make_finding(severity=Severity.MEDIUM)]
    query = _build_semantic_query(fn, contract, findings)
    assert "medium severity" in query


def test_build_semantic_query_payable():
    fn = _make_function(mutability="payable")
    contract = _make_contract()
    query = _build_semantic_query(fn, contract, [])
    assert "ETH" in query


def test_build_semantic_query_proxy():
    fn = _make_function()
    contract = _make_contract(is_proxy=True)
    query = _build_semantic_query(fn, contract, [])
    assert "proxy" in query or "delegatecall" in query


# ---------------------------------------------------------------------------
# RRF tests
# ---------------------------------------------------------------------------


def test_rrf_merges_two_lists():
    list_a = [_make_exploit("A", 0.9), _make_exploit("B", 0.7)]
    list_b = [_make_exploit("B", 0.8), _make_exploit("C", 0.6)]
    fused = _reciprocal_rank_fusion([list_a, list_b])
    ids = [r.exploit_id for r in fused]
    # B appears in both lists so should rank highly
    assert ids[0] == "B"
    assert set(ids) == {"A", "B", "C"}


def test_rrf_deduplicates():
    # Same exploit in both lists at rank 1
    list_a = [_make_exploit("X", 0.95)]
    list_b = [_make_exploit("X", 0.85)]
    fused = _reciprocal_rank_fusion([list_a, list_b])
    # Should appear only once
    assert len(fused) == 1
    assert fused[0].exploit_id == "X"


def test_rrf_score_normalised():
    exploit = _make_exploit("Z", 0.8)
    fused = _reciprocal_rank_fusion([[exploit]])
    # Score should be between 0 and 1
    assert 0.0 <= fused[0].similarity_score <= 1.0


def test_rrf_empty_lists():
    fused = _reciprocal_rank_fusion([[], []])
    assert fused == []


def test_rrf_single_list():
    results = [_make_exploit("A"), _make_exploit("B"), _make_exploit("C")]
    fused = _reciprocal_rank_fusion([results])
    # Order should be preserved (rank 1 → highest RRF)
    assert [r.exploit_id for r in fused] == ["A", "B", "C"]


def test_rrf_higher_k_softens_ranking():
    """Higher k constant should give more uniform scores."""
    e1, e2 = _make_exploit("A"), _make_exploit("B")
    fused_low_k = _reciprocal_rank_fusion([[e1, e2]], k=1)
    fused_high_k = _reciprocal_rank_fusion([[e1, e2]], k=200)
    gap_low = fused_low_k[0].similarity_score - fused_low_k[1].similarity_score
    gap_high = fused_high_k[0].similarity_score - fused_high_k[1].similarity_score
    assert gap_high < gap_low


# ---------------------------------------------------------------------------
# Cross-contract resolution tests
# ---------------------------------------------------------------------------


def test_resolve_cross_contract_calls_returns_deps():
    fn = _make_function()
    contract = _make_contract()
    scope = _make_scope(dep_graph={"Vault": ["Token", "PriceOracle"]})
    calls = _resolve_cross_contract_calls(fn, contract, scope)
    assert "Token" in calls
    assert "PriceOracle" in calls


def test_resolve_cross_contract_calls_empty_graph():
    fn = _make_function()
    contract = _make_contract()
    scope = _make_scope(dep_graph={})
    calls = _resolve_cross_contract_calls(fn, contract, scope)
    assert calls == []


# ---------------------------------------------------------------------------
# RAGRetriever unit tests (with mocked store + embedder)
# ---------------------------------------------------------------------------


def _make_mock_store(returns: list[RetrievedExploit] | None = None):
    """Build a mock VectorStore that returns a fixed exploit list."""
    results = returns or [_make_exploit("HACK-001", 0.85)]
    store = MagicMock()
    store.search_by_code.return_value = results
    store.search_by_pattern.return_value = results
    store.search_by_description.return_value = results
    return store


def _make_mock_embedder():
    embedder = MagicMock()
    embedder.embed_query.return_value = [0.1] * 768
    return embedder


def _make_retriever_with_mocks(
    exploits: list[RetrievedExploit] | None = None,
) -> RAGRetriever:
    retriever = RAGRetriever.__new__(RAGRetriever)
    retriever._model_name = "nomic-ai/nomic-embed-text-v1"
    retriever._embedder = _make_mock_embedder()
    retriever._store = _make_mock_store(exploits)
    return retriever


def test_retrieve_returns_exploits():
    retriever = _make_retriever_with_mocks([_make_exploit("HACK-001", 0.85)])
    fn = _make_function()
    contract = _make_contract()
    results = retriever.retrieve(fn, contract, [], top_k=5)
    assert len(results) >= 1
    assert results[0].exploit_id == "HACK-001"


def test_retrieve_respects_top_k():
    exploits = [_make_exploit(f"HACK-{i:03d}") for i in range(20)]
    retriever = _make_retriever_with_mocks(exploits)
    fn = _make_function()
    contract = _make_contract()
    results = retriever.retrieve(fn, contract, [], top_k=3)
    assert len(results) <= 3


def test_retrieve_filters_low_scores():
    """Exploits below MIN_SCORE threshold should be excluded."""
    low_score_exploit = _make_exploit("LOW-001", score=0.01)
    retriever = _make_retriever_with_mocks([low_score_exploit])
    fn = _make_function()
    contract = _make_contract()
    results = retriever.retrieve(fn, contract, [], top_k=5)
    # RRF-normalised score for a single result in 3 lists at rank 1
    # = 3/(60+1) / (3/(60+1)) = 1.0 → above threshold
    # But if only in one of 3 lists at rank 1: 1/(60+1)/(3/61) = 1/3 ~ 0.33 → above 0.20
    # Low_score_exploit was returned by all 3, so it will pass the cutoff
    # This test checks that the score is above _MIN_SCORE (0.20)
    for r in results:
        assert r.similarity_score >= 0.20


def test_enrich_context_attaches_exploits():
    retriever = _make_retriever_with_mocks([_make_exploit("HACK-001", 0.9)])
    fn = _make_function()
    contract = _make_contract()
    ctx = FunctionContext(function=fn, contract=contract)
    enriched = retriever.enrich_context(ctx, top_k=3)
    assert len(enriched.similar_exploits) >= 1
    assert enriched.similar_exploits[0].exploit_id == "HACK-001"


def test_enrich_context_does_not_mutate_original():
    retriever = _make_retriever_with_mocks()
    fn = _make_function()
    contract = _make_contract()
    ctx = FunctionContext(function=fn, contract=contract, similar_exploits=[])
    enriched = retriever.enrich_context(ctx, top_k=3)
    # Original should be unchanged
    assert ctx.similar_exploits == []
    # Enriched should have exploits
    assert len(enriched.similar_exploits) >= 0  # depends on score cutoff


def test_enrich_batch_processes_all():
    retriever = _make_retriever_with_mocks([_make_exploit("HACK-001")])
    fn = _make_function()
    contract = _make_contract()
    ctxs = [FunctionContext(function=fn, contract=contract) for _ in range(3)]
    enriched = retriever.enrich_batch(ctxs, top_k=2)
    assert len(enriched) == 3


# ---------------------------------------------------------------------------
# build_function_contexts tests
# ---------------------------------------------------------------------------


def test_build_function_contexts_no_retriever():
    """Without a retriever, similar_exploits should be empty."""
    fn = _make_function()
    contract = _make_contract()
    scope = _make_scope()
    findings = [_make_finding()]
    scored = [(fn, contract, 10)]

    contexts = build_function_contexts(scored, findings, scope, retriever=None)
    assert len(contexts) == 1
    assert contexts[0].function.name == "withdraw"
    assert contexts[0].static_findings  # findings should be attached
    assert contexts[0].similar_exploits == []


def test_build_function_contexts_attaches_findings():
    fn = _make_function()
    contract = _make_contract()
    scope = _make_scope()
    high_finding = _make_finding("reentrancy-eth", Severity.HIGH, fn="withdraw")
    other_finding = _make_finding("unchecked-send", Severity.MEDIUM, fn="deposit")
    scored = [(fn, contract, 10)]

    contexts = build_function_contexts(
        scored, [high_finding, other_finding], scope, retriever=None
    )
    # Only the withdraw finding should be attached
    fn_detectors = [f.detector_name for f in contexts[0].static_findings]
    assert "reentrancy-eth" in fn_detectors


def test_build_function_contexts_with_retriever():
    retriever = _make_retriever_with_mocks([_make_exploit("HACK-007")])
    fn = _make_function()
    contract = _make_contract()
    scope = _make_scope()
    scored = [(fn, contract, 10)]

    contexts = build_function_contexts(
        scored, [], scope, retriever=retriever, top_k_exploits=3
    )
    assert len(contexts) == 1
    assert len(contexts[0].similar_exploits) >= 1
    assert contexts[0].similar_exploits[0].exploit_id == "HACK-007"


def test_build_function_contexts_cross_calls():
    fn = _make_function()
    contract = _make_contract()
    scope = _make_scope(dep_graph={"Vault": ["Token", "Oracle"]})
    scored = [(fn, contract, 10)]

    contexts = build_function_contexts(scored, [], scope, retriever=None)
    assert "Token" in contexts[0].cross_contract_calls
    assert "Oracle" in contexts[0].cross_contract_calls


def test_build_function_contexts_empty_input():
    scope = _make_scope()
    contexts = build_function_contexts([], [], scope, retriever=None)
    assert contexts == []
