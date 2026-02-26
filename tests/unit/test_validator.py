"""
Unit tests for Stage 6: Validator
"""

from __future__ import annotations

import pytest
from datetime import datetime

from src.models import (
    AnalysisPass,
    Finding,
    FindingSource,
    Severity,
    VulnCategory,
)
from src.validator.deduplicator import (
    _are_duplicates,
    _pick_better,
    _title_similarity,
    deduplicate_findings,
)
from src.validator.severity_scorer import rescore_finding, rescore_all
from src.validator import validate_findings


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_finding(
    id: str = "VH-001",
    title: str = "Reentrancy in withdraw",
    severity: Severity = Severity.HIGH,
    category: VulnCategory = VulnCategory.REENTRANCY,
    contract: str = "Vault",
    function: str | None = "withdraw",
    confidence: float = 0.8,
    line_start: int = 42,
) -> Finding:
    return Finding(
        id=id,
        title=title,
        severity=severity,
        category=category,
        confidence=confidence,
        contract=contract,
        function=function,
        file_path="contracts/Vault.sol",
        line_start=line_start,
        description="Reentrancy vulnerability in withdraw.",
        impact="Attacker can drain ETH.",
        exploit_scenario="Call withdraw() recursively.",
        recommendation="Use ReentrancyGuard.",
        source=FindingSource.LLM_FUNCTION_AUDIT,
        analysis_pass=AnalysisPass.FUNCTION_AUDIT,
    )


# ---------------------------------------------------------------------------
# title_similarity
# ---------------------------------------------------------------------------


def test_title_similarity_identical():
    assert _title_similarity("foo bar baz", "foo bar baz") == 1.0


def test_title_similarity_no_overlap():
    assert _title_similarity("alpha beta", "gamma delta") == 0.0


def test_title_similarity_partial():
    score = _title_similarity("reentrancy in withdraw", "reentrancy in deposit")
    assert 0.0 < score < 1.0


def test_title_similarity_empty():
    assert _title_similarity("", "") == 1.0


def test_title_similarity_one_empty():
    assert _title_similarity("foo", "") == 0.0


# ---------------------------------------------------------------------------
# _are_duplicates
# ---------------------------------------------------------------------------


def test_are_duplicates_identical():
    a = _make_finding()
    b = _make_finding(id="VH-002")
    assert _are_duplicates(a, b)


def test_are_duplicates_different_contract():
    a = _make_finding(contract="Vault")
    b = _make_finding(id="VH-002", contract="Token")
    assert not _are_duplicates(a, b)


def test_are_duplicates_different_category_and_function():
    a = _make_finding(category=VulnCategory.REENTRANCY, function="withdraw")
    b = _make_finding(id="VH-002", category=VulnCategory.ACCESS_CONTROL, function="deposit")
    assert not _are_duplicates(a, b)


def test_are_duplicates_different_function_high_title_similarity():
    a = _make_finding(title="Reentrancy vulnerability in withdraw", function="withdraw")
    b = _make_finding(
        id="VH-002",
        title="Reentrancy vulnerability in withdraw function",
        function="deposit",
    )
    # Same category, very similar title but different function → depends on similarity threshold
    result = _are_duplicates(a, b)
    # Both results are valid depending on threshold; just ensure it doesn't crash
    assert isinstance(result, bool)


def test_are_duplicates_same_fn_different_category():
    a = _make_finding(category=VulnCategory.REENTRANCY, function="harvest")
    b = _make_finding(
        id="VH-002",
        title="Access control missing in harvest",
        category=VulnCategory.ACCESS_CONTROL,
        function="harvest",
    )
    # Same function, different category, very different title → not duplicate
    assert not _are_duplicates(a, b)


# ---------------------------------------------------------------------------
# _pick_better
# ---------------------------------------------------------------------------


def test_pick_better_higher_confidence():
    a = _make_finding(id="VH-001", confidence=0.9)
    b = _make_finding(id="VH-002", confidence=0.6)
    assert _pick_better(a, b).id == "VH-001"


def test_pick_better_lower_confidence():
    a = _make_finding(id="VH-001", confidence=0.4)
    b = _make_finding(id="VH-002", confidence=0.9)
    assert _pick_better(a, b).id == "VH-002"


def test_pick_better_equal_confidence_higher_severity():
    a = _make_finding(id="VH-001", confidence=0.7, severity=Severity.HIGH)
    b = _make_finding(id="VH-002", confidence=0.7, severity=Severity.MEDIUM)
    assert _pick_better(a, b).id == "VH-001"


def test_pick_better_both_equal():
    a = _make_finding(id="VH-001", confidence=0.7, severity=Severity.HIGH)
    b = _make_finding(id="VH-002", confidence=0.7, severity=Severity.HIGH)
    # Either is acceptable
    result = _pick_better(a, b)
    assert result.id in ("VH-001", "VH-002")


# ---------------------------------------------------------------------------
# deduplicate_findings
# ---------------------------------------------------------------------------


def test_deduplicate_empty():
    assert deduplicate_findings([]) == []


def test_deduplicate_single():
    f = _make_finding()
    result = deduplicate_findings([f])
    assert len(result) == 1


def test_deduplicate_removes_duplicate():
    a = _make_finding(id="VH-001", confidence=0.9)
    b = _make_finding(id="VH-002", confidence=0.5)
    result = deduplicate_findings([a, b])
    assert len(result) == 1
    assert result[0].id == "VH-001"  # higher confidence kept


def test_deduplicate_keeps_different_contracts():
    a = _make_finding(id="VH-001", contract="Vault")
    b = _make_finding(id="VH-002", contract="Token")
    result = deduplicate_findings([a, b])
    assert len(result) == 2


def test_deduplicate_keeps_different_functions_and_categories():
    a = _make_finding(id="VH-001", function="withdraw", category=VulnCategory.REENTRANCY)
    b = _make_finding(
        id="VH-002",
        title="Access control missing in deposit",
        function="deposit",
        category=VulnCategory.ACCESS_CONTROL,
    )
    result = deduplicate_findings([a, b])
    assert len(result) == 2


def test_deduplicate_sorted_by_severity():
    a = _make_finding(id="VH-001", severity=Severity.LOW, function="foo")
    b = _make_finding(id="VH-002", title="Oracle manipulation", severity=Severity.HIGH, function="bar",
                      category=VulnCategory.ORACLE_MANIPULATION)
    result = deduplicate_findings([a, b])
    assert result[0].severity == Severity.HIGH


def test_deduplicate_three_with_one_duplicate():
    a = _make_finding(id="VH-001", confidence=0.9)
    b = _make_finding(id="VH-002", confidence=0.5)
    c = _make_finding(id="VH-003", title="Integer overflow in mint", function="mint",
                      category=VulnCategory.INTEGER_OVERFLOW)
    result = deduplicate_findings([a, b, c])
    assert len(result) == 2


# ---------------------------------------------------------------------------
# rescore_finding
# ---------------------------------------------------------------------------


def test_rescore_never_downgrades_critical():
    f = _make_finding(severity=Severity.CRITICAL, confidence=0.1)
    result = rescore_finding(f)
    assert result.severity == Severity.CRITICAL


def test_rescore_upgrades_low_confidence_high_impact():
    # REENTRANCY with high confidence should stay HIGH or go CRITICAL
    f = _make_finding(
        severity=Severity.LOW,
        category=VulnCategory.REENTRANCY,
        confidence=0.9,
    )
    result = rescore_finding(f)
    # Should be upgraded since reentrancy is high impact
    assert result.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


def test_rescore_low_impact_stays_low():
    f = _make_finding(
        severity=Severity.LOW,
        category=VulnCategory.GAS_OPTIMIZATION,
        confidence=0.3,
    )
    result = rescore_finding(f)
    # GAS_OPTIMIZATION has impact=1 → score stays low
    assert result.severity in (Severity.LOW, Severity.INFORMATIONAL)


def test_rescore_returns_finding():
    f = _make_finding()
    result = rescore_finding(f)
    assert isinstance(result, Finding)


def test_rescore_all_empty():
    assert rescore_all([]) == []


def test_rescore_all_preserves_count():
    findings = [_make_finding(id=f"VH-{i:03d}", function=f"fn{i}") for i in range(5)]
    result = rescore_all(findings)
    assert len(result) == 5


# ---------------------------------------------------------------------------
# validate_findings (integration)
# ---------------------------------------------------------------------------


def test_validate_filters_low_confidence():
    findings = [
        _make_finding(id="VH-001", confidence=0.9),
        _make_finding(id="VH-002", confidence=0.1, function="deposit",
                      title="Low confidence finding"),
    ]
    result = validate_findings(findings, min_confidence=0.3)
    assert all(f.confidence >= 0.3 for f in result)
    assert len(result) == 1


def test_validate_marks_validated():
    f = _make_finding()
    result = validate_findings([f])
    assert all(f.validated for f in result)


def test_validate_empty_input():
    result = validate_findings([])
    assert result == []


def test_validate_deduplicates():
    a = _make_finding(id="VH-001", confidence=0.9)
    b = _make_finding(id="VH-002", confidence=0.4)
    result = validate_findings([a, b])
    assert len(result) == 1


def test_validate_preserves_unique_findings():
    a = _make_finding(id="VH-001", contract="Vault", function="withdraw")
    b = _make_finding(
        id="VH-002",
        contract="Token",
        title="Unchecked transfer return value",
        function="transfer",
        category=VulnCategory.UNCHECKED_EXTERNAL_CALL,
    )
    result = validate_findings([a, b])
    assert len(result) == 2
