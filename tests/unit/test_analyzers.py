"""
Tests for Stage 2: Static Analyzers

Tests the Slither JSON parser, severity/category mapping, deduplication,
and the analyze_repo orchestrator — all without network calls or
requiring Slither/solc to be installed.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.models import FindingSource, ProjectScope, Severity, StaticAnalysisFinding, ContractInfo
from src.analyzers.slither_runner import (
    _parse_detector,
    _sort_findings,
    _IMPACT_MAP,
    _DETECTOR_CATEGORY,
    is_slither_available,
)
from src.analyzers.aderyn_runner import (
    _parse_instance,
    is_aderyn_available,
)
from src.analyzers import _deduplicate, _pick_slither_target, analyze_repo


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_detector(
    check="reentrancy-eth",
    impact="High",
    confidence="Medium",
    description="Reentrancy in Vault.withdraw",
    filename="contracts/Vault.sol",
    lines=None,
    contract="Vault",
    function="withdraw",
) -> dict:
    """Build a minimal Slither detector dict."""
    return {
        "check": check,
        "impact": impact,
        "confidence": confidence,
        "description": description,
        "elements": [
            {
                "type": "function",
                "name": function,
                "source_mapping": {
                    "filename_relative": filename,
                    "lines": lines or [45, 46, 47],
                },
                "type_specific_fields": {
                    "parent": {"type": "contract", "name": contract}
                },
            }
        ],
    }


def _make_scope(tmp_path: Path) -> ProjectScope:
    """Create a minimal ProjectScope pointing to tmp_path."""
    sol = tmp_path / "contracts" / "Vault.sol"
    sol.parent.mkdir(parents=True, exist_ok=True)
    sol.write_text("contract Vault {}")
    return ProjectScope(
        repo_url=None,
        repo_path=str(tmp_path),
        framework="unknown",
        compiler_version="0.8.20",
        contracts=[
            ContractInfo(name="Vault", file_path=str(sol), loc=1)
        ],
    )


# ── slither_runner: _parse_detector ──────────────────────────────────────────

def test_parse_detector_reentrancy():
    d = _make_detector(check="reentrancy-eth", impact="High")
    finding = _parse_detector(d)
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.tool == FindingSource.SLITHER
    assert finding.detector_name == "reentrancy-eth"
    assert finding.contract == "Vault"
    assert finding.function == "withdraw"
    assert finding.line_start == 45


def test_parse_detector_medium_severity():
    d = _make_detector(check="incorrect-equality", impact="Medium", confidence="High")
    finding = _parse_detector(d)
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == "high"


def test_parse_detector_informational():
    d = _make_detector(check="naming-convention", impact="Informational")
    finding = _parse_detector(d)
    assert finding.severity == Severity.INFORMATIONAL


def test_parse_detector_unknown_check_defaults_to_logic_error():
    from src.models import VulnCategory
    d = _make_detector(check="some-unknown-detector", impact="Low")
    finding = _parse_detector(d)
    assert finding is not None
    assert finding.severity == Severity.LOW


def test_parse_detector_empty_elements():
    """Detector with no elements should still parse."""
    d = {
        "check": "reentrancy-eth",
        "impact": "High",
        "confidence": "Medium",
        "description": "Reentrancy found",
        "elements": [],
    }
    finding = _parse_detector(d)
    assert finding is not None
    assert finding.contract == "unknown"
    assert finding.line_start == 0


def test_parse_detector_line_end_set_when_multiple_lines():
    d = _make_detector(lines=[10, 11, 12, 13, 14])
    finding = _parse_detector(d)
    assert finding.line_start == 10
    assert finding.line_end == 14


def test_parse_detector_single_line():
    d = _make_detector(lines=[42])
    finding = _parse_detector(d)
    assert finding.line_start == 42
    assert finding.line_end is None


# ── slither_runner: impact / category maps ────────────────────────────────────

def test_impact_map_covers_all_slither_impacts():
    for impact in ("High", "Medium", "Low", "Informational", "Optimization"):
        assert impact in _IMPACT_MAP, f"Missing impact: {impact}"


def test_detector_category_map_has_common_detectors():
    important = [
        "reentrancy-eth", "reentrancy-no-eth",
        "unchecked-transfer", "arbitrary-send-eth",
        "delegatecall-loop", "timestamp",
        "tx-origin", "integer-overflow",
    ]
    for det in important:
        assert det in _DETECTOR_CATEGORY, f"Missing detector mapping: {det}"


# ── slither_runner: _sort_findings ───────────────────────────────────────────

def test_sort_findings_by_severity():
    f_med = StaticAnalysisFinding(
        tool=FindingSource.SLITHER, detector_name="x", severity=Severity.MEDIUM,
        confidence="high", description="", contract="A", file_path="A.sol", line_start=1,
    )
    f_high = StaticAnalysisFinding(
        tool=FindingSource.SLITHER, detector_name="y", severity=Severity.HIGH,
        confidence="high", description="", contract="B", file_path="B.sol", line_start=2,
    )
    f_info = StaticAnalysisFinding(
        tool=FindingSource.SLITHER, detector_name="z", severity=Severity.INFORMATIONAL,
        confidence="low", description="", contract="C", file_path="C.sol", line_start=3,
    )
    sorted_f = _sort_findings([f_info, f_med, f_high])
    assert sorted_f[0].severity == Severity.HIGH
    assert sorted_f[1].severity == Severity.MEDIUM
    assert sorted_f[2].severity == Severity.INFORMATIONAL


# ── aderyn_runner: _parse_instance ───────────────────────────────────────────

def test_parse_aderyn_instance():
    issue = {
        "title": "Unsafe ERC20 Operation",
        "description": "Use safeTransfer instead of transfer",
        "detector_name": "unsafe-erc20-operation",
    }
    instance = {
        "contract_path": "contracts/Token.sol",
        "line_no": 55,
        "src_char": "token.transfer(to, amount);",
    }
    finding = _parse_instance(issue, instance, Severity.HIGH)
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.tool == FindingSource.ADERYN
    assert finding.line_start == 55
    assert finding.contract == "Token"
    assert "Unsafe ERC20" in finding.description


def test_parse_aderyn_instance_no_src_char():
    issue = {"title": "Reentrancy", "description": "...", "detector_name": "reentrancy"}
    instance = {"contract_path": "Vault.sol", "line_no": 10}
    finding = _parse_instance(issue, instance, Severity.HIGH)
    assert finding is not None
    assert finding.code_snippet is None


# ── analyzers/__init__: _deduplicate ─────────────────────────────────────────

def _make_finding(detector="reentrancy-eth", contract="Vault", line=45,
                  severity=Severity.HIGH, tool=FindingSource.SLITHER):
    return StaticAnalysisFinding(
        tool=tool, detector_name=detector, severity=severity,
        confidence="medium", description="test", contract=contract,
        file_path="Vault.sol", line_start=line,
    )


def test_deduplicate_removes_exact_duplicates():
    f1 = _make_finding()
    f2 = _make_finding()  # identical key
    result = _deduplicate([f1, f2])
    assert len(result) == 1


def test_deduplicate_keeps_higher_severity():
    f_med = _make_finding(severity=Severity.MEDIUM)
    f_high = _make_finding(severity=Severity.HIGH)
    result = _deduplicate([f_med, f_high])
    assert len(result) == 1
    assert result[0].severity == Severity.HIGH


def test_deduplicate_keeps_different_lines():
    f1 = _make_finding(line=10)
    f2 = _make_finding(line=20)
    result = _deduplicate([f1, f2])
    assert len(result) == 2


def test_deduplicate_keeps_different_contracts():
    f1 = _make_finding(contract="Vault")
    f2 = _make_finding(contract="Token")
    result = _deduplicate([f1, f2])
    assert len(result) == 2


def test_deduplicate_cross_tool_same_location():
    f_slither = _make_finding(tool=FindingSource.SLITHER, severity=Severity.HIGH)
    f_aderyn  = _make_finding(tool=FindingSource.ADERYN,  severity=Severity.MEDIUM)
    result = _deduplicate([f_slither, f_aderyn])
    # Same detector+contract+line → deduplicated, keep HIGH
    assert len(result) == 1
    assert result[0].severity == Severity.HIGH


# ── analyzers/__init__: _pick_slither_target ─────────────────────────────────

def test_pick_slither_target_single_dir(tmp_path):
    scope = _make_scope(tmp_path)
    target = _pick_slither_target(scope)
    # All contracts are under contracts/ → should point there
    assert target.is_dir()


def test_pick_slither_target_no_contracts(tmp_path):
    scope = ProjectScope(
        repo_url=None,
        repo_path=str(tmp_path),
        framework="unknown",
        compiler_version=None,
    )
    target = _pick_slither_target(scope)
    assert target == tmp_path


# ── analyze_repo: integration (mocked Slither) ───────────────────────────────

def test_analyze_repo_returns_findings_when_slither_mocked(tmp_path):
    scope = _make_scope(tmp_path)
    mock_findings = [
        _make_finding("reentrancy-eth", severity=Severity.HIGH),
        _make_finding("timestamp", severity=Severity.LOW),
    ]

    with patch("src.analyzers.is_slither_available", return_value=True), \
         patch("src.analyzers.run_slither", return_value=mock_findings), \
         patch("src.analyzers.is_aderyn_available", return_value=False):
        results = analyze_repo(scope)

    assert len(results) == 2
    # HIGH should come first
    assert results[0].severity == Severity.HIGH


def test_analyze_repo_graceful_when_slither_unavailable(tmp_path):
    scope = _make_scope(tmp_path)

    with patch("src.analyzers.is_slither_available", return_value=False), \
         patch("src.analyzers.is_aderyn_available", return_value=False):
        results = analyze_repo(scope)

    assert results == []


def test_analyze_repo_deduplicates(tmp_path):
    scope = _make_scope(tmp_path)
    f = _make_finding("reentrancy-eth", severity=Severity.HIGH)

    with patch("src.analyzers.is_slither_available", return_value=True), \
         patch("src.analyzers.run_slither", return_value=[f, f, f]), \
         patch("src.analyzers.is_aderyn_available", return_value=False):
        results = analyze_repo(scope)

    assert len(results) == 1


def test_analyze_repo_slither_exception_doesnt_crash(tmp_path):
    scope = _make_scope(tmp_path)

    with patch("src.analyzers.is_slither_available", return_value=True), \
         patch("src.analyzers.run_slither", side_effect=RuntimeError("solc crash")), \
         patch("src.analyzers.is_aderyn_available", return_value=False):
        results = analyze_repo(scope)

    assert results == []
