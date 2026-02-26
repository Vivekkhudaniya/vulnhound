"""
Unit tests for Stage 7: Markdown Reporter
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.models import (
    AnalysisPass,
    ContractInfo,
    Finding,
    FindingSource,
    ProjectScope,
    RetrievedExploit,
    Severity,
    VulnCategory,
)
from src.reporter.markdown import (
    _render_executive_summary,
    _render_findings,
    _render_header,
    _render_scope,
    _render_single_finding,
    generate_markdown_report,
)
from src.reporter import generate_report


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_scope(contracts: int = 5, loc: int = 1000) -> ProjectScope:
    return ProjectScope(
        repo_path="./data/repos/my-protocol",
        repo_url="https://github.com/example/my-protocol",
        framework="foundry",
        compiler_version="0.8.24",
        contracts=[
            ContractInfo(
                name=f"Contract{i}",
                file_path=f"contracts/Contract{i}.sol",
                loc=loc // contracts,
                is_proxy=(i == 0),
            )
            for i in range(contracts)
        ],
        total_loc=loc,
    )


def _make_finding(
    id: str = "VH-001",
    title: str = "Reentrancy in withdraw",
    severity: Severity = Severity.HIGH,
    category: VulnCategory = VulnCategory.REENTRANCY,
    contract: str = "Vault",
    function: str | None = "withdraw",
    confidence: float = 0.85,
    line_start: int = 42,
    vulnerable_code: str | None = None,
    suggested_fix: str | None = None,
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
        description="Reentrancy vulnerability in withdraw function.",
        impact="Attacker can drain all ETH from the vault.",
        exploit_scenario="Attacker deploys contract with receive() that re-enters withdraw().",
        recommendation="Add ReentrancyGuard modifier or use checks-effects-interactions pattern.",
        vulnerable_code=vulnerable_code,
        suggested_fix=suggested_fix,
        source=FindingSource.LLM_FUNCTION_AUDIT,
        analysis_pass=AnalysisPass.FUNCTION_AUDIT,
    )


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


def test_render_header_contains_repo_name():
    scope = _make_scope()
    header = _render_header(scope, "TestAuditor")
    assert "my-protocol" in header


def test_render_header_contains_auditor():
    scope = _make_scope()
    header = _render_header(scope, "VulnHound AI")
    assert "VulnHound AI" in header


def test_render_header_contains_compiler():
    scope = _make_scope()
    header = _render_header(scope, "Auditor")
    assert "0.8.24" in header


def test_render_header_contains_url():
    scope = _make_scope()
    header = _render_header(scope, "Auditor")
    assert "https://github.com/example/my-protocol" in header


def test_render_header_no_url():
    scope = ProjectScope(
        repo_path="./data/repos/local",
        contracts=[],
        total_loc=0,
    )
    header = _render_header(scope, "Auditor")
    assert "local" in header
    assert "**Repository:**" not in header


# ---------------------------------------------------------------------------
# Executive Summary
# ---------------------------------------------------------------------------


def test_executive_summary_contains_count():
    findings = [_make_finding()]
    scope = _make_scope()
    summary = _render_executive_summary(findings, scope)
    assert "1" in summary  # 1 HIGH


def test_executive_summary_severity_table():
    findings = [
        _make_finding(id="VH-001", severity=Severity.CRITICAL, function="fn1"),
        _make_finding(id="VH-002", severity=Severity.HIGH, function="fn2"),
        _make_finding(id="VH-003", severity=Severity.MEDIUM, function="fn3"),
    ]
    scope = _make_scope()
    summary = _render_executive_summary(findings, scope)
    assert "CRITICAL" in summary
    assert "HIGH" in summary
    assert "MEDIUM" in summary


def test_executive_summary_key_findings():
    high = _make_finding(id="VH-001", severity=Severity.HIGH)
    low = _make_finding(id="VH-002", severity=Severity.LOW, function="foo",
                        title="Unused return value")
    scope = _make_scope()
    summary = _render_executive_summary([high, low], scope)
    # HIGH should be in key findings section
    assert "VH-001" in summary


def test_executive_summary_no_high_findings():
    findings = [_make_finding(severity=Severity.LOW, title="Gas optimization")]
    scope = _make_scope()
    summary = _render_executive_summary(findings, scope)
    # Key findings section should be absent
    assert "Key Findings" not in summary


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


def test_render_scope_lists_contracts():
    scope = _make_scope(contracts=3)
    rendered = _render_scope(scope)
    assert "Contract0" in rendered
    assert "Contract1" in rendered
    assert "Contract2" in rendered


def test_render_scope_marks_proxy():
    scope = _make_scope(contracts=3)
    rendered = _render_scope(scope)
    assert "✓" in rendered  # proxy marker


def test_render_scope_shows_loc():
    scope = _make_scope(loc=5000)
    rendered = _render_scope(scope)
    assert "5,000" in rendered


# ---------------------------------------------------------------------------
# Single Finding
# ---------------------------------------------------------------------------


def test_render_single_finding_contains_id():
    f = _make_finding()
    rendered = _render_single_finding(f)
    assert "VH-001" in rendered


def test_render_single_finding_contains_severity():
    f = _make_finding(severity=Severity.HIGH)
    rendered = _render_single_finding(f)
    assert "HIGH" in rendered


def test_render_single_finding_contains_location():
    f = _make_finding(contract="Vault", function="withdraw", line_start=99)
    rendered = _render_single_finding(f)
    assert "Vault" in rendered
    assert "withdraw" in rendered
    assert "99" in rendered


def test_render_single_finding_with_code():
    f = _make_finding(
        vulnerable_code="(bool ok,) = addr.call{value: amount}('');",
        suggested_fix="require(ok, 'transfer failed');",
    )
    rendered = _render_single_finding(f)
    assert "```solidity" in rendered
    assert "addr.call" in rendered


def test_render_single_finding_with_exploits():
    exploit = RetrievedExploit(
        exploit_id="HACK-2023-001",
        protocol="BadProtocol",
        similarity_score=0.92,
        category=VulnCategory.REENTRANCY,
        description="Classic reentrancy drain",
        loss_usd=1_000_000,
        attack_summary="Reentrant withdraw drained pool",
    )
    f = _make_finding()
    f = f.model_copy(update={"similar_exploits": [exploit]})
    rendered = _render_single_finding(f)
    assert "BadProtocol" in rendered
    assert "1,000,000" in rendered


def test_render_single_finding_no_function():
    f = _make_finding(function=None)
    rendered = _render_single_finding(f)
    assert "Vault" in rendered
    assert "None" not in rendered


# ---------------------------------------------------------------------------
# Findings section
# ---------------------------------------------------------------------------


def test_render_findings_empty():
    rendered = _render_findings([])
    assert "No findings" in rendered


def test_render_findings_separates_minor():
    high = _make_finding(id="VH-001", severity=Severity.HIGH)
    low = _make_finding(id="VH-002", severity=Severity.LOW, function="foo",
                        title="Unused return value")
    rendered = _render_findings([high, low])
    assert "Informational / Low" in rendered
    assert "VH-001" in rendered
    assert "VH-002" in rendered


def test_render_findings_only_high_no_minor_section():
    high = _make_finding(id="VH-001", severity=Severity.HIGH)
    rendered = _render_findings([high])
    assert "Informational / Low" not in rendered


# ---------------------------------------------------------------------------
# Full report
# ---------------------------------------------------------------------------


def test_generate_markdown_report_is_string():
    findings = [_make_finding()]
    scope = _make_scope()
    report = generate_markdown_report(findings, scope)
    assert isinstance(report, str)
    assert len(report) > 100


def test_generate_markdown_report_sections():
    findings = [_make_finding()]
    scope = _make_scope()
    report = generate_markdown_report(findings, scope)
    assert "Executive Summary" in report
    assert "Audit Scope" in report
    assert "Findings" in report
    assert "Methodology" in report
    assert "Disclaimer" in report


def test_generate_report_writes_file(tmp_path):
    findings = [_make_finding()]
    scope = _make_scope()
    out = tmp_path / "report.md"
    report = generate_markdown_report(findings, scope, output_path=out)
    assert out.exists()
    assert out.read_text(encoding="utf-8") == report


def test_generate_report_no_findings():
    scope = _make_scope()
    report = generate_markdown_report([], scope)
    assert "No findings" in report


def test_generate_report_public_api():
    findings = [_make_finding()]
    scope = _make_scope()
    report = generate_report(findings, scope)
    assert "VulnHound" in report


def test_generate_report_unsupported_format():
    scope = _make_scope()
    with pytest.raises(ValueError, match="Unsupported"):
        generate_report([], scope, format="pdf")
