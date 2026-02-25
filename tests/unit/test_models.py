"""
Tests for core data models.

Run with: pytest tests/unit/test_models.py -v
"""

from datetime import datetime

from src.models import (
    AuditReport,
    Chain,
    CodeContext,
    ExploitDocument,
    ExploitMechanism,
    Finding,
    FindingSource,
    AnalysisPass,
    ProjectScope,
    Severity,
    VulnCategory,
    VulnerabilityPattern,
)


def test_exploit_document_creation():
    """Test creating an ExploitDocument with all fields."""
    doc = ExploitDocument(
        id="HACK-2023-0001",
        protocol="Euler Finance",
        date=datetime(2023, 3, 13),
        chain=Chain.ETHEREUM,
        loss_usd=197_000_000,
        recovered=True,
        vulnerability=VulnerabilityPattern(
            category=VulnCategory.LOGIC_ERROR,
            subcategory="donation_attack",
            description="Flawed health check logic in liquidation",
            root_cause="Missing check on self-liquidation + donation flow",
            affected_functions=["liquidate()", "donateToReserves()"],
            owasp_mapping="SC01:2025",
        ),
        code_context=CodeContext(
            vulnerable_snippet="function donateToReserves() { ... }",
            fix_snippet="Added health factor check after donation",
            contract_name="EToken.sol",
            solidity_version="0.8.17",
        ),
        exploit_mechanism=ExploitMechanism(
            attack_steps=[
                "Flash loan 30M DAI from Aave",
                "Deposit into Euler",
                "Mint eTokens",
                "Donate to reserves",
                "Self-liquidate at profit",
            ],
            tx_hash="0x47ac3527d02e3b99a9e5f1d67a71bba4d77d2b2c0bc tried...",
        ),
        source="defihacklabs",
        tags=["logic_error", "flash_loan", "ethereum"],
    )

    assert doc.id == "HACK-2023-0001"
    assert doc.protocol == "Euler Finance"
    assert doc.loss_usd == 197_000_000
    assert doc.vulnerability.category == VulnCategory.LOGIC_ERROR
    assert len(doc.exploit_mechanism.attack_steps) == 5
    assert doc.recovered is True


def test_finding_creation():
    """Test creating a Finding object."""
    finding = Finding(
        id="VH-001",
        title="Reentrancy in withdraw()",
        severity=Severity.CRITICAL,
        category=VulnCategory.REENTRANCY,
        confidence=0.92,
        contract="Vault.sol",
        function="withdraw(uint256)",
        file_path="src/Vault.sol",
        line_start=142,
        line_end=165,
        description="The withdraw function sends ETH before updating state",
        impact="Attacker can drain all funds from the vault",
        exploit_scenario="1. Deposit 1 ETH\n2. Call withdraw\n3. Re-enter from receive()",
        recommendation="Use checks-effects-interactions pattern or ReentrancyGuard",
        source=FindingSource.LLM_FUNCTION_AUDIT,
        analysis_pass=AnalysisPass.FUNCTION_AUDIT,
    )

    assert finding.severity == Severity.CRITICAL
    assert finding.confidence == 0.92
    assert finding.validated is False
    assert finding.false_positive is False


def test_audit_report_compute_stats():
    """Test that audit report correctly computes finding statistics."""
    report = AuditReport(
        id="AUDIT-001",
        scope=ProjectScope(repo_path="./test-project"),
        findings=[
            Finding(
                id="VH-001",
                title="Critical bug",
                severity=Severity.CRITICAL,
                category=VulnCategory.REENTRANCY,
                confidence=0.9,
                contract="A.sol",
                file_path="A.sol",
                line_start=1,
                description="",
                impact="",
                exploit_scenario="",
                recommendation="",
                source=FindingSource.SLITHER,
                analysis_pass=AnalysisPass.FUNCTION_AUDIT,
            ),
            Finding(
                id="VH-002",
                title="High bug",
                severity=Severity.HIGH,
                category=VulnCategory.ACCESS_CONTROL,
                confidence=0.8,
                contract="B.sol",
                file_path="B.sol",
                line_start=1,
                description="",
                impact="",
                exploit_scenario="",
                recommendation="",
                source=FindingSource.LLM_CROSS_CONTRACT,
                analysis_pass=AnalysisPass.CROSS_CONTRACT,
            ),
            Finding(
                id="VH-003",
                title="Medium bug",
                severity=Severity.MEDIUM,
                category=VulnCategory.INPUT_VALIDATION,
                confidence=0.7,
                contract="C.sol",
                file_path="C.sol",
                line_start=1,
                description="",
                impact="",
                exploit_scenario="",
                recommendation="",
                source=FindingSource.LLM_ECONOMIC,
                analysis_pass=AnalysisPass.ECONOMIC_AUDIT,
            ),
        ],
    )

    report.compute_stats()

    assert report.total_findings == 3
    assert report.critical_count == 1
    assert report.high_count == 1
    assert report.medium_count == 1
    assert report.low_count == 0
    assert report.informational_count == 0


def test_severity_ordering():
    """Test that severity enum values are as expected."""
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"


def test_vuln_category_coverage():
    """Ensure all major vulnerability categories are represented."""
    critical_categories = [
        VulnCategory.REENTRANCY,
        VulnCategory.ACCESS_CONTROL,
        VulnCategory.LOGIC_ERROR,
        VulnCategory.PRICE_MANIPULATION,
        VulnCategory.FLASH_LOAN,
        VulnCategory.CROSS_CHAIN,
        VulnCategory.ORACLE_MANIPULATION,
        VulnCategory.INPUT_VALIDATION,
    ]

    for cat in critical_categories:
        assert cat in VulnCategory, f"Missing critical category: {cat}"
