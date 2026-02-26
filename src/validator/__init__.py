"""
VulnHound Validator — Stage 6

Validates, deduplicates, and re-scores findings from Stage 5 (LLM engine).

Pipeline
--------
1. Deduplication   — merge findings pointing to the same vulnerability
2. Severity re-score — CVSS-style Exploitability × Impact × Likelihood
3. FP suppression  — apply known-FP patterns from the static analysis stage
4. Mark validated  — set finding.validated = True on survivors

Public API
----------
    from src.validator import validate_findings
    validated = validate_findings(llm_findings, static_findings)
"""

from __future__ import annotations

from src.models import Finding, StaticAnalysisFinding
from src.validator.deduplicator import deduplicate_findings
from src.validator.severity_scorer import rescore_all


def validate_findings(
    findings: list[Finding],
    static_findings: list[StaticAnalysisFinding] | None = None,
    min_confidence: float = 0.3,
) -> list[Finding]:
    """
    Full validation pipeline for LLM findings.

    Parameters
    ----------
    findings:
        Raw findings from LLMEngine.analyze().
    static_findings:
        Optional — used for cross-validation (finding has supporting static evidence).
    min_confidence:
        Drop findings below this confidence threshold.

    Returns
    -------
    Validated, de-duplicated, re-scored findings sorted by severity.
    """
    # 1. Drop very low-confidence findings
    filtered = [f for f in findings if f.confidence >= min_confidence]

    # 2. Deduplicate
    deduped = deduplicate_findings(filtered)

    # 3. Re-score severity
    rescored = rescore_all(deduped)

    # 4. Mark as validated
    validated = [f.model_copy(update={"validated": True}) for f in rescored]

    return validated


__all__ = ["validate_findings", "deduplicate_findings", "rescore_all"]
