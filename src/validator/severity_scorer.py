"""
VulnHound Validator — Severity Scorer

Re-scores finding severity using the CVSS-inspired formula:
    score = Exploitability × Impact × Likelihood

Each dimension is rated 1–3:
  Exploitability: 3=public/no-auth, 2=auth-required, 1=internal-only
  Impact:         3=fund-loss/critical, 2=state-corruption, 1=informational
  Likelihood:     3=deterministic (always triggers), 2=conditional, 1=theoretical

Resulting score [1–27] maps to final Severity enum.
"""

from __future__ import annotations

from src.models import Finding, Severity, VulnCategory


# Category → base impact score
_CATEGORY_IMPACT: dict[VulnCategory, int] = {
    VulnCategory.REENTRANCY: 3,
    VulnCategory.FLASH_LOAN: 3,
    VulnCategory.PRICE_MANIPULATION: 3,
    VulnCategory.ORACLE_MANIPULATION: 3,
    VulnCategory.ACCESS_CONTROL: 3,
    VulnCategory.INTEGER_OVERFLOW: 2,
    VulnCategory.UNCHECKED_EXTERNAL_CALL: 2,
    VulnCategory.DELEGATE_CALL: 3,
    VulnCategory.STORAGE_COLLISION: 3,
    VulnCategory.LOGIC_ERROR: 2,
    VulnCategory.INPUT_VALIDATION: 2,
    VulnCategory.FRONT_RUNNING: 2,
    VulnCategory.GOVERNANCE: 2,
    VulnCategory.CROSS_CHAIN: 2,
    VulnCategory.TOKEN_STANDARD: 1,
    VulnCategory.DENIAL_OF_SERVICE: 2,
    VulnCategory.GAS_OPTIMIZATION: 1,
    VulnCategory.OTHER: 1,
}

# Keywords that suggest no access control (exploitability = 3)
_NO_AUTH_KEYWORDS = frozenset({
    "onlyowner", "onlyadmin", "onlyrole", "onlygov",
    "onlyauthorized", "requiresauth", "auth", "restricted",
})

# Score thresholds → Severity
_SCORE_THRESHOLDS = [
    (20, Severity.CRITICAL),
    (14, Severity.HIGH),
    (8,  Severity.MEDIUM),
    (4,  Severity.LOW),
    (0,  Severity.INFORMATIONAL),
]


def rescore_finding(finding: Finding) -> Finding:
    """
    Compute a refined severity for a finding.

    Only upgrades findings — never downgrades a CRITICAL to lower.
    Returns a copy with potentially updated severity.
    """
    exploitability = _estimate_exploitability(finding)
    impact = _CATEGORY_IMPACT.get(finding.category, 1)
    likelihood = _estimate_likelihood(finding)

    raw_score = exploitability * impact * likelihood
    new_severity = _score_to_severity(raw_score)

    # Never downgrade
    current_rank = _severity_rank(finding.severity)
    new_rank = _severity_rank(new_severity)
    final_severity = finding.severity if current_rank >= new_rank else new_severity

    if final_severity == finding.severity:
        return finding

    return finding.model_copy(update={"severity": final_severity})


def rescore_all(findings: list[Finding]) -> list[Finding]:
    """Apply rescore_finding to every finding."""
    return [rescore_finding(f) for f in findings]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _estimate_exploitability(finding: Finding) -> int:
    """1=internal, 2=requires-auth, 3=public/no-auth."""
    desc_lower = (finding.description or "").lower()
    title_lower = finding.title.lower()
    combined = desc_lower + " " + title_lower

    # No access control keywords → assume public
    if not any(kw in combined for kw in _NO_AUTH_KEYWORDS):
        return 3

    # Access control present → 2
    return 2


def _estimate_likelihood(finding: Finding) -> int:
    """1=theoretical, 2=conditional, 3=deterministic."""
    if finding.confidence >= 0.8:
        return 3
    if finding.confidence >= 0.5:
        return 2
    return 1


def _score_to_severity(score: int) -> Severity:
    for threshold, sev in _SCORE_THRESHOLDS:
        if score > threshold:
            return sev
    return Severity.INFORMATIONAL


def _severity_rank(s: Severity) -> int:
    ranks = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFORMATIONAL: 1,
    }
    return ranks.get(s, 0)
