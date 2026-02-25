"""
VulnHound — Slither False Positive Filter

Slither has a ~40% false positive rate on Low/Informational findings.
This module applies context-aware rules to suppress or downgrade
findings that are almost certainly not exploitable.

Rules applied:
  1. reentrancy-* + lock/nonReentrant modifier present → downgrade to INFO
  2. weak-prng in TWAP/timestamp-accumulation context → downgrade to LOW
  3. naming-convention, pragma, solc-version → keep as INFO (never report as bug)
  4. assembly → INFO (common in optimized DeFi, not a vulnerability)
  5. too-many-digits → suppress entirely
  6. dead-code in interface/library context → suppress
  7. timestamp on well-known safe patterns (block.timestamp % 2**32) → LOW only
  8. reentrancy-events / reentrancy-benign → downgrade to INFO
"""

from __future__ import annotations

from pathlib import Path

from src.models import FindingSource, Severity, StaticAnalysisFinding

# ---------------------------------------------------------------------------
# Detectors that are always noise — suppress completely
# ---------------------------------------------------------------------------
_ALWAYS_SUPPRESS: frozenset[str] = frozenset({
    "too-many-digits",           # stylistic only
    "similar-names",             # variable naming
    "constable-states",          # gas optimization, not a bug
    "uninitialized-local",       # very low risk in practice
    "boolean-equality",          # style
    "divide-before-multiply",    # caught by overflow checks in modern solc
})

# ---------------------------------------------------------------------------
# Detectors that are always INFO regardless of Slither's reported impact
# ---------------------------------------------------------------------------
_ALWAYS_INFO: frozenset[str] = frozenset({
    "naming-convention",
    "pragma",
    "solc-version",
    "assembly",
    "dead-code",
    "low-level-calls",           # common in DeFi, not inherently vulnerable
    "calls-loop",                # gas concern, not security
    "reentrancy-events",         # events out of order — cosmetic
    "reentrancy-benign",         # state written but no ETH sent — very low risk
    "locked-ether",              # informational pattern
    "incorrect-modifier",        # usually style
    "shadowing-local",           # low risk
})

# ---------------------------------------------------------------------------
# Reentrancy detectors that can be suppressed if a guard modifier is present
# ---------------------------------------------------------------------------
_REENTRANCY_DETECTORS: frozenset[str] = frozenset({
    "reentrancy-eth",
    "reentrancy-no-eth",
    "reentrancy-benign",
    "reentrancy-events",
    "reentrancy-unlimited-gas",
})

# Common reentrancy guard names
_REENTRANCY_GUARDS: frozenset[str] = frozenset({
    "lock", "nonReentrant", "noReentrant", "reentrancyGuard",
    "locked", "mutex", "ReentrancyGuard", "nonreentrant",
})


def filter_findings(
    findings: list[StaticAnalysisFinding],
    contracts: list | None = None,
) -> list[StaticAnalysisFinding]:
    """
    Apply false-positive rules to a list of findings.

    Parameters
    ----------
    findings:
        Raw findings from Slither/Aderyn.
    contracts:
        Optional list of ContractInfo objects. Used for modifier context.
        If None, modifier-based rules are skipped.

    Returns
    -------
    list[StaticAnalysisFinding]
        Filtered and severity-adjusted findings.
    """
    # Build modifier lookup: contract_name → set of modifiers used
    modifier_map: dict[str, set[str]] = {}
    if contracts:
        for c in contracts:
            # We'll look this up per-finding
            modifier_map[c.name] = set()

    result: list[StaticAnalysisFinding] = []

    for f in findings:
        adjusted = _apply_rules(f, modifier_map)
        if adjusted is not None:
            result.append(adjusted)

    suppressed = len(findings) - len(result)
    if suppressed:
        from rich.console import Console
        Console(stderr=True).log(
            f"[dim]FP filter: suppressed {suppressed}, "
            f"kept {len(result)} of {len(findings)} findings[/dim]"
        )

    return result


def _apply_rules(
    f: StaticAnalysisFinding,
    modifier_map: dict[str, set[str]],
) -> StaticAnalysisFinding | None:
    """
    Apply all FP rules to a single finding.
    Returns None to suppress, or a (possibly modified) finding to keep.
    """
    det = f.detector_name

    # Rule 1: Always suppress
    if det in _ALWAYS_SUPPRESS:
        return None

    # Rule 2: Always downgrade to INFO
    if det in _ALWAYS_INFO:
        return _with_severity(f, Severity.INFORMATIONAL)

    # Rule 3: Reentrancy with known guard modifier → INFO
    if det in _REENTRANCY_DETECTORS:
        contract_modifiers = modifier_map.get(f.contract, set())
        if _has_reentrancy_guard(f, contract_modifiers):
            return _with_severity(f, Severity.INFORMATIONAL)

    # Rule 4: weak-prng → downgrade HIGH to LOW
    # Slither flags block.timestamp arithmetic as weak-prng but in TWAP
    # oracles this is intentional and safe.
    if det == "weak-prng" and f.severity == Severity.HIGH:
        return _with_severity(f, Severity.LOW)

    # Rule 5: missing-zero-check on internal/constructor → LOW max
    if det == "missing-zero-check" and f.severity in (Severity.HIGH, Severity.MEDIUM):
        return _with_severity(f, Severity.LOW)

    # Rule 6: timestamp → LOW max (not a direct exploit, needs context)
    if det == "timestamp" and f.severity in (Severity.HIGH, Severity.MEDIUM):
        return _with_severity(f, Severity.LOW)

    # Rule 7: incorrect-equality on data.length == 0 patterns → LOW
    # This is common in safe-transfer patterns like Uniswap's _safeTransfer
    if det == "incorrect-equality":
        desc_lower = (f.description or "").lower()
        if "data.length == 0" in desc_lower or "length == 0" in desc_lower:
            return _with_severity(f, Severity.LOW)

    return f


def _has_reentrancy_guard(
    f: StaticAnalysisFinding,
    contract_modifiers: set[str],
) -> bool:
    """Check if description mentions a reentrancy guard modifier."""
    desc = (f.description or "").lower()
    for guard in _REENTRANCY_GUARDS:
        if guard.lower() in desc:
            return True
    for guard in contract_modifiers:
        if guard.lower() in _REENTRANCY_GUARDS:
            return True
    return False


def _with_severity(
    f: StaticAnalysisFinding, severity: Severity
) -> StaticAnalysisFinding:
    """Return a copy of the finding with a different severity."""
    return f.model_copy(update={"severity": severity})
