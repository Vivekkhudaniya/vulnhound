"""
VulnHound Validator — Finding Deduplicator

Merges duplicate findings that refer to the same underlying vulnerability.
Two findings are considered duplicates when they share:
  - the same contract + function location
  - the same or highly-similar category
  - similar title (fuzzy match ≥ 0.8 Jaccard similarity on word tokens)

Merge policy
------------
When duplicates are found the finding with the highest confidence is kept.
Its ID is preserved and the lower-confidence finding is discarded.
"""

from __future__ import annotations

from src.models import Finding, Severity, VulnCategory


# Severity ordering for comparison
_SEV_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 1,
}


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Remove duplicate findings and return a de-duplicated list.

    Findings are processed in input order; when a duplicate pair is found,
    the higher-confidence (or higher-severity) finding is kept.

    Parameters
    ----------
    findings:
        All findings from all passes.

    Returns
    -------
    Unique findings sorted by severity (highest first).
    """
    if not findings:
        return []

    kept: list[Finding] = []

    for candidate in findings:
        merged = False
        for i, existing in enumerate(kept):
            if _are_duplicates(candidate, existing):
                # Keep the better of the two
                kept[i] = _pick_better(candidate, existing)
                merged = True
                break
        if not merged:
            kept.append(candidate)

    # Sort by severity descending
    kept.sort(key=lambda f: _SEV_ORDER.get(f.severity, 0), reverse=True)
    return kept


def _are_duplicates(a: Finding, b: Finding) -> bool:
    """Return True if two findings represent the same vulnerability."""
    # Must be in the same contract
    if a.contract != b.contract:
        return False

    # Same category is a strong signal
    if a.category != b.category:
        # Allow close categories to still be considered duplicate if location matches
        if a.function and b.function and a.function == b.function:
            # Same exact function but different category — still check title similarity
            pass
        else:
            return False

    # Same function (or both None)
    same_location = a.function == b.function

    if not same_location:
        # Different functions — only consider dupe if titles are very similar
        return _title_similarity(a.title, b.title) >= 0.85

    # Same function → lower threshold for title match
    return _title_similarity(a.title, b.title) >= 0.6


def _title_similarity(a: str, b: str) -> float:
    """Jaccard similarity on word-token sets."""
    tokens_a = set(a.lower().split())
    tokens_b = set(b.lower().split())
    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = len(tokens_a & tokens_b)
    union = len(tokens_a | tokens_b)
    return intersection / union


def _pick_better(a: Finding, b: Finding) -> Finding:
    """Return the finding that has higher confidence, or severity as tiebreaker."""
    if a.confidence > b.confidence:
        return a
    if b.confidence > a.confidence:
        return b
    # Equal confidence — use severity
    if _SEV_ORDER.get(a.severity, 0) >= _SEV_ORDER.get(b.severity, 0):
        return a
    return b
