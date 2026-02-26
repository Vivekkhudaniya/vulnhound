"""
VulnHound Reporter — Stage 7: Markdown Report Generator

Produces a professional, human-readable audit report in Markdown format,
structured like a real competitive audit report (Code4rena / Sherlock style).

Report structure
----------------
1. Executive Summary     — stats, severity matrix, key findings
2. Scope                 — contracts in scope, LOC, framework
3. Findings              — ordered HIGH→CRITICAL, each with full write-up
4. Informational Notes   — low/info findings (compact)
5. Methodology           — how the analysis was done
6. Disclaimer            — AI-assisted, human review recommended

Each HIGH+ finding gets:
  - Severity badge
  - Vulnerability category
  - Location (contract:function:line)
  - Description
  - Impact
  - Proof of Concept / Exploit scenario
  - Recommended fix
  - Code snippet (vulnerable + suggested fix if available)
  - Similar historical exploits
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from src.models import (
    AuditReport,
    Finding,
    ProjectScope,
    Severity,
)


# Severity → badge string and sort key
_SEV_BADGE = {
    Severity.CRITICAL: "🔴 **CRITICAL**",
    Severity.HIGH:     "🟠 **HIGH**",
    Severity.MEDIUM:   "🟡 **MEDIUM**",
    Severity.LOW:      "🔵 **LOW**",
    Severity.INFORMATIONAL: "⚪ **INFORMATIONAL**",
}

_SEV_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 1,
}


def generate_markdown_report(
    findings: list[Finding],
    scope: ProjectScope,
    output_path: Optional[Path] = None,
    auditor: str = "VulnHound AI",
) -> str:
    """
    Generate a complete Markdown audit report.

    Parameters
    ----------
    findings:
        Validated findings from Stage 6.
    scope:
        Project scope from Stage 1.
    output_path:
        If provided, write the report to this file.
    auditor:
        Name/label to use in the report header.

    Returns
    -------
    The full Markdown report as a string.
    """
    sorted_findings = sorted(
        findings,
        key=lambda f: (_SEV_ORDER.get(f.severity, 0), f.confidence),
        reverse=True,
    )

    sections = [
        _render_header(scope, auditor),
        _render_executive_summary(sorted_findings, scope),
        _render_scope(scope),
        _render_findings(sorted_findings),
        _render_methodology(),
        _render_disclaimer(),
    ]

    report = "\n\n---\n\n".join(s for s in sections if s)

    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")

    return report


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


def _render_header(scope: ProjectScope, auditor: str) -> str:
    repo_name = Path(scope.repo_path).name if scope.repo_path else "Unknown"
    date_str = datetime.now().strftime("%B %d, %Y")
    url_line = f"\n**Repository:** {scope.repo_url}" if scope.repo_url else ""
    return (
        f"# Security Audit Report: {repo_name}\n\n"
        f"**Prepared by:** {auditor}  \n"
        f"**Date:** {date_str}  {url_line}\n"
        f"**Framework:** {scope.framework or 'Unknown'}  \n"
        f"**Compiler:** Solidity {scope.compiler_version or 'Unknown'}"
    )


def _render_executive_summary(findings: list[Finding], scope: ProjectScope) -> str:
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines = [
        "## Executive Summary",
        "",
        f"This report presents the findings of an AI-assisted security audit of "
        f"**{Path(scope.repo_path).name}**, covering "
        f"**{len(scope.contracts)} contracts** and **{scope.total_loc:,} lines of code**.",
        "",
        "### Severity Distribution",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]:
        n = counts.get(sev, 0)
        badge = _SEV_BADGE[sev]
        lines.append(f"| {badge} | {n} |")

    total = sum(counts.values())
    lines += [
        f"| **Total** | **{total}** |",
        "",
    ]

    # Highlight top findings
    top_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if top_findings:
        lines += ["### Key Findings", ""]
        for f in top_findings[:5]:
            badge = _SEV_BADGE[f.severity]
            lines.append(f"- {badge} [{f.id}] **{f.title}** — `{f.contract}`")
        lines.append("")

    return "\n".join(lines)


def _render_scope(scope: ProjectScope) -> str:
    lines = [
        "## Audit Scope",
        "",
        f"| Property | Value |",
        f"|----------|-------|",
        f"| Contracts | {len(scope.contracts)} |",
        f"| Total LOC | {scope.total_loc:,} |",
        f"| Framework | {scope.framework or '—'} |",
        f"| Compiler | {scope.compiler_version or '—'} |",
        f"| Proxy Contracts | {sum(1 for c in scope.contracts if c.is_proxy)} |",
        "",
        "### Contracts",
        "",
        "| Contract | LOC | Proxy |",
        "|----------|-----|-------|",
    ]

    for c in sorted(scope.contracts, key=lambda x: x.name):
        proxy_mark = "✓" if c.is_proxy else ""
        lines.append(f"| `{c.name}` | {c.loc} | {proxy_mark} |")

    return "\n".join(lines)


def _render_findings(findings: list[Finding]) -> str:
    if not findings:
        return "## Findings\n\nNo findings identified."

    # Separate high+ from low/info
    important = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)]
    minor = [f for f in findings if f.severity in (Severity.LOW, Severity.INFORMATIONAL)]

    lines = ["## Findings"]

    if important:
        for f in important:
            lines.append("")
            lines.append(_render_single_finding(f, verbose=True))

    if minor:
        lines += [
            "",
            "### Informational / Low Severity",
            "",
            "| ID | Severity | Contract | Title |",
            "|----|----------|----------|-------|",
        ]
        for f in minor:
            badge = _SEV_BADGE[f.severity].replace("**", "").strip()
            lines.append(f"| {f.id} | {badge} | `{f.contract}` | {f.title} |")

    return "\n".join(lines)


def _render_single_finding(f: Finding, verbose: bool = True) -> str:
    badge = _SEV_BADGE[f.severity]
    location = f"`{f.contract}`"
    if f.function:
        location += f" → `{f.function}()`"
    if f.line_start:
        location += f" (line {f.line_start})"

    lines = [
        f"### [{f.id}] {f.title}",
        "",
        f"**Severity:** {badge}  ",
        f"**Category:** {f.category.value.replace('_', ' ').title()}  ",
        f"**Location:** {location}  ",
        f"**Confidence:** {f.confidence:.0%}",
        "",
        "#### Description",
        "",
        f.description,
        "",
        "#### Impact",
        "",
        f.impact,
        "",
        "#### Exploit Scenario",
        "",
        f.exploit_scenario,
    ]

    if f.vulnerable_code:
        lines += [
            "",
            "#### Vulnerable Code",
            "",
            "```solidity",
            f.vulnerable_code.strip(),
            "```",
        ]

    if f.suggested_fix:
        lines += [
            "",
            "#### Recommended Fix",
            "",
            f.recommendation,
            "",
            "```solidity",
            f.suggested_fix.strip(),
            "```",
        ]
    else:
        lines += [
            "",
            "#### Recommendation",
            "",
            f.recommendation,
        ]

    if f.similar_exploits:
        lines += ["", "#### Similar Historical Exploits", ""]
        for exploit in f.similar_exploits[:3]:
            loss = f"${exploit.loss_usd:,.0f}" if exploit.loss_usd else "Unknown"
            lines.append(
                f"- **{exploit.protocol}** — {exploit.category.value} "
                f"(Loss: {loss}, Similarity: {exploit.similarity_score:.0%})"
            )

    return "\n".join(lines)


def _render_methodology() -> str:
    return """\
## Methodology

This audit was performed by VulnHound, an AI-powered smart contract auditing pipeline.

### Analysis Pipeline

1. **Stage 1 — Repository Ingestion**: Parse all Solidity contracts, build dependency graph, detect proxy patterns
2. **Stage 2 — Static Analysis**: Run Slither detectors; filter false positives using context-aware rules
3. **Stage 3 — RAG Retrieval**: Query the exploit knowledge base (DeFiHackLabs, Rekt, Solodit) for similar historical attacks using triple-query Reciprocal Rank Fusion
4. **Stage 4 — LLM Multi-Pass Analysis**:
   - Pass B: Per-function deep audit with source code + static findings + KB context
   - Pass C: Cross-contract trust boundary analysis
   - Pass D: Economic attack sweep (flash loans, oracle manipulation, MEV)
5. **Stage 5 — Validation**: Deduplication, severity re-scoring, confidence filtering
6. **Stage 6 — Report Generation**: This report

### Limitations

- AI-generated findings require human expert review before acting on them
- Dynamic analysis (fuzzing, symbolic execution) was not performed
- Business logic vulnerabilities require protocol-specific domain knowledge
- Findings are scored by confidence — lower confidence findings may be false positives"""


def _render_disclaimer() -> str:
    return """\
## Disclaimer

This report was generated by **VulnHound** (AI-assisted smart contract auditing tool).

**Important:** This is an automated analysis. All findings should be reviewed and verified by a qualified human security researcher before making any conclusions or taking action. AI analysis can produce false positives and may miss context-dependent vulnerabilities.

This report does not constitute a guarantee of security. The absence of a finding does not mean the absence of a vulnerability.

---
*Generated by VulnHound v0.1.0*"""
