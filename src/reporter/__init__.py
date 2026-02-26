"""
VulnHound Reporter — Stage 7

Generates human-readable audit reports from validated findings.

Public API
----------
    from src.reporter import generate_report
    report_md = generate_report(findings, scope, output_path=Path("report.md"))
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from src.models import Finding, ProjectScope
from src.reporter.markdown import generate_markdown_report


def generate_report(
    findings: list[Finding],
    scope: ProjectScope,
    output_path: Optional[Path] = None,
    format: str = "markdown",
) -> str:
    """
    Generate an audit report.

    Parameters
    ----------
    findings:
        Validated findings from Stage 6.
    scope:
        Project scope from Stage 1.
    output_path:
        If provided, write report to this path.
    format:
        Report format — currently only "markdown" is supported.

    Returns
    -------
    The report content as a string.
    """
    if format == "markdown":
        return generate_markdown_report(findings, scope, output_path=output_path)
    raise ValueError(f"Unsupported report format: {format!r}. Use 'markdown'.")


__all__ = ["generate_report", "generate_markdown_report"]
