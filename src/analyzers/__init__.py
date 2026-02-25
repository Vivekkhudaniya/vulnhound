"""
VulnHound Analyzers — Stage 2: Static Analysis Orchestrator

Entry point: ``analyze_repo(scope, settings) -> list[StaticAnalysisFinding]``

Runs all enabled static analysis tools (Slither, Aderyn) against the
project scope from Stage 1 and returns a deduplicated, sorted list of
findings ready for Stage 3 (RAG) and Stage 4 (LLM).

Pipeline
--------
1. Determine analysis targets (individual .sol files vs full directory)
2. Run Slither  — deep semantic analysis, requires solc compilation
3. Run Aderyn   — fast structural analysis, no compilation needed
4. Deduplicate overlapping findings across tools
5. Return findings sorted by severity
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from src.models import ProjectScope, Severity, StaticAnalysisFinding
from src.analyzers.slither_runner import is_slither_available, run_slither
from src.analyzers.aderyn_runner import is_aderyn_available, run_aderyn

console = Console(stderr=True)

__all__ = ["analyze_repo", "print_findings_table"]

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL:      0,
    Severity.HIGH:          1,
    Severity.MEDIUM:        2,
    Severity.LOW:           3,
    Severity.INFORMATIONAL: 4,
}


def analyze_repo(
    scope: ProjectScope,
    *,
    run_slither_flag: bool = True,
    run_aderyn_flag: bool = True,
    solc_version: Optional[str] = None,
    timeout: int = 300,
) -> list[StaticAnalysisFinding]:
    """
    Run all enabled static analyzers against *scope* and return findings.

    Parameters
    ----------
    scope:
        ``ProjectScope`` produced by Stage 1 (``ingest_repo``).
    run_slither_flag:
        Set ``False`` to skip Slither (e.g. when solc is unavailable).
    run_aderyn_flag:
        Set ``False`` to skip Aderyn.
    solc_version:
        Override compiler version (defaults to ``scope.compiler_version``).
    timeout:
        Seconds per tool.

    Returns
    -------
    list[StaticAnalysisFinding]
        Deduplicated, sorted by severity.
    """
    repo_path = Path(scope.repo_path)
    compiler = solc_version or scope.compiler_version
    framework = scope.framework or "unknown"

    console.rule("[bold yellow]VulnHound — Stage 2: Static Analysis[/bold yellow]")
    console.log(f"  Repo     : {repo_path.name}")
    console.log(f"  Framework: {framework}")
    console.log(f"  Compiler : {compiler or 'auto-detect'}")

    all_findings: list[StaticAnalysisFinding] = []

    slither_target = _pick_slither_target(scope)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:

        # ── Slither ───────────────────────────────────────────────────────────
        if run_slither_flag:
            if is_slither_available():
                task = progress.add_task("[cyan]Running Slither...", total=None)
                try:
                    slither_findings = run_slither(
                        slither_target,
                        solc_version=compiler,
                        framework=framework,
                        timeout=timeout,
                    )
                    all_findings.extend(slither_findings)
                    progress.update(
                        task,
                        description=f"[cyan]Slither: {len(slither_findings)} finding(s)",
                    )
                except Exception as exc:
                    console.log(f"[yellow]Slither error: {exc}[/yellow]")
                    progress.update(task, description="[yellow]Slither: failed")
            else:
                console.log("[yellow]Slither not installed — run: pip install slither-analyzer[/yellow]")

        # ── Aderyn ────────────────────────────────────────────────────────────
        if run_aderyn_flag:
            if is_aderyn_available():
                task = progress.add_task("[cyan]Running Aderyn...", total=None)
                try:
                    aderyn_findings = run_aderyn(repo_path, timeout=timeout)
                    all_findings.extend(aderyn_findings)
                    progress.update(
                        task,
                        description=f"[cyan]Aderyn: {len(aderyn_findings)} finding(s)",
                    )
                except Exception as exc:
                    console.log(f"[yellow]Aderyn error: {exc}[/yellow]")
                    progress.update(task, description="[yellow]Aderyn: failed")
            else:
                console.log("[dim]Aderyn not installed — skipping.[/dim]")

    deduped = _deduplicate(all_findings)
    sorted_findings = sorted(deduped, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    _log_summary(sorted_findings)
    return sorted_findings


def print_findings_table(
    findings: list[StaticAnalysisFinding],
    console_out: Optional[Console] = None,
) -> None:
    """Print a Rich table of findings to the console."""
    c = console_out or Console()
    if not findings:
        c.print("[green]No findings.[/green]")
        return

    table = Table(title="Static Analysis Findings", border_style="yellow")
    table.add_column("#",         width=3,  style="dim")
    table.add_column("Severity",  width=14)
    table.add_column("Tool",      width=8)
    table.add_column("Detector",  width=30)
    table.add_column("Contract",  width=22)
    table.add_column("Function",  width=22)
    table.add_column("File:Line", width=35)

    _SEVERITY_STYLE = {
        Severity.CRITICAL:      "[bold red]CRITICAL[/bold red]",
        Severity.HIGH:          "[red]HIGH[/red]",
        Severity.MEDIUM:        "[yellow]MEDIUM[/yellow]",
        Severity.LOW:           "[blue]LOW[/blue]",
        Severity.INFORMATIONAL: "[dim]INFO[/dim]",
    }

    for i, f in enumerate(findings, 1):
        sev_str = _SEVERITY_STYLE.get(f.severity, f.severity.value)
        file_line = f"{Path(f.file_path).name}:{f.line_start}"
        table.add_row(
            str(i),
            sev_str,
            f.tool.value,
            f.detector_name,
            f.contract,
            f.function or "—",
            file_line,
        )

    c.print(table)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _pick_slither_target(scope: ProjectScope) -> Path:
    """Choose the best Slither target path."""
    repo_path = Path(scope.repo_path)

    if scope.contracts:
        dirs: set[Path] = {Path(c.file_path).parent for c in scope.contracts}
        if len(dirs) == 1:
            return list(dirs)[0]
        for subdir in ("contracts", "src"):
            candidate = repo_path / subdir
            if candidate.is_dir():
                return candidate

    return repo_path


def _deduplicate(findings: list[StaticAnalysisFinding]) -> list[StaticAnalysisFinding]:
    """Remove near-duplicate findings (same detector + contract + line)."""
    seen: dict[tuple, StaticAnalysisFinding] = {}
    for f in findings:
        key = (f.detector_name, f.contract, f.line_start)
        existing = seen.get(key)
        if existing is None:
            seen[key] = f
        elif _SEVERITY_ORDER.get(f.severity, 99) < _SEVERITY_ORDER.get(existing.severity, 99):
            seen[key] = f
    return list(seen.values())


def _log_summary(findings: list[StaticAnalysisFinding]) -> None:
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    console.rule("[bold yellow]Stage 2 complete[/bold yellow]")
    console.log(
        f"  CRITICAL={counts.get(Severity.CRITICAL,0)}  "
        f"HIGH={counts.get(Severity.HIGH,0)}  "
        f"MEDIUM={counts.get(Severity.MEDIUM,0)}  "
        f"LOW={counts.get(Severity.LOW,0)}  "
        f"INFO={counts.get(Severity.INFORMATIONAL,0)}  "
        f"| Total={len(findings)}"
    )
