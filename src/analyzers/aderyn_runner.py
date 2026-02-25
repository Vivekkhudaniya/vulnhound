"""
VulnHound Analyzer — Stage 2: Aderyn Runner

Aderyn is a fast Rust-based Solidity static analyzer by Cyfrin.
It does NOT require solc compilation, making it a great complement
to Slither — especially for projects where solc setup is complex.

Install: cargo install aderyn   OR   npm install -g @cyfrin/aderyn

Aderyn JSON output format:
  {
    "high_issues": { "issues": [ { "title": "...", "description": "...",
                                   "detector_name": "...",
                                   "instances": [ { "contract_path": "...",
                                                    "line_no": 45,
                                                    "src": "45:123:0",
                                                    "src_char": "..." } ] } ] },
    "low_issues":  { "issues": [...] }
  }
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from rich.console import Console

from src.models import FindingSource, Severity, StaticAnalysisFinding, VulnCategory

console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

_ADERYN_SEVERITY: dict[str, Severity] = {
    "critical_issues": Severity.CRITICAL,
    "high_issues":     Severity.HIGH,
    "medium_issues":   Severity.MEDIUM,
    "low_issues":      Severity.LOW,
    "nc_issues":       Severity.INFORMATIONAL,  # non-critical
}

# ---------------------------------------------------------------------------
# Detector name → VulnCategory (best-effort)
# ---------------------------------------------------------------------------

_ADERYN_CATEGORY: dict[str, VulnCategory] = {
    "reentrancy":                        VulnCategory.REENTRANCY,
    "centralization-risk":               VulnCategory.ACCESS_CONTROL,
    "unprotected-initialization":        VulnCategory.ACCESS_CONTROL,
    "dangerous-strict-equality-balance": VulnCategory.LOGIC_ERROR,
    "delegatecall-in-loop":              VulnCategory.DELEGATE_CALL,
    "weak-randomness":                   VulnCategory.LOGIC_ERROR,
    "block-timestamp-deadline":          VulnCategory.FRONT_RUNNING,
    "unsafe-erc20-operation":            VulnCategory.UNCHECKED_EXTERNAL_CALL,
    "unchecked-return":                  VulnCategory.UNCHECKED_EXTERNAL_CALL,
    "divide-before-multiply":            VulnCategory.INTEGER_OVERFLOW,
    "storage-collision-risk":            VulnCategory.STORAGE_COLLISION,
    "uninitialized-state-variable":      VulnCategory.STORAGE_COLLISION,
    "tx-origin-used":                    VulnCategory.ACCESS_CONTROL,
    "inconsistent-erc20":                VulnCategory.TOKEN_STANDARD,
}

_DEFAULT_CATEGORY = VulnCategory.LOGIC_ERROR


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_aderyn_available() -> bool:
    """Return True if the ``aderyn`` executable is on PATH."""
    try:
        result = subprocess.run(
            ["aderyn", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_aderyn(
    target: Path,
    *,
    timeout: int = 180,
) -> list[StaticAnalysisFinding]:
    """
    Run Aderyn against *target* directory and return parsed findings.

    Parameters
    ----------
    target:
        Project root directory (must contain Solidity files).
    timeout:
        Max seconds to wait.

    Returns
    -------
    list[StaticAnalysisFinding]
        Sorted by severity (critical → informational).
    """
    if not is_aderyn_available():
        console.log("[dim]Aderyn not found — skipping. (Install: cargo install aderyn)[/dim]")
        return []

    target = Path(target).resolve()
    if not target.is_dir():
        console.log(f"[yellow]Aderyn requires a directory, got: {target}[/yellow]")
        return []

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = Path(tmp.name)

    try:
        findings = _run_aderyn_subprocess(target, out_path, timeout)
    finally:
        out_path.unlink(missing_ok=True)

    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run_aderyn_subprocess(
    target: Path,
    out_path: Path,
    timeout: int,
) -> list[StaticAnalysisFinding]:
    """Execute Aderyn and parse its JSON output."""
    cmd = ["aderyn", ".", "--output", str(out_path)]

    console.log(f"[cyan]Running Aderyn on {target.name}...[/cyan]")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(target),
        )
    except subprocess.TimeoutExpired:
        console.log(f"[yellow]Aderyn timed out after {timeout}s[/yellow]")
        return []
    except FileNotFoundError:
        console.log("[yellow]Aderyn executable not found[/yellow]")
        return []

    if not out_path.exists():
        console.log("[yellow]Aderyn produced no JSON output[/yellow]")
        return []

    try:
        data = json.loads(out_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        console.log(f"[yellow]Failed to parse Aderyn JSON: {exc}[/yellow]")
        return []

    findings: list[StaticAnalysisFinding] = []
    for severity_key, severity_val in _ADERYN_SEVERITY.items():
        section = data.get(severity_key, {})
        for issue in section.get("issues", []):
            for inst in issue.get("instances", []):
                f = _parse_instance(issue, inst, severity_val)
                if f:
                    findings.append(f)

    console.log(f"[green]Aderyn: {len(findings)} finding(s) from {target.name}[/green]")
    return _sort_findings(findings)


def _parse_instance(
    issue: dict,
    instance: dict,
    severity: Severity,
) -> Optional[StaticAnalysisFinding]:
    """Convert one Aderyn issue+instance → StaticAnalysisFinding."""
    try:
        title = issue.get("title", "unknown")
        description = issue.get("description", "").strip()
        detector_name = issue.get("detector_name", title.lower().replace(" ", "-"))
        contract_path = instance.get("contract_path", "unknown")
        line_no = instance.get("line_no", 0)

        # Best-effort contract name from file path
        contract = Path(contract_path).stem if contract_path != "unknown" else "unknown"

        category = _ADERYN_CATEGORY.get(detector_name, _DEFAULT_CATEGORY)

        return StaticAnalysisFinding(
            tool=FindingSource.ADERYN,
            detector_name=detector_name,
            severity=severity,
            confidence="medium",
            description=f"{title}: {description}"[:500],
            contract=contract,
            function=None,
            file_path=contract_path,
            line_start=line_no,
            line_end=None,
            code_snippet=instance.get("src_char", "")[:200] or None,
        )
    except Exception as exc:
        console.log(f"[yellow]Aderyn parse error: {exc}[/yellow]")
        return None


_SEVERITY_ORDER = {
    Severity.CRITICAL:       0,
    Severity.HIGH:           1,
    Severity.MEDIUM:         2,
    Severity.LOW:            3,
    Severity.INFORMATIONAL:  4,
}


def _sort_findings(findings: list[StaticAnalysisFinding]) -> list[StaticAnalysisFinding]:
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
