"""
VulnHound Analyzer — Stage 2: Slither Runner

Runs Slither against a Solidity project and converts its findings
into VulnHound's StaticAnalysisFinding model.

Slither JSON output format (per detector):
  {
    "check":      "reentrancy-eth",
    "impact":     "High",
    "confidence": "Medium",
    "description": "...",
    "elements": [
      {
        "type": "function",
        "name": "withdraw",
        "source_mapping": {
          "filename_relative": "contracts/Vault.sol",
          "lines": [45, 46, 47]
        },
        "type_specific_fields": {
          "parent": { "type": "contract", "name": "Vault" }
        }
      }
    ]
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
# Severity mapping: Slither impact → VulnHound Severity
# ---------------------------------------------------------------------------

_IMPACT_MAP: dict[str, Severity] = {
    "High":           Severity.HIGH,
    "Medium":         Severity.MEDIUM,
    "Low":            Severity.LOW,
    "Informational":  Severity.INFORMATIONAL,
    "Optimization":   Severity.INFORMATIONAL,
}

# ---------------------------------------------------------------------------
# Detector → VulnCategory mapping
# ---------------------------------------------------------------------------

_DETECTOR_CATEGORY: dict[str, VulnCategory] = {
    # Reentrancy
    "reentrancy-eth":              VulnCategory.REENTRANCY,
    "reentrancy-no-eth":           VulnCategory.REENTRANCY,
    "reentrancy-benign":           VulnCategory.REENTRANCY,
    "reentrancy-events":           VulnCategory.REENTRANCY,
    "reentrancy-unlimited-gas":    VulnCategory.REENTRANCY,
    # Access control
    "suicidal":                    VulnCategory.ACCESS_CONTROL,
    "arbitrary-send-eth":          VulnCategory.ACCESS_CONTROL,
    "arbitrary-send-erc20":        VulnCategory.ACCESS_CONTROL,
    "tx-origin":                   VulnCategory.ACCESS_CONTROL,
    "missing-zero-check":          VulnCategory.ACCESS_CONTROL,
    "unprotected-upgrade":         VulnCategory.ACCESS_CONTROL,
    "protected-vars":              VulnCategory.ACCESS_CONTROL,
    "msg-value-loop":              VulnCategory.ACCESS_CONTROL,
    # Integer / arithmetic
    "integer-overflow":            VulnCategory.INTEGER_OVERFLOW,
    "tautology":                   VulnCategory.INTEGER_OVERFLOW,
    "incorrect-equality":          VulnCategory.INTEGER_OVERFLOW,
    "weak-prng":                   VulnCategory.LOGIC_ERROR,
    # Delegate call
    "delegatecall-loop":           VulnCategory.DELEGATE_CALL,
    "controlled-delegatecall":     VulnCategory.DELEGATE_CALL,
    "delegatecall":                VulnCategory.DELEGATE_CALL,
    # Storage / proxy
    "uninitialized-state":         VulnCategory.STORAGE_COLLISION,
    "uninitialized-storage":       VulnCategory.STORAGE_COLLISION,
    "uninitialized-local":         VulnCategory.STORAGE_COLLISION,
    "storage-array":               VulnCategory.STORAGE_COLLISION,
    # Oracle / price
    "oracle-manipulation":         VulnCategory.ORACLE_MANIPULATION,
    "price-manipulation":          VulnCategory.PRICE_MANIPULATION,
    # Front-running
    "timestamp":                   VulnCategory.FRONT_RUNNING,
    "block-number":                VulnCategory.FRONT_RUNNING,
    # DoS
    "calls-loop":                  VulnCategory.DENIAL_OF_SERVICE,
    "dos-gas-limit":               VulnCategory.DENIAL_OF_SERVICE,
    "dos-revert":                  VulnCategory.DENIAL_OF_SERVICE,
    # Unchecked calls
    "unchecked-transfer":          VulnCategory.UNCHECKED_EXTERNAL_CALL,
    "unchecked-lowlevel":          VulnCategory.UNCHECKED_EXTERNAL_CALL,
    "unchecked-send":              VulnCategory.UNCHECKED_EXTERNAL_CALL,
    "low-level-calls":             VulnCategory.UNCHECKED_EXTERNAL_CALL,
    "return-bomb":                 VulnCategory.UNCHECKED_EXTERNAL_CALL,
    # Token standards
    "erc20-interface":             VulnCategory.TOKEN_STANDARD,
    "erc721-interface":            VulnCategory.TOKEN_STANDARD,
    "locked-ether":                VulnCategory.LOGIC_ERROR,
    # Input validation
    "shadowing-abstract":          VulnCategory.INPUT_VALIDATION,
    "shadowing-local":             VulnCategory.INPUT_VALIDATION,
    "shadowing-state":             VulnCategory.INPUT_VALIDATION,
    "variable-scope":              VulnCategory.INPUT_VALIDATION,
    "incorrect-modifier":          VulnCategory.INPUT_VALIDATION,
}

_DEFAULT_CATEGORY = VulnCategory.LOGIC_ERROR


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_slither_available() -> bool:
    """Return True if slither is importable."""
    try:
        import slither  # noqa: F401
        return True
    except ImportError:
        return False


def run_slither(
    target: Path,
    *,
    solc_version: Optional[str] = None,
    framework: str = "unknown",
    timeout: int = 300,
) -> list[StaticAnalysisFinding]:
    """
    Run Slither against *target* (a .sol file or project directory) and
    return a list of ``StaticAnalysisFinding`` objects.

    Parameters
    ----------
    target:
        Path to a single ``.sol`` file **or** a project root directory.
    solc_version:
        Solidity compiler version to use (e.g. ``"0.8.20"``).
        If ``None``, the currently active ``solc-select`` version is used.
    framework:
        ``"foundry"``, ``"hardhat"``, ``"truffle"``, or ``"unknown"``.
    timeout:
        Maximum seconds to wait for Slither to finish.

    Returns
    -------
    list[StaticAnalysisFinding]
        Parsed findings, sorted by severity (critical → informational).
    """
    if not is_slither_available():
        console.log("[yellow]Slither not installed — skipping static analysis.[/yellow]")
        return []

    target = Path(target).resolve()
    if not target.exists():
        console.log(f"[yellow]Slither target not found: {target}[/yellow]")
        return []

    # Install solc version if needed
    if solc_version:
        _ensure_solc_version(solc_version)

    # Write output to the target directory so Slither's relative CWD works
    out_dir = target if target.is_dir() else target.parent
    out_path = out_dir / ".slither_out.json"

    try:
        findings = _run_slither_subprocess(
            target=target,
            out_path=out_path,
            solc_version=solc_version,
            framework=framework,
            timeout=timeout,
        )
    finally:
        out_path.unlink(missing_ok=True)

    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _ensure_solc_version(version: str) -> None:
    """Install + select a solc version via solc-select if not already active."""
    try:
        result = subprocess.run(
            ["solc-select", "versions"],
            capture_output=True, text=True, timeout=30,
        )
        installed = result.stdout
        if version not in installed:
            console.log(f"[cyan]Installing solc {version}...[/cyan]")
            subprocess.run(
                ["solc-select", "install", version],
                capture_output=True, timeout=120,
            )
        # Set as current
        subprocess.run(
            ["solc-select", "use", version],
            capture_output=True, timeout=10,
        )
    except Exception as exc:
        console.log(f"[yellow]solc-select warning: {exc}[/yellow]")


def _build_slither_cmd(
    target: Path,
    out_path: Path,
    solc_version: Optional[str],
    framework: str,
) -> list[str]:
    """Build the slither CLI command list."""
    # Use relative paths so they resolve correctly from the CWD
    cwd = target if target.is_dir() else target.parent
    try:
        target_arg = str(target.relative_to(cwd))
    except ValueError:
        target_arg = str(target)
    try:
        out_arg = str(out_path.relative_to(cwd))
    except ValueError:
        out_arg = str(out_path)

    cmd = [
        "python", "-m", "slither",
        target_arg,
        "--json", out_arg,
        "--disable-color",
    ]

    if solc_version:
        cmd += ["--solc-solcs-select", solc_version]

    if framework == "foundry":
        cmd += ["--foundry-out-directory", "out"]
    elif framework == "hardhat":
        cmd += ["--hardhat-artifacts-directory", "artifacts"]

    return cmd


def _run_slither_subprocess(
    target: Path,
    out_path: Path,
    solc_version: Optional[str],
    framework: str,
    timeout: int,
) -> list[StaticAnalysisFinding]:
    """Execute Slither and parse its JSON output."""
    cmd = _build_slither_cmd(target, out_path, solc_version, framework)

    console.log(f"[cyan]Running Slither on {target.name}...[/cyan]")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(target) if target.is_dir() else str(target.parent),
        )
    except subprocess.TimeoutExpired:
        console.log(f"[yellow]Slither timed out after {timeout}s[/yellow]")
        return []
    except FileNotFoundError:
        console.log("[yellow]Slither executable not found[/yellow]")
        return []

    # Slither exit codes: 0 = no findings, 1/2 = findings found, 255 = fatal error
    if result.returncode == 255:
        console.log(f"[red]Slither compilation failed:[/red]\n{result.stderr[-500:]}")
        return []

    if not out_path.exists():
        console.log("[yellow]Slither produced no JSON output[/yellow]")
        return []

    try:
        data = json.loads(out_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        console.log(f"[yellow]Failed to parse Slither JSON: {exc}[/yellow]")
        return []

    if not data.get("success"):
        err = data.get("error", "unknown error")
        console.log(f"[yellow]Slither reported failure: {err}[/yellow]")
        return []

    detectors = data.get("results", {}).get("detectors", [])
    findings = [_parse_detector(d) for d in detectors]
    findings = [f for f in findings if f is not None]

    console.log(
        f"[green]Slither: {len(findings)} finding(s) from "
        f"{target.name}[/green]"
    )
    return _sort_findings(findings)


def _parse_detector(detector: dict) -> Optional[StaticAnalysisFinding]:
    """Convert one Slither detector entry → StaticAnalysisFinding."""
    try:
        check = detector.get("check", "unknown")
        impact = detector.get("impact", "Informational")
        confidence = detector.get("confidence", "Low").lower()
        description = detector.get("description", "").strip()

        severity = _IMPACT_MAP.get(impact, Severity.INFORMATIONAL)
        category = _DETECTOR_CATEGORY.get(check, _DEFAULT_CATEGORY)

        # Extract location from first element
        elements = detector.get("elements", [])
        file_path = "unknown"
        line_start = 0
        line_end: Optional[int] = None
        contract = "unknown"
        function: Optional[str] = None

        for el in elements:
            sm = el.get("source_mapping", {})
            lines = sm.get("lines", [])
            if lines:
                file_path = sm.get("filename_relative", "unknown")
                line_start = lines[0]
                line_end = lines[-1] if len(lines) > 1 else None

            tp = el.get("type_specific_fields", {})
            parent = tp.get("parent", {})

            if el.get("type") == "function":
                function = el.get("name")
                contract = parent.get("name", "unknown")
                break
            elif el.get("type") == "contract":
                contract = el.get("name", "unknown")
            elif el.get("type") == "variable":
                contract = parent.get("name", "unknown")

        # Build a short readable code snippet from description first line
        snippet = description.split("\n")[0][:200] if description else None

        return StaticAnalysisFinding(
            tool=FindingSource.SLITHER,
            detector_name=check,
            severity=severity,
            confidence=confidence,
            description=description,
            contract=contract,
            function=function,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            code_snippet=snippet,
        )
    except Exception as exc:
        console.log(f"[yellow]Failed to parse detector '{detector.get('check')}': {exc}[/yellow]")
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
