"""
VulnHound Ingester — Stage 1: Repository Ingestion

Entry point: ``ingest_repo(url_or_path, work_dir) -> ProjectScope``

Pipeline
--------
1. Clone remote repo or validate local path          (clone.py)
2. Detect build framework (Foundry / Hardhat / …)    (clone.py)
3. Resolve compiler version and import remappings     (resolver.py)
4. Discover all in-scope .sol files                   (resolver.py)
5. Parse each file → ContractInfo objects             (ast_parser.py)
6. Classify proxy contracts                           (proxy_detector.py)
7. Build contract dependency graph                    (dependency_graph.py)
8. Return a populated ProjectScope                    (models.py)
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from src.models import ContractInfo, ProjectScope
from src.ingester.clone import detect_framework, resolve_repo
from src.ingester.resolver import find_sol_files, get_compiler_version, read_remappings
from src.ingester.ast_parser import parse_sol_file
from src.ingester.dependency_graph import build_dependency_graph
from src.ingester.proxy_detector import detect_proxy

console = Console(stderr=True)

__all__ = ["ingest_repo"]


def ingest_repo(url_or_path: str, work_dir: Path) -> ProjectScope:
    """
    Stage 1: Clone / locate a Solidity repository and extract a full
    ``ProjectScope`` describing every contract it contains.

    Parameters
    ----------
    url_or_path:
        Either a Git URL (``https://`` / ``git@``) or a local filesystem path.
    work_dir:
        Working directory where remote repos will be cloned.  Must be writable.

    Returns
    -------
    ProjectScope
        Populated data-model ready for Stage 2 (static analysis).

    Raises
    ------
    FileNotFoundError
        If a local path is given but does not exist.
    RuntimeError
        If git clone / pull fails.
    """
    work_dir = Path(work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    console.rule("[bold cyan]VulnHound — Stage 1: Repository Ingestion[/bold cyan]")

    # ── Step 1: Clone or resolve local path ──────────────────────────────────
    console.log("[bold]Step 1/7[/bold] Resolving repository…")
    repo_path, repo_url = resolve_repo(url_or_path, work_dir)
    console.log(f"  Repository root: [green]{repo_path}[/green]")

    # ── Step 2: Framework detection ──────────────────────────────────────────
    console.log("[bold]Step 2/7[/bold] Detecting build framework…")
    framework = detect_framework(repo_path)
    console.log(f"  Framework: [green]{framework}[/green]")

    # ── Step 3: Compiler version & remappings ────────────────────────────────
    console.log("[bold]Step 3/7[/bold] Reading compiler configuration…")
    compiler_version = get_compiler_version(repo_path)
    remappings = read_remappings(repo_path)
    console.log(f"  Compiler version: [green]{compiler_version or 'unknown'}[/green]")
    console.log(f"  Remappings: {len(remappings)} entries")

    # ── Step 4: Discover .sol files ───────────────────────────────────────────
    console.log("[bold]Step 4/7[/bold] Discovering Solidity source files…")
    sol_files = find_sol_files(repo_path, exclude_tests=True)
    console.log(f"  Found [bold]{len(sol_files)}[/bold] .sol file(s)")

    if not sol_files:
        console.log("[yellow]No Solidity files found — returning empty ProjectScope.[/yellow]")
        return ProjectScope(
            repo_url=repo_url,
            repo_path=str(repo_path),
            framework=framework,
            compiler_version=compiler_version,
        )

    # ── Step 5: Parse contracts ───────────────────────────────────────────────
    console.log("[bold]Step 5/7[/bold] Parsing contracts…")
    all_contracts: list[ContractInfo] = []
    parse_errors: list[str] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Parsing .sol files", total=len(sol_files))
        for sol_file in sol_files:
            try:
                contracts = parse_sol_file(sol_file)
                all_contracts.extend(contracts)
            except Exception as exc:  # noqa: BLE001
                parse_errors.append(f"{sol_file}: {exc}")
                console.log(f"[yellow]  Parse warning: {sol_file.name}: {exc}[/yellow]")
            finally:
                progress.advance(task)

    console.log(
        f"  Parsed [bold]{len(all_contracts)}[/bold] contract(s) "
        f"across {len(sol_files)} file(s)"
        + (f" — {len(parse_errors)} file(s) had errors" if parse_errors else "")
    )

    # ── Step 6: Proxy detection ───────────────────────────────────────────────
    console.log("[bold]Step 6/7[/bold] Detecting proxy patterns…")
    proxy_count = 0

    for contract in all_contracts:
        try:
            file_content = _read_file_safe(Path(contract.file_path))
            is_proxy, proxy_type = detect_proxy(file_content, contract.name)
            contract.is_proxy = is_proxy
            contract.proxy_type = proxy_type
            if is_proxy:
                proxy_count += 1
        except Exception as exc:  # noqa: BLE001
            console.log(
                f"[yellow]  Proxy detection warning for {contract.name}: {exc}[/yellow]"
            )

    console.log(f"  Detected [bold]{proxy_count}[/bold] proxy contract(s)")

    # ── Step 7: Dependency graph ──────────────────────────────────────────────
    console.log("[bold]Step 7/7[/bold] Building dependency graph…")
    dep_graph = build_dependency_graph(all_contracts)

    # ── Aggregate LOC ─────────────────────────────────────────────────────────
    total_loc = sum(c.loc for c in all_contracts)

    scope = ProjectScope(
        repo_url=repo_url,
        repo_path=str(repo_path),
        contracts=all_contracts,
        total_loc=total_loc,
        framework=framework,
        compiler_version=compiler_version,
        dependency_graph=dep_graph,
    )

    console.rule("[bold green]Stage 1 complete[/bold green]")
    console.log(
        f"  Contracts : [bold]{len(all_contracts)}[/bold]  |  "
        f"LOC : [bold]{total_loc:,}[/bold]  |  "
        f"Proxies : [bold]{proxy_count}[/bold]  |  "
        f"Framework : [bold]{framework}[/bold]"
    )

    return scope


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_file_safe(path: Path) -> str:
    """Read a file, returning an empty string on any I/O error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
