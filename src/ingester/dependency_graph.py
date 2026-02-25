"""
VulnHound Ingester - Stage 1: Contract Dependency Graph

Builds a directed graph that maps each contract to the set of other
contracts / interfaces it depends on, derived from:
  - Inheritance (``inherits_from``)
  - External call sites (``external_calls``) cross-referenced against known
    contract names found in import statements or identifier usage
  - Direct name references inside source code

The graph is stored as ``dict[str, list[str]]`` — contract_name → [dependencies].
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Optional

from rich.console import Console

from src.models import ContractInfo

console = Console(stderr=True)


# ============================================================
# Regex helpers
# ============================================================

# Matches import paths, capturing the last identifier which is typically
# the contract/interface name brought into scope.
# e.g.  import "./interfaces/IFoo.sol";
#        import {IFoo, IBar} from "@openzeppelin/contracts/...";
_IMPORT_BRACE_RE = re.compile(r"import\s*\{([^}]+)\}\s*from")
_IMPORT_PATH_RE = re.compile(r"""import\s+["']([^"']+\.sol)["']""")

# Matches identifier(  — a common pattern for interface / contract casts
# e.g.  IERC20(token).transfer(...)  or  IRouter(routerAddr).swap(...)
_CAST_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]*)\s*\(")

# Matches  using SomeLibrary for  declarations
_USING_RE = re.compile(r"using\s+(\w+)\s+for")


# ============================================================
# Public API
# ============================================================


def build_dependency_graph(contracts: list[ContractInfo]) -> dict[str, list[str]]:
    """
    Build a dependency graph from a list of parsed contracts.

    The graph maps each contract name to a de-duplicated, sorted list of
    the contract names it depends on (via inheritance or external calls).

    Parameters
    ----------
    contracts:
        All ``ContractInfo`` objects returned by the AST parser.

    Returns
    -------
    dict[str, list[str]]
        ``{ "ContractA": ["ContractB", "InterfaceC"], ... }``
    """
    known_names: set[str] = {c.name for c in contracts}
    graph: dict[str, list[str]] = {}

    for contract in contracts:
        deps: set[str] = set()

        # ── 1. Inheritance ────────────────────────────────────────────────
        for base in contract.inherits_from:
            # bases may carry generic args like `ERC20Upgradeable` — already stripped upstream
            base_name = base.strip()
            if base_name:
                deps.add(base_name)

        # ── 2. external_calls entries that match a known contract name ────
        # The list normally holds category labels (e.g. "erc20_transfer"), but
        # when a caller passes actual contract names we honour them too.
        for ec in contract.external_calls:
            if ec in known_names:
                deps.add(ec)

        # ── 3. Parse raw source file for any remaining name references ─────
        if contract.file_path:
            file_deps = _extract_file_dependencies(
                Path(contract.file_path), known_names, contract.name
            )
            deps.update(file_deps)

        # Remove self-reference
        deps.discard(contract.name)

        graph[contract.name] = sorted(deps)

    console.log(
        f"[cyan]Dependency graph built: {len(graph)} node(s), "
        f"{sum(len(v) for v in graph.values())} edge(s)[/cyan]"
    )
    return graph


def extract_called_contracts(
    content: str, known_contract_names: set[str]
) -> list[str]:
    """
    Scan Solidity *content* for references to any of the *known_contract_names*
    and return the matched names.

    This is a best-effort textual scan; it does **not** perform full AST
    resolution.

    Parameters
    ----------
    content:
        Raw or comment-stripped Solidity source.
    known_contract_names:
        The universe of contract names discovered across the whole repo.

    Returns
    -------
    list[str]
        Sorted, de-duplicated list of referenced contract names.
    """
    found: set[str] = set()

    # Named imports: import {IFoo, IBar} from "..."
    for m in _IMPORT_BRACE_RE.finditer(content):
        for ident in m.group(1).split(","):
            name = ident.strip().split()[-1]  # handle  "IFoo as Foo"
            if name in known_contract_names:
                found.add(name)

    # Interface / contract cast expressions: IERC20(addr)
    for m in _CAST_RE.finditer(content):
        name = m.group(1)
        if name in known_contract_names:
            found.add(name)

    # using Library for type
    for m in _USING_RE.finditer(content):
        name = m.group(1)
        if name in known_contract_names:
            found.add(name)

    # Plain identifier usage — scan for any known name as a whole word
    for name in known_contract_names:
        if re.search(rf"\b{re.escape(name)}\b", content):
            found.add(name)

    return sorted(found)


# ============================================================
# Internal helpers
# ============================================================


def _extract_file_dependencies(
    file_path: Path, known_names: set[str], self_name: str
) -> set[str]:
    """
    Read *file_path* and return the set of known contract names referenced
    inside it (excluding *self_name*).
    """
    if not file_path.exists():
        return set()
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()

    deps = set(extract_called_contracts(content, known_names))
    deps.discard(self_name)
    return deps
