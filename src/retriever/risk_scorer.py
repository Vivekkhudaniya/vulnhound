"""
VulnHound Retriever — Function Risk Scorer

Scores each function in a project by exploitability risk so the LLM
only analyses the most dangerous functions (top N), saving time and
token budget while improving signal-to-noise ratio.

Scoring factors
---------------
+3  function is public or external (accessible from outside)
+3  function is payable (handles native ETH)
+2  function name matches a high-value pattern (withdraw, deposit, etc.)
+2  function has an external call in body (call, delegatecall, transfer)
+2  no access-control modifier present
+3  has a HIGH Slither finding on this function
+2  has a MEDIUM Slither finding
+1  has a LOW Slither finding
+1  function is in a proxy contract
"""

from __future__ import annotations

from src.models import (
    ContractInfo,
    FunctionInfo,
    ProjectScope,
    Severity,
    StaticAnalysisFinding,
)

# Function names that commonly handle critical logic
_HIGH_VALUE_NAMES: frozenset[str] = frozenset({
    "withdraw", "withdrawAll", "withdrawTokens",
    "deposit", "depositAll",
    "borrow", "repay", "liquidate",
    "swap", "swapExactTokens", "swapTokensForExact",
    "mint", "burn", "redeem",
    "flashLoan", "flashloan", "flash",
    "upgrade", "upgradeTo", "upgradeToAndCall",
    "initialize", "init",
    "execute", "multicall",
    "transfer", "transferFrom",
    "setOwner", "transferOwnership",
    "setPrice", "updatePrice", "setOracle",
    "pause", "unpause",
    "emergencyWithdraw",
})

# Modifiers that indicate access control is present
_ACCESS_CONTROL_MODIFIERS: frozenset[str] = frozenset({
    "onlyOwner", "onlyAdmin", "onlyRole", "onlyGov",
    "onlyAuthorized", "onlyOperator", "onlyMinter",
    "requiresAuth", "auth", "restricted",
    "onlyDAO", "onlyMultisig", "onlyGuardian",
})

# External call patterns in our external_calls labels
_EXTERNAL_CALL_LABELS: frozenset[str] = frozenset({
    "low_level_call", "delegatecall", "staticcall",
    "erc20_transfer", "erc20_transfer_from",
    "erc20_interface", "erc721_interface", "send",
})


def score_functions(
    scope: ProjectScope,
    findings: list[StaticAnalysisFinding],
    top_n: int = 20,
) -> list[tuple[FunctionInfo, ContractInfo, int]]:
    """
    Score all functions and return the top N highest-risk ones.

    Parameters
    ----------
    scope:
        ProjectScope from Stage 1.
    findings:
        StaticAnalysisFindings from Stage 2 (already FP-filtered).
    top_n:
        Maximum number of functions to return.

    Returns
    -------
    list[tuple[FunctionInfo, ContractInfo, int]]
        Sorted (highest score first) list of (function, contract, score).
    """
    # Build finding lookup: (contract, function) → [findings]
    finding_map: dict[tuple[str, str], list[StaticAnalysisFinding]] = {}
    for f in findings:
        key = (f.contract, f.function or "")
        finding_map.setdefault(key, []).append(f)

    # Build contract lookup by name
    contract_map: dict[str, ContractInfo] = {c.name: c for c in scope.contracts}

    scored: list[tuple[FunctionInfo, ContractInfo, int]] = []

    for contract in scope.contracts:
        # We need functions — parse them if not already attached
        functions = _get_functions(contract, scope)
        for fn in functions:
            score = _score_function(fn, contract, finding_map)
            scored.append((fn, contract, score))

    # Sort descending by score
    scored.sort(key=lambda x: x[2], reverse=True)
    return scored[:top_n]


def _score_function(
    fn: FunctionInfo,
    contract: ContractInfo,
    finding_map: dict[tuple[str, str], list[StaticAnalysisFinding]],
) -> int:
    score = 0

    # Visibility: public/external are reachable from outside
    if fn.visibility in ("public", "external"):
        score += 3

    # Payable: handles native ETH
    if fn.state_mutability == "payable":
        score += 3

    # High-value function name
    if fn.name in _HIGH_VALUE_NAMES:
        score += 2

    # External call in function body
    if contract.external_calls:
        score += 2

    # No access control modifier
    modifiers_lower = {m.lower() for m in fn.modifiers}
    ac_modifiers_lower = {m.lower() for m in _ACCESS_CONTROL_MODIFIERS}
    if fn.visibility in ("public", "external") and not modifiers_lower.intersection(ac_modifiers_lower):
        score += 2

    # Slither findings on this function
    fn_findings = finding_map.get((contract.name, fn.name), [])
    for f in fn_findings:
        if f.severity == Severity.HIGH or f.severity == Severity.CRITICAL:
            score += 3
        elif f.severity == Severity.MEDIUM:
            score += 2
        elif f.severity == Severity.LOW:
            score += 1

    # Proxy contract — upgrade logic is high risk
    if contract.is_proxy:
        score += 1

    return score


def _get_functions(
    contract: ContractInfo,
    scope: ProjectScope,
) -> list[FunctionInfo]:
    """
    Get FunctionInfo list for a contract.
    Re-parses the file if functions not already cached.
    """
    from pathlib import Path
    from src.ingester.ast_parser import parse_functions

    try:
        content = Path(contract.file_path).read_text(encoding="utf-8", errors="replace")
        return parse_functions(content, contract.name)
    except Exception:
        return []
