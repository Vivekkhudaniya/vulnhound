"""
VulnHound LLM Prompt Templates — Stage 5

All prompt strings and the report_finding tool schema live here.
Keeping prompts separate from engine logic makes wording iterations
fast without touching control-flow code.

Structure
---------
SYSTEM_PROMPT          — shared across all three passes
REPORT_FINDING_TOOL    — tool schema for structured Finding output
build_pass_b_prompt()  — Pass B: per-function deep audit
build_pass_c_prompt()  — Pass C: cross-contract trust boundary analysis
build_pass_d_prompt()  — Pass D: project-wide economic vulnerability scan

Helper formatters
-----------------
format_static_findings()   — StaticAnalysisFinding list → compact text
format_similar_exploits()  — RetrievedExploit list → numbered KB context
truncate_source()          — hard-cap source_code before embedding in prompt
"""

from __future__ import annotations

from src.models import (
    ContractInfo,
    FindingSource,
    FunctionContext,
    FunctionInfo,
    ProjectScope,
    RetrievedExploit,
    Severity,
    StaticAnalysisFinding,
    VulnCategory,
)

# ---------------------------------------------------------------------------
# System prompt — shared across all passes
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """\
You are an elite smart contract security auditor specialising in DeFi protocol \
vulnerabilities. You have 10+ years of experience with Solidity, EVM internals, \
and financial attack vectors (flash loans, price oracle manipulation, MEV).

## Output Rules
- Call `report_finding` ONCE per distinct vulnerability.
- Do NOT repeat a finding you have already reported in this session.
- Do NOT report pure gas optimisations — only security vulnerabilities.
- Only report findings where confidence >= 0.5. Discard speculative noise.
- Report severity honestly: CRITICAL = direct fund loss at any time; \
HIGH = likely fund loss under realistic conditions; MEDIUM = fund loss or \
significant protocol disruption under specific conditions; \
LOW = minor impact or very low probability; INFORMATIONAL = code quality.

## Taxonomy
Use the exact category values from the VulnHound taxonomy:
reentrancy | access_control | logic_error | input_validation | \
price_manipulation | flash_loan | front_running | oracle_manipulation | \
cross_chain | governance | integer_overflow | unchecked_external_call | \
delegate_call | storage_collision | denial_of_service | token_standard | \
gas_optimization | other

## Evidence Standard
Every finding must have a concrete exploit_scenario with step-by-step attacker \
actions. Vague scenarios like "an attacker could exploit this" are not acceptable.
"""

# ---------------------------------------------------------------------------
# report_finding tool schema
# ---------------------------------------------------------------------------

REPORT_FINDING_TOOL: dict = {
    "name": "report_finding",
    "description": (
        "Report a security vulnerability discovered during analysis. "
        "Call this tool once per distinct vulnerability. "
        "Omit optional fields if not applicable."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": (
                    "Short, specific title capturing both WHAT and WHERE. "
                    "Example: 'Reentrancy in withdraw() allows fund drainage'"
                ),
            },
            "severity": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "informational"],
                "description": "Severity based on actual exploitability and impact.",
            },
            "category": {
                "type": "string",
                "enum": [v.value for v in VulnCategory],
                "description": "Vulnerability category from VulnHound taxonomy.",
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": (
                    "Your confidence this is a real vulnerability. "
                    "0.0 = speculative, 1.0 = certain. Only report >= 0.5."
                ),
            },
            "description": {
                "type": "string",
                "description": (
                    "Technical description of the vulnerability: root cause, "
                    "affected state variables, and why the code is insecure."
                ),
            },
            "impact": {
                "type": "string",
                "description": (
                    "Concrete impact if exploited. Include estimated loss range "
                    "if calculable (e.g., 'All ETH in contract (currently X ETH)')."
                ),
            },
            "exploit_scenario": {
                "type": "string",
                "description": (
                    "Step-by-step attacker walkthrough. Must be specific and realistic. "
                    "Example: '1. Attacker calls deposit(1 ether). "
                    "2. In fallback, re-enters withdraw() before balance update. "
                    "3. Repeats N times draining the contract.'"
                ),
            },
            "recommendation": {
                "type": "string",
                "description": (
                    "Concrete remediation. Prefer code-level fixes with specific "
                    "patterns (e.g., CEI pattern, OpenZeppelin ReentrancyGuard, "
                    "Chainlink TWAP oracle)."
                ),
            },
            "vulnerable_code": {
                "type": "string",
                "description": "The specific vulnerable code snippet (optional).",
            },
            "suggested_fix": {
                "type": "string",
                "description": "Fixed version of the vulnerable snippet (optional).",
            },
            "line_start": {
                "type": "integer",
                "description": "Starting line number of the vulnerability (use 0 if unknown).",
            },
            "line_end": {
                "type": "integer",
                "description": "Ending line number (optional).",
            },
        },
        "required": [
            "title",
            "severity",
            "category",
            "confidence",
            "description",
            "impact",
            "exploit_scenario",
            "recommendation",
            "line_start",
        ],
    },
}

# ---------------------------------------------------------------------------
# Pass B — per-function deep audit
# ---------------------------------------------------------------------------

_PASS_B_TEMPLATE = """\
Perform a deep security audit on the following Solidity function.

## Target
- **Contract:** {contract_name}
- **Function:** `{function_name}({params})` — `{visibility}` `{mutability}`
- **File:** `{file_path}` line {line_start}
- **Modifiers:** {modifiers_text}
- **Cross-contract deps:** {cross_calls_text}

## Source Code
```solidity
{source_code}
```

## Pre-Computed Static Analysis Findings
These are from Slither/Aderyn — use as starting hints, not conclusions:
{static_findings_text}

## Similar Historical Exploits (from Knowledge Base)
Past incidents that share patterns with this code:
{similar_exploits_text}

---
Analyse the function thoroughly. Focus especially on:
1. Reentrancy (ETH, token, cross-function, cross-contract)
2. Access control bypasses or missing authorisation
3. Integer over/underflow even under Solidity 0.8+ (custom unchecked blocks)
4. Logic errors: incorrect state transitions, wrong accounting
5. Unchecked external call return values
6. Flash loan attack vectors enabled by this function
7. Price oracle manipulation via spot prices
8. Front-running / sandwich attack opportunities
9. DoS via gas griefing or unbounded loops
10. Proxy/upgrade vulnerabilities (storage collision, initialiser re-entry)

Call `report_finding` for each real vulnerability you identify.
If the function is safe, do NOT call any tools.\
"""


def build_pass_b_prompt(ctx: FunctionContext, max_source_chars: int = 4000) -> str:
    """Assemble the Pass B user message for a single FunctionContext."""
    fn = ctx.function
    contract = ctx.contract

    params = ", ".join(fn.parameters) if fn.parameters else ""
    modifiers_text = ", ".join(fn.modifiers) if fn.modifiers else "none"
    cross_calls_text = ", ".join(ctx.cross_contract_calls) if ctx.cross_contract_calls else "none"

    source_code = truncate_source(fn.source_code, max_source_chars)
    static_text = format_static_findings(ctx.static_findings)
    exploits_text = format_similar_exploits(ctx.similar_exploits, max_count=3)

    return _PASS_B_TEMPLATE.format(
        contract_name=contract.name,
        function_name=fn.name,
        params=params,
        visibility=fn.visibility,
        mutability=fn.state_mutability or "nonpayable",
        file_path=contract.file_path,
        line_start=fn.start_line or 0,
        modifiers_text=modifiers_text,
        cross_calls_text=cross_calls_text,
        source_code=source_code,
        static_findings_text=static_text,
        similar_exploits_text=exploits_text,
    )


# ---------------------------------------------------------------------------
# Pass C — cross-contract trust boundary analysis
# ---------------------------------------------------------------------------

_PASS_C_TEMPLATE = """\
Analyse cross-contract interactions and trust boundary violations for `{contract_name}`.

## External Dependencies
{dependency_summary}

## Functions with External Calls
{functions_with_calls}

---
Focus EXCLUSIVELY on vulnerabilities that arise from cross-contract interactions:
- Reentrancy via untrusted external callbacks (ETH transfer, ERC-777 hooks, etc.)
- Trust assumption violations (assuming callee is benign / non-malicious)
- Return-value-ignored on external calls (transfer, send, low-level call)
- Delegatecall to user-controlled or upgradeable addresses
- Callback manipulation in flash-loan or multi-call scenarios
- Price manipulation via callee-controlled return values (price oracles)
- Circular dependency exploits between sibling contracts

Do NOT re-report function-level bugs already obvious from the source — focus on \
the interaction surface between contracts.

Call `report_finding` for each cross-contract vulnerability found.\
"""


def build_pass_c_prompt(
    contract: ContractInfo,
    contexts: list[FunctionContext],
) -> str:
    """Assemble Pass C cross-contract prompt for one contract."""
    # Build dependency summary
    dep_lines = []
    all_deps: set[str] = set()
    for ctx in contexts:
        all_deps.update(ctx.cross_contract_calls)
    for dep in sorted(all_deps):
        dep_lines.append(f"  - {dep}")
    dependency_summary = "\n".join(dep_lines) if dep_lines else "  (none detected)"

    # Build per-function call summary
    fn_lines = []
    for ctx in contexts:
        fn = ctx.function
        if not ctx.cross_contract_calls and not contract.external_calls:
            continue
        calls = ctx.cross_contract_calls or contract.external_calls
        call_list = ", ".join(calls[:5])
        source_preview = truncate_source(fn.source_code, max_chars=600)
        fn_lines.append(
            f"### `{fn.name}` ({fn.visibility} {fn.state_mutability or 'nonpayable'})\n"
            f"External calls to: {call_list}\n"
            f"```solidity\n{source_preview}\n```"
        )
    functions_with_calls = "\n\n".join(fn_lines) if fn_lines else "(no functions with external calls)"

    return _PASS_C_TEMPLATE.format(
        contract_name=contract.name,
        dependency_summary=dependency_summary,
        functions_with_calls=functions_with_calls,
    )


# ---------------------------------------------------------------------------
# Pass D — project-wide economic vulnerability scan
# ---------------------------------------------------------------------------

_PASS_D_TEMPLATE = """\
Perform a DeFi economic attack surface analysis for the following project.

## Project Overview
- **Repo:** {repo_path}
- **Contracts:** {contract_count} ({contract_names})
- **Total LOC:** {total_loc}

## Contract Summaries
{contract_summaries}

## High-Value Functions (payable / token-transfer / oracle-interaction)
{high_value_functions}

---
Focus EXCLUSIVELY on economic and DeFi-specific attack categories:
1. **Price oracle manipulation** — spot price vs TWAP, single-block manipulation
2. **Flash loan attack vectors** — atomic borrow + exploit + repay in one tx
3. **Front-running / sandwich attacks** — MEV-exploitable state changes
4. **Governance token manipulation** — vote buying, flash-loan governance
5. **Liquidity pool invariant violations** — constant-product bypasses
6. **Cross-chain bridge assumptions** — message replay, validator collusion
7. **Rebasing/elastic token accounting errors**
8. **Fee-on-transfer token incompatibilities**

For each economic vulnerability: estimate the maximum loss if exploited.
Do NOT repeat code-level bugs covered in function-level analysis.

Call `report_finding` for each economic vulnerability found.\
"""


def build_pass_d_prompt(
    scope: ProjectScope,
    contexts: list[FunctionContext],
) -> str:
    """Assemble Pass D economic audit prompt for the whole project."""
    contract_names = ", ".join(c.name for c in scope.contracts[:10])
    if len(scope.contracts) > 10:
        contract_names += f" (+{len(scope.contracts) - 10} more)"

    # Build per-contract summaries
    summary_lines = []
    for c in scope.contracts[:15]:  # cap to avoid massive prompt
        summary_lines.append(
            f"- **{c.name}** ({c.loc} LOC)"
            + (f" [proxy: {c.proxy_type}]" if c.is_proxy else "")
            + (f" inherits: {', '.join(c.inherits_from)}" if c.inherits_from else "")
        )
    contract_summaries = "\n".join(summary_lines) if summary_lines else "(none)"

    # Identify high-value functions for economic analysis
    hv_lines = []
    _ECONOMIC_NAMES = {
        "swap", "swapExactTokens", "swapTokensForExact",
        "deposit", "withdraw", "borrow", "repay", "liquidate",
        "flashLoan", "flashloan", "flash",
        "getPrice", "latestAnswer", "price", "getReserves",
        "mint", "burn", "redeem",
    }
    for ctx in contexts:
        fn = ctx.function
        if fn.state_mutability == "payable" or fn.name in _ECONOMIC_NAMES:
            hv_lines.append(
                f"- `{ctx.contract.name}.{fn.name}` "
                f"({fn.visibility} {fn.state_mutability or 'nonpayable'})"
            )
    high_value = "\n".join(hv_lines[:20]) if hv_lines else "(none identified)"

    return _PASS_D_TEMPLATE.format(
        repo_path=scope.repo_path,
        contract_count=len(scope.contracts),
        contract_names=contract_names,
        total_loc=scope.total_loc,
        contract_summaries=contract_summaries,
        high_value_functions=high_value,
    )


# ---------------------------------------------------------------------------
# Prompt helper formatters
# ---------------------------------------------------------------------------


def format_static_findings(findings: list[StaticAnalysisFinding]) -> str:
    """Convert static findings list → compact numbered text for prompt."""
    if not findings:
        return "  (none — function passed static analysis)"

    lines = []
    for i, f in enumerate(findings, start=1):
        line = (
            f"  {i}. [{f.severity.value.upper()}] {f.detector_name} "
            f"(confidence: {f.confidence}): {f.description[:200]}"
        )
        if f.line_start:
            line += f" (line {f.line_start})"
        lines.append(line)
    return "\n".join(lines)


def format_similar_exploits(
    exploits: list[RetrievedExploit],
    max_count: int = 3,
) -> str:
    """Serialize top-N exploits → numbered list for prompt context."""
    if not exploits:
        return "  (no similar exploits found in Knowledge Base)"

    lines = []
    for i, ex in enumerate(exploits[:max_count], start=1):
        loss = f"${ex.loss_usd:,.0f}" if ex.loss_usd else "unknown"
        lines.append(
            f"  {i}. **{ex.protocol}** (score: {ex.similarity_score:.2f}, "
            f"loss: {loss})\n"
            f"     Category: {ex.category if isinstance(ex.category, str) else ex.category.value}\n"
            f"     {ex.attack_summary[:300]}"
        )
    return "\n".join(lines)


def truncate_source(source: str, max_chars: int = 4000) -> str:
    """Hard-cap source_code at max_chars, appending a truncation notice."""
    if not source:
        return "(source code unavailable)"
    if len(source) <= max_chars:
        return source
    return source[:max_chars] + f"\n// ... [truncated at {max_chars} chars]"
