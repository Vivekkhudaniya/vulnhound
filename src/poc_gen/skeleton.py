"""
VulnHound PoC Generator — Stage 6: Proof-of-Concept Skeleton

Generates a Foundry-style PoC test scaffold for a vulnerable contract.
This is a SKELETON only — it creates the structure and TODOs so a human
auditor can fill in the actual exploit logic.

What is generated:
  - Foundry test file with Attack contract + Test class
  - Interface for the target contract with vulnerable functions
  - Flash loan scaffold (Uniswap V2) if flash loan is detected
  - Attack flow TODOs based on the top static findings
  - Invariant check at the end of the exploit

Why skeleton only?
  Generating working exploits requires deep semantic understanding beyond
  what static analysis + RAG can reliably provide. A wrong exploit wastes
  auditor time. A good skeleton + correct context saves 60-70% of writing time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from src.models import Severity, StaticAnalysisFinding, VulnCategory


# ---------------------------------------------------------------------------
# Output model
# ---------------------------------------------------------------------------


@dataclass
class PoCResult:
    """Generated PoC skeleton for one contract."""
    contract_name: str
    file_name: str          # e.g. "AttackVault.t.sol"
    source: str             # full Solidity source
    primary_vuln: str       # short label e.g. "reentrancy-eth"
    needs_flash_loan: bool
    todo_count: int


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_poc_skeleton(
    contract_name: str,
    source_code: str,
    findings: list[StaticAnalysisFinding],
    similar_exploits: list | None = None,  # RetrievedExploit — avoid circular import
) -> PoCResult:
    """
    Generate a Foundry PoC skeleton for a vulnerable contract.

    Parameters
    ----------
    contract_name:
        Name of the contract to attack.
    source_code:
        Full Solidity source of the target contract.
    findings:
        Static analysis findings for this contract.
    similar_exploits:
        Retrieved historical exploits (used to pick the right attack pattern).

    Returns
    -------
    PoCResult
        The generated skeleton with metadata.
    """
    high_findings = [
        f for f in findings
        if f.severity in (Severity.HIGH, Severity.CRITICAL)
    ]
    all_findings = high_findings or findings[:5]

    primary_vuln = _pick_primary_vuln(all_findings)
    needs_flash_loan = _needs_flash_loan(source_code, all_findings)
    interface_fns = _extract_interface_functions(source_code, contract_name, all_findings)
    attack_steps = _build_attack_steps(primary_vuln, all_findings, needs_flash_loan)
    todo_count = attack_steps.count("// TODO")

    source = _render_foundry_test(
        contract_name=contract_name,
        primary_vuln=primary_vuln,
        interface_fns=interface_fns,
        attack_steps=attack_steps,
        needs_flash_loan=needs_flash_loan,
        findings=all_findings,
    )

    return PoCResult(
        contract_name=contract_name,
        file_name=f"Attack{contract_name}.t.sol",
        source=source,
        primary_vuln=primary_vuln,
        needs_flash_loan=needs_flash_loan,
        todo_count=todo_count,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pick_primary_vuln(findings: list[StaticAnalysisFinding]) -> str:
    """Pick the most dangerous vulnerability to scaffold around."""
    # Priority order
    priority = [
        "reentrancy-eth", "reentrancy-no-eth",
        "arbitrary-send-eth", "arbitrary-send-erc20",
        "controlled-delegatecall", "unprotected-upgrade",
        "integer-overflow", "suicidal",
        "unchecked-transfer", "unchecked-lowlevel",
        "tx-origin", "oracle-manipulation",
    ]
    detector_names = {f.detector_name for f in findings}
    for p in priority:
        if p in detector_names:
            return p
    # Fall back to first finding
    return findings[0].detector_name if findings else "unknown"


def _needs_flash_loan(source_code: str, findings: list[StaticAnalysisFinding]) -> bool:
    """Determine if the attack likely needs a flash loan."""
    src_lower = source_code.lower()
    # Flash loan keywords in source
    if any(k in src_lower for k in ("flashloan", "flash_loan", "uniswapv2call", "pancakeswap")):
        return True
    # Price manipulation findings often benefit from flash loans
    categories = {f.category for f in findings}
    return VulnCategory.PRICE_MANIPULATION in categories or VulnCategory.ORACLE_MANIPULATION in categories


def _extract_interface_functions(
    source_code: str,
    contract_name: str,
    findings: list[StaticAnalysisFinding],
) -> list[str]:
    """
    Extract function signatures from source for the attack interface.
    Focuses on functions mentioned in findings + public/external functions.
    """
    # Get function names from findings
    finding_fns: set[str] = {f.function for f in findings if f.function}

    # Simple regex to extract public/external function signatures
    pattern = re.compile(
        r'function\s+(\w+)\s*\(([^)]*)\)\s*(?:public|external)[^;{]*(?:returns\s*\([^)]*\))?',
        re.MULTILINE,
    )

    sigs = []
    seen: set[str] = set()

    for m in pattern.finditer(source_code):
        fn_name = m.group(1)
        if fn_name in seen:
            continue
        seen.add(fn_name)

        params = m.group(2).strip()
        full_match = m.group(0)

        # Extract return type if present
        ret_match = re.search(r'returns\s*\(([^)]*)\)', full_match)
        ret_str = f" external returns ({ret_match.group(1)})" if ret_match else " external"

        sig = f"    function {fn_name}({params}){ret_str};"

        # Prioritise functions mentioned in findings
        if fn_name in finding_fns:
            sigs.insert(0, sig)
        else:
            sigs.append(sig)

    # Cap at 12 functions to keep the interface manageable
    return sigs[:12] if sigs else [
        f"    // TODO: Add {contract_name} function signatures here",
    ]


def _build_attack_steps(
    primary_vuln: str,
    findings: list[StaticAnalysisFinding],
    needs_flash_loan: bool,
) -> str:
    """Build the attack() function body with TODO steps."""
    lines: list[str] = []

    if needs_flash_loan:
        lines += [
            "        // TODO: Replace with actual Uniswap V2 pair address",
            "        address pair = address(0); // e.g. WETH/USDC pair",
            "        uint amount0 = 1_000_000e18; // TODO: set flash loan amount",
            "        uint amount1 = 0;",
            "        IUniswapV2Pair(pair).swap(amount0, amount1, address(this), abi.encode(\"flash\"));",
        ]
        return "\n".join(lines)

    # Reentrancy attack scaffold
    if "reentrancy" in primary_vuln:
        fn_name = _find_fn_for_vuln(findings, primary_vuln)
        lines += [
            f"        // Step 1: Deposit initial funds to establish position",
            f"        // TODO: determine minimum deposit amount",
            f"        target.deposit{{value: 1 ether}}();",
            f"",
            f"        // Step 2: Trigger the reentrant call",
            f"        // The receive() / fallback() will call back into the target",
            f"        target.{fn_name or 'withdraw'}();",
            f"",
            f"        // Step 3: Verify profit",
            f"        uint profit = address(this).balance - 1 ether;",
            f"        require(profit > 0, \"Attack failed: no profit\");",
        ]

    # Arbitrary ETH send
    elif primary_vuln == "arbitrary-send-eth":
        fn_name = _find_fn_for_vuln(findings, primary_vuln)
        lines += [
            "        // TODO: identify which function sends ETH without access control",
            f"        // Suspected function: {fn_name or 'UNKNOWN'}",
            "        // target.FUNCTION_NAME(address(this), AMOUNT);",
            "        // TODO: fill in the call above",
        ]

    # Unprotected upgrade
    elif primary_vuln == "unprotected-upgrade":
        fn_name = _find_fn_for_vuln(findings, primary_vuln)
        lines += [
            "        // Step 1: Deploy malicious implementation",
            "        MaliciousImpl impl = new MaliciousImpl();",
            "",
            "        // Step 2: Call the unprotected upgrade function",
            f"        // Suspected function: {fn_name or 'upgradeTo'}",
            f"        // TODO: target.{fn_name or 'upgradeTo'}(address(impl));",
        ]

    # Generic / unknown
    else:
        lines += [
            f"        // Primary vulnerability: {primary_vuln}",
            "        // TODO: Build attack sequence based on findings below",
        ]
        for f in findings[:3]:
            fn = f.function or "unknown"
            lines.append(f"        // Finding: {f.detector_name} in {fn} — {f.description[:80] if f.description else ''}...")

    return "\n".join(lines)


def _find_fn_for_vuln(findings: list[StaticAnalysisFinding], detector: str) -> Optional[str]:
    """Find the function name associated with a specific detector."""
    for f in findings:
        if f.detector_name == detector and f.function:
            return f.function
    return None


# ---------------------------------------------------------------------------
# Foundry template renderer
# ---------------------------------------------------------------------------


def _render_foundry_test(
    contract_name: str,
    primary_vuln: str,
    interface_fns: list[str],
    attack_steps: str,
    needs_flash_loan: bool,
    findings: list[StaticAnalysisFinding],
) -> str:
    """Render the complete Foundry test file."""

    flash_loan_imports = (
        '\ninterface IUniswapV2Pair {\n'
        '    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;\n'
        '}\n'
    ) if needs_flash_loan else ""

    flash_loan_callback = (
        '\n    // Uniswap V2 flash loan callback\n'
        '    function uniswapV2Call(\n'
        '        address sender,\n'
        '        uint amount0,\n'
        '        uint amount1,\n'
        '        bytes calldata data\n'
        '    ) external {\n'
        '        // TODO: Implement attack inside the flash loan\n'
        '        // Step 1: Execute exploit using borrowed funds\n'
        '        // TODO: exploit logic here\n\n'
        '        // Step 2: Repay flash loan\n'
        '        uint fee = (amount0 * 3) / 997 + 1; // 0.3% Uniswap V2 fee\n'
        '        // TODO: IERC20(token).transfer(msg.sender, amount0 + fee);\n'
        '    }\n'
    ) if needs_flash_loan else ""

    reentrancy_receive = (
        '\n    receive() external payable {\n'
        '        // Reentrancy callback — re-enter the target\n'
        '        if (address(target).balance > 0) {\n'
        '            // TODO: call the vulnerable function again\n'
        '            // target.withdraw();\n'
        '        }\n'
        '    }\n'
    ) if "reentrancy" in primary_vuln else ""

    finding_comments = "\n".join(
        f"//   [{f.severity.value.upper()}] {f.detector_name}"
        + (f" in {f.function}()" if f.function else "")
        + (f" — {f.description[:100]}..." if f.description else "")
        for f in findings[:5]
    )

    interface_body = "\n".join(interface_fns)

    return f"""// SPDX-License-Identifier: UNLICENSED
// ============================================================
//  VulnHound PoC Skeleton — {contract_name}
//  Primary vulnerability: {primary_vuln}
//  !! THIS IS A SCAFFOLD — FILL IN THE TODOs !!
// ============================================================
//
// Findings that triggered this scaffold:
{finding_comments}
//
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "forge-std/console.sol";
{flash_loan_imports}
// ---------------------------------------------------------------------------
// Interface for the target contract
// Replace with the actual import if the contract is in-scope.
// ---------------------------------------------------------------------------
interface I{contract_name} {{
{interface_body}
}}

// ---------------------------------------------------------------------------
// Attack contract
// ---------------------------------------------------------------------------
contract Attack{contract_name} {{
    I{contract_name} public target;
    address public owner;

    constructor(address _target) {{
        target = I{contract_name}(_target);
        owner = msg.sender;
    }}

    // ── Main attack entry point ──────────────────────────────────────────
    function attack() external payable {{
{attack_steps}
    }}
{reentrancy_receive}{flash_loan_callback}
    // Allow contract to receive ETH
    fallback() external payable {{}}
}}

// ---------------------------------------------------------------------------
// Foundry Test
// ---------------------------------------------------------------------------
contract Attack{contract_name}Test is Test {{
    Attack{contract_name} internal attacker;
    I{contract_name}  internal target;

    function setUp() public {{
        // TODO: Fork mainnet at the block before the vulnerability was introduced
        // vm.createSelectFork("mainnet", BLOCK_NUMBER);

        // TODO: Deploy or find the vulnerable contract
        // target = I{contract_name}(address(new {contract_name}()));
        // OR for a live contract:
        // target = I{contract_name}(0xCAFEBABE...);

        attacker = new Attack{contract_name}(address(target));

        // TODO: Fund attacker with initial ETH if needed
        vm.deal(address(attacker), 10 ether);
    }}

    function testExploit() public {{
        uint balanceBefore = address(attacker.owner()).balance;

        // Run the attack
        attacker.attack{{value: 1 ether}}();

        uint balanceAfter = address(attacker.owner()).balance;

        console.log("Balance before:", balanceBefore);
        console.log("Balance after: ", balanceAfter);
        console.log("Profit:        ", balanceAfter - balanceBefore);

        // TODO: Adjust the profit assertion to match the expected exploit
        assertGt(balanceAfter, balanceBefore, "Exploit did not profit");
    }}
}}
"""
