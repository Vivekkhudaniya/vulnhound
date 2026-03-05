# VulnHound — Audit Checklist
> Follow these steps IN ORDER for every new repo. Check off each item as you complete it.

---

## CURRENT TARGET: altitude-v2
Status: ❌ NOT STARTED (all previous Slither runs were on v2-core/UniswapV2, NOT altitude-v2)

---

## PHASE 1 — SETUP & RECON (Manual, no tools needed)

- [ ] **1.1 Read the README** — understand what the protocol does in 1 paragraph
- [ ] **1.2 Identify contract categories** — which folders/files are in scope?
  - altitude-v2 has: access/, common/, libraries/, oracles/, strategies/, tokens/, vaults/
- [ ] **1.3 Identify external integrations** — what protocols does it talk to?
  - altitude-v2 integrates: Aave, Curve, Convex, Uniswap, stETH/wstETH
- [ ] **1.4 Identify privileged roles** — who is admin/owner/operator?
- [ ] **1.5 Identify entry points** — what functions can users call?
- [ ] **1.6 Map the money flow** — where do funds come in? Where do they go?

---

## PHASE 2 — STATIC ANALYSIS (Automated)

- [ ] **2.1 Run VulnHound static analysis on altitude-v2**
  ```
  PYTHONUTF8=1 python -m src.cli.main analyze ./data/repos/altitude-v2 --tool slither
  ```
- [ ] **2.2 Review all HIGH findings** — are any real? Not false positives?
- [ ] **2.3 Review all MEDIUM findings** — cross-check with manual reading
- [ ] **2.4 Note which contracts appear most in findings** — those are hot zones

---

## PHASE 3 — FULL PIPELINE (Automated — needs Anthropic API credits)

- [ ] **3.1 Confirm API credits are available**
  ```
  PYTHONUTF8=1 python -m src.cli.main audit ./data/repos/altitude-v2 -o report_altitude.md
  ```
- [ ] **3.2 Read the generated report** — `report_altitude.md`
- [ ] **3.3 For each CRITICAL/HIGH finding — manually verify in the source code**
- [ ] **3.4 For each MEDIUM — decide: real or FP?**

---

## PHASE 4 — MANUAL DEEP DIVE (This is where real bugs are found)

### 4.1 Oracle Manipulation
- [ ] Read every file in `contracts/oracles/`
- [ ] Ask: Is the price from a single source? Can it be flash-loan manipulated?
- [ ] Ask: Is there a TWAP? Is the TWAP window long enough (>= 30 min)?
- [ ] Ask: What happens if the oracle returns 0 or stale data?

### 4.2 Access Control
- [ ] Read `contracts/access/Ingress.sol` and `contracts/common/Roles.sol`
- [ ] Ask: Can any function be called by an unauthorized address?
- [ ] Ask: Can roles be granted to address(0)?
- [ ] Ask: Is there a timelock on privileged actions?

### 4.3 Vault Logic
- [ ] Read every file in `contracts/vaults/`
- [ ] Ask: Can a user withdraw more than they deposited?
- [ ] Ask: Is the share price calculation rounding correctly (favor protocol, not user)?
- [ ] Ask: What happens on first deposit (inflation attack)?
- [ ] Ask: Is there a reentrancy guard on deposit/withdraw?

### 4.4 Strategy Logic
- [ ] Read every file in `contracts/strategies/`
- [ ] Ask: What happens if the external protocol (Aave/Curve) is paused?
- [ ] Ask: Can the strategy be drained by a sandwich attack?
- [ ] Ask: Is slippage checked when swapping?

### 4.5 Token Logic
- [ ] Read every file in `contracts/tokens/`
- [ ] Ask: Is transfer/transferFrom properly guarded?
- [ ] Ask: Are there any rebasing or fee-on-transfer tokens involved?

### 4.6 Libraries & Math
- [ ] Read every file in `contracts/libraries/`
- [ ] Ask: Are there unchecked blocks? Can they overflow?
- [ ] Ask: Is division-before-multiplication present? (causes precision loss)

---

## PHASE 5 — KNOWN ATTACK PATTERNS (Check each manually)

- [ ] **Reentrancy** — any external call before state update?
- [ ] **Flash loan attack** — can an attacker borrow, manipulate, repay in 1 tx?
- [ ] **Price oracle manipulation** — spot price used instead of TWAP?
- [ ] **Inflation/donation attack** — first depositor can manipulate share price?
- [ ] **Front-running** — are there transactions that can be sandwiched?
- [ ] **Signature replay** — are nonces and chain IDs checked in permit()?
- [ ] **Integer overflow/underflow** — any unchecked math?
- [ ] **Centralization risk** — can owner rug pull funds?
- [ ] **Upgradability risk** — is the proxy implementation slot safe?
- [ ] **DOS attack** — can an attacker make a function always revert?
- [ ] **Cross-function reentrancy** — reentrancy via a different function than deposit?
- [ ] **Read-only reentrancy** — price read during another contract's reentrancy?

---

## PHASE 6 — WRITE FINDINGS

For each real finding, document:
```
Title: [Short description]
Severity: Critical / High / Medium / Low
Contract: [file path]
Function: [function name]
Line: [line number]
Description: [what is wrong]
Impact: [what attacker can do]
POC: [step 1, step 2, step 3...]
Recommendation: [how to fix it]
```

---

## COMMANDS REFERENCE

```bash
# Static analysis only (no API key needed)
PYTHONUTF8=1 python -m src.cli.main analyze ./data/repos/altitude-v2

# Full pipeline (needs API key)
PYTHONUTF8=1 python -m src.cli.main audit ./data/repos/altitude-v2 -o report_altitude.md

# Search knowledge base
PYTHONUTF8=1 python -m src.cli.main kb search "flash loan oracle manipulation"

# KB stats
PYTHONUTF8=1 python -m src.cli.main kb stats
```

---

## CURRENT BLOCKERS

1. **Static analysis not run on altitude-v2** — all previous runs were on v2-core. Run Phase 2.1 first.
2. **API credits** — needed for Phase 3. Check if top-up has propagated.

---
*Last updated: 2026-02-27*
