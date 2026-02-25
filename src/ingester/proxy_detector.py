"""
VulnHound Ingester - Stage 1: Proxy Pattern Detector

Identifies common proxy upgrade patterns in Solidity contracts using
regex-based heuristics against the contract source and its parsed metadata.

Supported patterns
------------------
- **UUPS**        — EIP-1822 / OpenZeppelin UUPSUpgradeable
- **Transparent** — OpenZeppelin TransparentUpgradeableProxy / ProxyAdmin
- **Diamond**     — EIP-2535 Diamond / facet pattern
- **Beacon**      — BeaconProxy / UpgradeableBeacon
- **EIP-1967**    — raw storage-slot implementation proxy (base class)
"""

from __future__ import annotations

import re
from typing import Optional

from rich.console import Console

console = Console(stderr=True)


# ============================================================
# Compiled detection patterns
# ============================================================

# --- UUPS ---
_UUPS_BASE_CLASSES = re.compile(r"\bUUPSUpgradeable\b")
_UUPS_FUNCTION = re.compile(r"\bfunction\s+upgradeTo\b")
_UUPS_UPGRADE_AND_CALL = re.compile(r"\bfunction\s+upgradeToAndCall\b")

# --- Transparent ---
_TRANSPARENT_BASE_CLASSES = re.compile(
    r"\b(?:TransparentUpgradeableProxy|ProxyAdmin|ITransparentUpgradeableProxy)\b"
)
_TRANSPARENT_ADMIN_SLOT = re.compile(r"_ADMIN_SLOT\b")

# --- Diamond ---
_DIAMOND_CUT_FUNCTION = re.compile(r"\bfunction\s+diamondCut\b")
_DIAMOND_LOUPE_FUNCTION = re.compile(r"\bfunction\s+facets\b")
_DIAMOND_FACET_PATTERN = re.compile(r"\bfacet\b", re.IGNORECASE)

# --- Beacon ---
_BEACON_BASE_CLASSES = re.compile(r"\b(?:BeaconProxy|UpgradeableBeacon|IBeacon)\b")
_BEACON_IMPL_FUNCTION = re.compile(r"\bfunction\s+implementation\b")

# --- EIP-1967 storage slots ---
_EIP1967_IMPL_SLOT = re.compile(r"\b_IMPLEMENTATION_SLOT\b")
_EIP1967_SLOT_VALUE = re.compile(
    r"0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
)
_FALLBACK_DELEGATE = re.compile(r"\bassembly\b.*?\.delegatecall\b", re.DOTALL)
_PROXY_BASE_CLASSES = re.compile(r"\b(?:Proxy|ERC1967Proxy|ERC1967Upgrade)\b")


# ============================================================
# Public API
# ============================================================


def detect_proxy(content: str, contract_name: str) -> tuple[bool, Optional[str]]:
    """
    Analyse Solidity source *content* for the contract named *contract_name*
    and return a classification.

    Detection priority (highest specificity first):
    Diamond > UUPS > Transparent > Beacon > EIP-1967

    Parameters
    ----------
    content:
        Raw (or comment-stripped) Solidity source for **the specific contract**
        being evaluated (i.e. just the contract body, not the entire file).
        Passing the entire file is also safe — the function checks name-level
        heuristics too.
    contract_name:
        The name of the contract (used for name-based heuristics).

    Returns
    -------
    tuple[bool, Optional[str]]
        ``(is_proxy, proxy_type)`` where *proxy_type* is one of
        ``"UUPS"``, ``"Transparent"``, ``"Diamond"``, ``"Beacon"``, ``"EIP-1967"``,
        or ``None`` if not a proxy.
    """
    name_lower = contract_name.lower()

    # ── Diamond ───────────────────────────────────────────────────────────────
    if _is_diamond(content, name_lower):
        console.log(f"[magenta]  [proxy] {contract_name} → Diamond[/magenta]")
        return True, "Diamond"

    # ── UUPS ─────────────────────────────────────────────────────────────────
    if _is_uups(content):
        console.log(f"[magenta]  [proxy] {contract_name} → UUPS[/magenta]")
        return True, "UUPS"

    # ── Transparent ──────────────────────────────────────────────────────────
    if _is_transparent(content):
        console.log(f"[magenta]  [proxy] {contract_name} → Transparent[/magenta]")
        return True, "Transparent"

    # ── Beacon ───────────────────────────────────────────────────────────────
    if _is_beacon(content):
        console.log(f"[magenta]  [proxy] {contract_name} → Beacon[/magenta]")
        return True, "Beacon"

    # ── Generic EIP-1967 / raw proxy ─────────────────────────────────────────
    if _is_eip1967(content, name_lower):
        console.log(f"[magenta]  [proxy] {contract_name} → EIP-1967[/magenta]")
        return True, "EIP-1967"

    return False, None


# ============================================================
# Pattern-specific detectors
# ============================================================


def _is_uups(content: str) -> bool:
    """UUPS: inherits UUPSUpgradeable OR exposes upgradeTo/upgradeToAndCall."""
    return bool(
        _UUPS_BASE_CLASSES.search(content)
        or _UUPS_FUNCTION.search(content)
        or _UUPS_UPGRADE_AND_CALL.search(content)
    )


def _is_transparent(content: str) -> bool:
    """Transparent: inherits TransparentUpgradeableProxy or ProxyAdmin."""
    return bool(
        _TRANSPARENT_BASE_CLASSES.search(content)
        or _TRANSPARENT_ADMIN_SLOT.search(content)
    )


def _is_diamond(content: str, name_lower: str) -> bool:
    """
    Diamond: has diamondCut function, OR has facets() loupe, OR contract name
    contains "diamond" and source mentions "facet".
    """
    if _DIAMOND_CUT_FUNCTION.search(content):
        return True
    if _DIAMOND_LOUPE_FUNCTION.search(content):
        return True
    if "diamond" in name_lower and _DIAMOND_FACET_PATTERN.search(content):
        return True
    return False


def _is_beacon(content: str) -> bool:
    """Beacon: inherits BeaconProxy or UpgradeableBeacon."""
    return bool(_BEACON_BASE_CLASSES.search(content))


def _is_eip1967(content: str, name_lower: str) -> bool:
    """
    Generic EIP-1967 / raw delegatecall proxy:
    - uses _IMPLEMENTATION_SLOT constant, OR
    - contains the well-known EIP-1967 slot value, OR
    - has assembly delegatecall (typical fallback pattern), OR
    - inherits from Proxy / ERC1967Proxy, OR
    - name contains "proxy" and source has delegatecall
    """
    if _EIP1967_IMPL_SLOT.search(content):
        return True
    if _EIP1967_SLOT_VALUE.search(content):
        return True
    if _PROXY_BASE_CLASSES.search(content):
        return True
    if "proxy" in name_lower and re.search(r"\.delegatecall\b", content):
        return True
    # Assembly-level delegatecall in a fallback / receive
    if _FALLBACK_DELEGATE.search(content):
        return True
    return False
