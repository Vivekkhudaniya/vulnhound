"""
VulnHound Ingester - Stage 1: Regex-Based Solidity AST Parser

Parses Solidity source files without relying on any third-party parser
(solidity-parser, tree-sitter, etc.) — pure regex, so it never crashes on
exotic syntax.

Extracts:
- Pragma / compiler version
- Contract / interface / library / abstract contract declarations
- Inheritance lists
- Function signatures (name, visibility, state mutability, modifiers)
- External call sites
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from rich.console import Console

from src.models import ContractInfo, FunctionInfo

console = Console(stderr=True)


# ============================================================
# Compiled regex patterns
# ============================================================

# Strip single-line and multi-line comments before parsing
_SINGLE_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_MULTI_LINE_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)

# pragma solidity >=0.8.0 <0.9.0;  or  ^0.8.20
_PRAGMA_RE = re.compile(r"pragma\s+solidity\s+([^\s;][^;]*);")

# contract Foo is Bar, Baz {
_CONTRACT_RE = re.compile(
    r"(?:^|\n)\s*"
    r"(?P<kind>abstract\s+contract|contract|interface|library)"
    r"\s+(?P<name>\w+)"
    r"(?:\s+is\s+(?P<bases>[^{]+))?"
    r"\s*\{",
    re.MULTILINE,
)

# function transfer(address to, uint256 amount) public payable override returns (bool) {
_FUNCTION_RE = re.compile(
    r"function\s+(?P<name>\w+)\s*"
    r"\((?P<params>[^)]*)\)\s*"
    r"(?P<modifiers>(?:"
    r"public|external|internal|private|"
    r"view|pure|payable|"
    r"virtual|override|"
    r"[\w]+(?:\s*\([^)]*\))?"  # named modifiers with optional args
    r")\s*)*"
    r"(?:returns\s*\([^)]*\))?"
    r"\s*(?:\{|;)",
    re.MULTILINE,
)

# Visibility keywords
_VISIBILITY_TOKENS = frozenset({"public", "external", "internal", "private"})
# State mutability keywords
_MUTABILITY_TOKENS = frozenset({"view", "pure", "payable"})
# Non-visibility / non-mutability modifier words to strip
_SKIP_MODIFIER_TOKENS = frozenset({"virtual", "override", "returns", "function"})

# External call site patterns
_EXTERNAL_CALL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("low_level_call",      re.compile(r"\.call\s*\{")),
    ("delegatecall",        re.compile(r"\.delegatecall\s*\(")),
    ("staticcall",          re.compile(r"\.staticcall\s*\(")),
    ("erc20_transfer",      re.compile(r"\.transfer\s*\(")),
    ("erc20_transfer_from", re.compile(r"\.transferFrom\s*\(")),
    ("erc20_interface",     re.compile(r"IERC20\s*\(")),
    ("erc721_interface",    re.compile(r"IERC721\s*\(")),
    ("send",                re.compile(r"\.send\s*\(")),
]


# ============================================================
# Public API
# ============================================================


def parse_sol_file(file_path: Path) -> list[ContractInfo]:
    """
    Parse a single Solidity file and return one ``ContractInfo`` per
    contract / interface / library found in the file.

    Parameters
    ----------
    file_path:
        Absolute path to the ``.sol`` file.

    Returns
    -------
    list[ContractInfo]
        May be empty if the file contains no contract declarations.
    """
    try:
        raw_content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        console.log(f"[red]Cannot read {file_path}: {exc}[/red]")
        return []

    # Strip comments so patterns don't accidentally match inside them
    content = _strip_comments(raw_content)

    solidity_version = _extract_pragma(content)
    loc = _count_loc(raw_content)

    contracts: list[ContractInfo] = []

    for match in _CONTRACT_RE.finditer(content):
        name: str = match.group("name")
        bases_raw: Optional[str] = match.group("bases")

        inherits_from: list[str] = []
        if bases_raw:
            inherits_from = [b.strip() for b in bases_raw.split(",") if b.strip()]
            # Remove generic type arguments, e.g. ERC20Upgradeable → keep as-is but strip <...>
            inherits_from = [re.sub(r"<[^>]*>", "", b).strip() for b in inherits_from]
            inherits_from = [b for b in inherits_from if b]

        # Extract the body of this contract to scope our function/call searches
        body_start = match.end()
        body = _extract_contract_body(content, body_start)

        external_calls = _detect_external_calls(body)

        contracts.append(
            ContractInfo(
                name=name,
                file_path=str(file_path),
                solidity_version=solidity_version,
                inherits_from=inherits_from,
                external_calls=external_calls,
                loc=loc,
            )
        )

    return contracts


def parse_functions(content: str, contract_name: str) -> list[FunctionInfo]:
    """
    Extract all function declarations from Solidity source *content*.

    Parameters
    ----------
    content:
        Raw (or comment-stripped) Solidity source text.
    contract_name:
        Name of the contract these functions belong to (used to populate
        ``FunctionInfo.contract``).

    Returns
    -------
    list[FunctionInfo]
    """
    stripped = _strip_comments(content)
    functions: list[FunctionInfo] = []
    lines = content.splitlines()

    for match in _FUNCTION_RE.finditer(stripped):
        func_name: str = match.group("name")
        params_raw: str = match.group("params") or ""
        modifiers_raw: str = match.group("modifiers") or ""

        visibility, state_mutability, modifiers = _parse_modifier_string(modifiers_raw)

        parameters = _parse_parameter_list(params_raw)

        # Locate source lines for this function
        start_char = match.start()
        end_char = _find_function_end(stripped, match.end())
        start_line = stripped[:start_char].count("\n") + 1
        end_line = stripped[:end_char].count("\n") + 1

        source_code = "\n".join(lines[start_line - 1 : end_line])

        functions.append(
            FunctionInfo(
                name=func_name,
                contract=contract_name,
                visibility=visibility,
                state_mutability=state_mutability,
                modifiers=modifiers,
                parameters=parameters,
                return_types=[],          # populated separately if needed
                source_code=source_code,
                start_line=start_line,
                end_line=end_line,
            )
        )

    return functions


# ============================================================
# Internal helpers
# ============================================================


def _strip_comments(source: str) -> str:
    """Remove // and /* */ comments, preserving line structure."""
    source = _MULTI_LINE_COMMENT_RE.sub(lambda m: "\n" * m.group().count("\n"), source)
    source = _SINGLE_LINE_COMMENT_RE.sub("", source)
    return source


def _extract_pragma(content: str) -> Optional[str]:
    """Return the first pragma solidity version specifier found."""
    m = _PRAGMA_RE.search(content)
    if not m:
        return None
    # Normalise whitespace
    return " ".join(m.group(1).split())


def _count_loc(raw_content: str) -> int:
    """Count non-empty, non-comment lines (rough LOC metric)."""
    stripped = _strip_comments(raw_content)
    return sum(1 for line in stripped.splitlines() if line.strip())


def _extract_contract_body(content: str, start: int) -> str:
    """
    Return the text of a contract body starting just after the opening ``{``.
    Tracks brace nesting to find the matching closing ``}``.
    """
    depth = 1
    i = start
    length = len(content)
    while i < length and depth > 0:
        ch = content[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        i += 1
    return content[start:i]


def _detect_external_calls(body: str) -> list[str]:
    """Return deduplicated list of external-call categories found in *body*."""
    found: list[str] = []
    for label, pattern in _EXTERNAL_CALL_PATTERNS:
        if pattern.search(body):
            found.append(label)
    return found


def _parse_modifier_string(
    modifiers_raw: str,
) -> tuple[str, Optional[str], list[str]]:
    """
    Split a raw modifier string into visibility, state_mutability, and
    any named modifier references.

    Returns
    -------
    tuple[str, Optional[str], list[str]]
        ``(visibility, state_mutability, named_modifiers)``
    """
    # Tokenise: split on whitespace / parenthesised modifier args
    tokens = re.findall(r"\w+", modifiers_raw)

    visibility = "internal"  # Solidity default for functions
    state_mutability: Optional[str] = None
    named_modifiers: list[str] = []

    for token in tokens:
        if token in _VISIBILITY_TOKENS:
            visibility = token
        elif token in _MUTABILITY_TOKENS:
            state_mutability = token
        elif token not in _SKIP_MODIFIER_TOKENS:
            named_modifiers.append(token)

    return visibility, state_mutability, named_modifiers


def _parse_parameter_list(params_raw: str) -> list[str]:
    """
    Convert a raw parameter string into a list of parameter type strings.

    e.g. ``"address to, uint256 amount"`` → ``["address", "uint256"]``
    """
    if not params_raw.strip():
        return []
    params: list[str] = []
    for param in params_raw.split(","):
        parts = param.strip().split()
        if parts:
            params.append(parts[0])  # type token only
    return params


def _find_function_end(content: str, brace_search_start: int) -> int:
    """
    Starting from *brace_search_start*, find the position just after the
    closing ``}`` of a function body.  If the function has no body (just a
    ``;``), return the position of the semicolon.
    """
    i = brace_search_start
    length = len(content)

    # Skip whitespace to find first meaningful character
    while i < length and content[i] in " \t\n\r":
        i += 1

    if i >= length:
        return length

    # Abstract / interface functions end with ;
    if content[i] == ";":
        return i + 1

    # Regular function — scan for matching closing brace
    if content[i] == "{":
        depth = 1
        i += 1
        while i < length and depth > 0:
            ch = content[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            i += 1
        return i

    # Fallback: return current position
    return i
