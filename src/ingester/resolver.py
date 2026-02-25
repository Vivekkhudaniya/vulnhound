"""
VulnHound Ingester - Stage 1: Solidity File Resolver

Locates all relevant .sol files in a repository, parses remappings used by the
compiler, and extracts the configured Solidity compiler version.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console(stderr=True)

# Directory segments that indicate test / vendor / generated code
_EXCLUDE_SEGMENTS: frozenset[str] = frozenset(
    {
        "test",
        "tests",
        "mock",
        "mocks",
        "lib",
        "node_modules",
        ".git",
        "script",
        "scripts",
    }
)


def find_sol_files(repo_path: Path, exclude_tests: bool = True) -> list[Path]:
    """
    Recursively find all Solidity source files under *repo_path*.

    Parameters
    ----------
    repo_path:
        Root of the repository.
    exclude_tests:
        When ``True`` (default), skip paths whose components match any of the
        common test / vendor directory names.  When ``False``, return every
        ``.sol`` file found.

    Returns
    -------
    list[Path]
        Sorted list of absolute paths to ``.sol`` files.
    """
    repo_path = repo_path.resolve()
    all_files: list[Path] = sorted(repo_path.rglob("*.sol"))

    if not exclude_tests:
        console.log(f"[cyan]Found {len(all_files)} .sol file(s) (include-all mode)[/cyan]")
        return all_files

    filtered: list[Path] = []
    for sol_file in all_files:
        # Get path parts relative to repo root for segment-level matching
        try:
            rel_parts = set(sol_file.relative_to(repo_path).parts[:-1])  # exclude filename
        except ValueError:
            rel_parts = set(sol_file.parts[:-1])

        # Lowercase comparison for cross-platform safety
        lower_parts = {p.lower() for p in rel_parts}
        if lower_parts & _EXCLUDE_SEGMENTS:
            continue

        filtered.append(sol_file)

    console.log(
        f"[cyan]Found {len(filtered)} .sol file(s) "
        f"(excluded {len(all_files) - len(filtered)} test/vendor files)[/cyan]"
    )
    return filtered


def read_remappings(repo_path: Path) -> dict[str, str]:
    """
    Parse compiler import remappings for the project.

    Sources checked (in order):
    1. ``remappings.txt`` — one remapping per line (``prefix=target``)
    2. ``foundry.toml`` — ``[profile.default]`` section ``remappings`` array

    Returns
    -------
    dict[str, str]
        Mapping of ``import_prefix → resolved_path``.
    """
    repo_path = repo_path.resolve()
    remappings: dict[str, str] = {}

    # ── 1. remappings.txt ────────────────────────────────────────────────────
    remap_txt = repo_path / "remappings.txt"
    if remap_txt.exists():
        try:
            for line in remap_txt.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    prefix, _, target = line.partition("=")
                    remappings[prefix.strip()] = target.strip()
            console.log(f"[cyan]Loaded {len(remappings)} remapping(s) from remappings.txt[/cyan]")
            return remappings
        except OSError as exc:
            console.log(f"[yellow]Could not read remappings.txt: {exc}[/yellow]")

    # ── 2. foundry.toml ──────────────────────────────────────────────────────
    foundry_toml = repo_path / "foundry.toml"
    if foundry_toml.exists():
        try:
            content = foundry_toml.read_text(encoding="utf-8", errors="replace")
            remappings.update(_parse_foundry_remappings(content))
            if remappings:
                console.log(
                    f"[cyan]Loaded {len(remappings)} remapping(s) from foundry.toml[/cyan]"
                )
        except OSError as exc:
            console.log(f"[yellow]Could not read foundry.toml: {exc}[/yellow]")

    return remappings


def get_compiler_version(repo_path: Path) -> Optional[str]:
    """
    Extract the Solidity compiler version declared by the project.

    Checks ``foundry.toml`` first, then ``hardhat.config.js`` / ``.ts``.

    Returns
    -------
    Optional[str]
        Version string such as ``"0.8.20"``, or ``None`` if not found.
    """
    repo_path = repo_path.resolve()

    # ── foundry.toml ─────────────────────────────────────────────────────────
    foundry_toml = repo_path / "foundry.toml"
    if foundry_toml.exists():
        version = _extract_version_foundry(foundry_toml)
        if version:
            return version

    # ── hardhat.config.{js,ts,cjs,mjs} ──────────────────────────────────────
    for config_name in ("hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs", "hardhat.config.mjs"):
        hardhat_cfg = repo_path / config_name
        if hardhat_cfg.exists():
            version = _extract_version_hardhat(hardhat_cfg)
            if version:
                return version

    # ── package.json solc field ───────────────────────────────────────────────
    package_json = repo_path / "package.json"
    if package_json.exists():
        version = _extract_version_package_json(package_json)
        if version:
            return version

    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Matches a TOML array spanning multiple lines, e.g.
# remappings = [
#   "@openzeppelin/=lib/openzeppelin-contracts/",
# ]
_FOUNDRY_REMAP_ARRAY_RE = re.compile(
    r'remappings\s*=\s*\[([^\]]*)\]',
    re.DOTALL,
)
_QUOTED_REMAP_RE = re.compile(r'["\']([^"\']+=[^"\']*)["\']')


def _parse_foundry_remappings(content: str) -> dict[str, str]:
    remappings: dict[str, str] = {}
    match = _FOUNDRY_REMAP_ARRAY_RE.search(content)
    if not match:
        return remappings
    array_body = match.group(1)
    for item_match in _QUOTED_REMAP_RE.finditer(array_body):
        item = item_match.group(1).strip()
        if "=" in item:
            prefix, _, target = item.partition("=")
            remappings[prefix.strip()] = target.strip()
    return remappings


# solc = "0.8.20"  or  solc = '0.8.20'
_FOUNDRY_SOLC_RE = re.compile(r'solc\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']')
# solc_version = "0.8.20"
_FOUNDRY_SOLC_VER_RE = re.compile(r'solc_version\s*=\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']')


def _extract_version_foundry(toml_path: Path) -> Optional[str]:
    try:
        content = toml_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for pattern in (_FOUNDRY_SOLC_RE, _FOUNDRY_SOLC_VER_RE):
        m = pattern.search(content)
        if m:
            return m.group(1)
    return None


# solidity: { version: "0.8.20" }  or  solcVersion: "0.8.20"
_HARDHAT_VERSION_RE = re.compile(
    r'(?:version|solcVersion)\s*[=:]\s*["\']([0-9]+\.[0-9]+\.[0-9]+)["\']'
)


def _extract_version_hardhat(config_path: Path) -> Optional[str]:
    try:
        content = config_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _HARDHAT_VERSION_RE.search(content)
    return m.group(1) if m else None


# "solc": "0.8.20"  inside package.json
_PKG_SOLC_RE = re.compile(r'"solc"\s*:\s*"([0-9]+\.[0-9]+\.[0-9]+)"')


def _extract_version_package_json(pkg_path: Path) -> Optional[str]:
    try:
        content = pkg_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _PKG_SOLC_RE.search(content)
    return m.group(1) if m else None
