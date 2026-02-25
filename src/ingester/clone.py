"""
VulnHound Ingester - Stage 1: Clone & Framework Detection

Handles cloning remote Git repositories or validating local paths,
and detecting which build framework the project uses.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console

console = Console(stderr=True)

# Markers used to identify build frameworks
_FRAMEWORK_MARKERS: list[tuple[str, list[str]]] = [
    ("foundry", ["foundry.toml", "forge.toml"]),
    ("hardhat", ["hardhat.config.js", "hardhat.config.ts", "hardhat.config.cjs", "hardhat.config.mjs"]),
    ("truffle", ["truffle-config.js", "truffle-config.ts", "truffle.js"]),
]


def is_git_repo(path: Path) -> bool:
    """Return True if *path* is the root of a git repository (has a .git entry)."""
    return (path / ".git").exists()


def clone_repo(url: str, target_dir: Path) -> Path:
    """
    Clone *url* into *target_dir* (creating it if necessary) and return the
    clone path.  If the directory already exists and is a git repo, ``git pull``
    is run instead of a fresh clone.

    Parameters
    ----------
    url:
        A HTTPS or SSH git URL, e.g. ``https://github.com/owner/repo.git``.
    target_dir:
        The directory that will contain the cloned repository.

    Returns
    -------
    Path
        Absolute path to the repository root.
    """
    target_dir = target_dir.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    if is_git_repo(target_dir):
        console.log(f"[cyan]Repository already cloned at {target_dir} — pulling latest…[/cyan]")
        _run_git(["git", "-C", str(target_dir), "pull", "--ff-only"], cwd=target_dir)
    else:
        console.log(f"[cyan]Cloning [bold]{url}[/bold] → {target_dir}[/cyan]")
        _run_git(["git", "clone", "--depth", "1", url, str(target_dir)], cwd=None)

    return target_dir


def detect_framework(repo_path: Path) -> str:
    """
    Inspect the repository root for well-known config files and return the
    framework name.

    Returns
    -------
    str
        One of ``"foundry"``, ``"hardhat"``, ``"truffle"``, or ``"unknown"``.
    """
    repo_path = repo_path.resolve()
    for framework, markers in _FRAMEWORK_MARKERS:
        for marker in markers:
            if (repo_path / marker).exists():
                console.log(f"[green]Detected framework: [bold]{framework}[/bold] (found {marker})[/green]")
                return framework

    console.log("[yellow]Framework not detected — returning 'unknown'[/yellow]")
    return "unknown"


def resolve_repo(url_or_path: str, work_dir: Path) -> tuple[Path, Optional[str]]:
    """
    High-level helper used by the ingester ``__init__``.

    If *url_or_path* looks like a remote URL (starts with ``http``, ``https``,
    or ``git@``) it is cloned; otherwise the path is used directly.

    Returns
    -------
    tuple[Path, Optional[str]]
        ``(repo_path, repo_url)`` where ``repo_url`` is ``None`` for local paths.
    """
    stripped = url_or_path.strip()

    is_remote = (
        stripped.startswith("http://")
        or stripped.startswith("https://")
        or stripped.startswith("git@")
        or stripped.endswith(".git")
    )

    if is_remote:
        # Derive a deterministic subdirectory name from the URL
        repo_name = stripped.rstrip("/").split("/")[-1].removesuffix(".git")
        target = work_dir / repo_name
        repo_path = clone_repo(stripped, target)
        return repo_path, stripped
    else:
        local_path = Path(stripped).resolve()
        if not local_path.exists():
            raise FileNotFoundError(f"Local path does not exist: {local_path}")
        if not local_path.is_dir():
            raise NotADirectoryError(f"Expected a directory, got: {local_path}")
        console.log(f"[cyan]Using local repository at {local_path}[/cyan]")
        return local_path, None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run_git(cmd: list[str], *, cwd: Optional[Path]) -> subprocess.CompletedProcess[str]:
    """Run a git command, raising ``RuntimeError`` on non-zero exit."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(cwd) if cwd else None,
            timeout=300,  # 5 minutes — enough for large repos with --depth 1
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Git command timed out: {' '.join(cmd)}") from exc
    except FileNotFoundError as exc:
        raise RuntimeError(
            "git executable not found. Please install Git and ensure it is on your PATH."
        ) from exc

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(
            f"Git command failed (exit {result.returncode}): {' '.join(cmd)}\n{stderr}"
        )

    return result
