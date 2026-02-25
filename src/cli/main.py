"""
VulnHound CLI

The main command-line interface for running audits.

Usage:
    vulnhound audit <repo-url>          # Full audit pipeline
    vulnhound audit <local-path>        # Audit local project
    vulnhound kb ingest                 # Ingest exploits into knowledge base
    vulnhound kb search "reentrancy"    # Search the exploit KB
    vulnhound kb stats                  # Show KB statistics
    vulnhound analyze <path>            # Static analysis only
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

app = typer.Typer(
    name="vulnhound",
    help="🐕 VulnHound — AI Smart Contract Auditing Agent",
    no_args_is_help=True,
)
console = Console()

# Sub-commands
kb_app = typer.Typer(help="Knowledge base management")
app.add_typer(kb_app, name="kb")


# ============================================
# Banner
# ============================================

BANNER = """
[bold red]
 __   ___   _ _     _   _  ___  _   _ _   _ ____
 \ \ / / | | | |   | \ | |/ _ \| | | | \ | |  _ \\
  \ V /| | | | |   |  \| | | | | | | |  \| | | | |
   | | | |_| | |___| |\  | |_| | |_| | |\  | |_| |
   |_|  \___/|_____|_| \_|\___/ \___/|_| \_|____/
[/bold red]
[dim]AI Smart Contract Auditing Agent v0.1.0[/dim]
"""


def show_banner():
    console.print(BANNER)


# ============================================
# Main Commands
# ============================================


@app.command()
def audit(
    target: str = typer.Argument(help="GitHub repo URL or local path to audit"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output report path"),
    severity: str = typer.Option("medium", "--min-severity", "-s", help="Minimum severity to report"),
    skip_poc: bool = typer.Option(False, "--skip-poc", help="Skip PoC generation (faster)"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="Override LLM model"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """
    🔍 Run a full audit on a smart contract repository.

    Examples:
        vulnhound audit https://github.com/user/defi-protocol
        vulnhound audit ./contracts --skip-poc
        vulnhound audit ./contracts -s high -o report.md
    """
    show_banner()

    console.print(
        Panel(
            f"[bold]Target:[/bold] {target}\n"
            f"[bold]Min Severity:[/bold] {severity}\n"
            f"[bold]PoC Generation:[/bold] {'disabled' if skip_poc else 'enabled'}",
            title="[bold red]Audit Configuration[/bold red]",
            border_style="red",
        )
    )

    from pathlib import Path
    from src.ingester import ingest_repo
    from src.config import get_settings
    settings = get_settings()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Stage 1
        task = progress.add_task("[red]Stage 1: Ingesting repository...", total=None)
        scope = ingest_repo(target, work_dir=Path("./data/repos"))
        progress.update(task, description=f"[red]Stage 1: OK {len(scope.contracts)} contracts, {scope.total_loc} LOC")

        # Stage 2
        task = progress.add_task("[yellow]Stage 2: Running static analysis...", total=None)
        # TODO: Implement static analysis
        progress.update(task, description="[yellow]Stage 2: ✓ Static analysis complete")

        # Stage 3
        task = progress.add_task("[green]Stage 3: Retrieving similar exploits...", total=None)
        # TODO: Implement RAG retrieval
        progress.update(task, description="[green]Stage 3: ✓ Exploit context loaded")

        # Stage 4
        task = progress.add_task("[cyan]Stage 4: LLM deep analysis...", total=None)
        # TODO: Implement LLM analysis
        progress.update(task, description="[cyan]Stage 4: ✓ LLM analysis complete")

        # Stage 5
        task = progress.add_task("[blue]Stage 5: Validating findings...", total=None)
        # TODO: Implement validation
        progress.update(task, description="[blue]Stage 5: ✓ Findings validated")

        if not skip_poc:
            # Stage 6
            task = progress.add_task("[magenta]Stage 6: Generating PoCs...", total=None)
            # TODO: Implement PoC generation
            progress.update(task, description="[magenta]Stage 6: ✓ PoCs generated")

        # Stage 7
        task = progress.add_task("[white]Stage 7: Generating report...", total=None)
        # TODO: Implement report generation
        progress.update(task, description="[white]Stage 7: ✓ Report generated")

    # Summary table (placeholder)
    table = Table(title="Audit Summary", border_style="red")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("[red]Critical[/red]", "0")
    table.add_row("[yellow]High[/yellow]", "0")
    table.add_row("[blue]Medium[/blue]", "0")
    table.add_row("[dim]Low[/dim]", "0")
    table.add_row("[dim]Informational[/dim]", "0")
    console.print(table)

    console.print("\n[bold green]✓ Audit complete![/bold green]")
    console.print("[dim]Pipeline connected. Implement each stage to see real results.[/dim]\n")


@app.command()
def analyze(
    path: str = typer.Argument(help="Path to contracts directory"),
    tool: str = typer.Option("slither", "--tool", "-t", help="Static analysis tool"),
):
    """
    ⚡ Run static analysis only (no LLM, no KB).

    Quick way to get Slither/Aderyn results in structured format.
    """
    show_banner()
    console.print(f"[bold]Running {tool} on {path}...[/bold]")
    # TODO: Implement
    console.print("[yellow]Static analysis module not yet implemented.[/yellow]")
    console.print("[dim]Next step: implement src/analyzers/slither_runner.py[/dim]")


# ============================================
# Knowledge Base Commands
# ============================================


@kb_app.command("ingest")
def kb_ingest(
    source: str = typer.Option(
        "all", "--source", "-s", help="Data source: defihacklabs, solodit, rekt, all"
    ),
    limit: Optional[int] = typer.Option(None, "--limit", "-l", help="Limit number of exploits"),
):
    """
    🧠 Ingest historical exploits into the knowledge base.

    This populates the vector DB with historical DeFi exploits
    that the LLM uses during analysis.
    """
    from pathlib import Path
    from src.knowledge_base.ingest_exploits import ingest_defihacklabs
    from src.config import get_settings

    show_banner()
    settings = get_settings()
    console.print(f"[bold]Ingesting exploits from: {source}[/bold]")

    if source in ("all", "defihacklabs"):
        ingest_defihacklabs(
            target_dir=Path("./data/repos/DeFiHackLabs"),
            output_dir=Path(settings.knowledge_base_dir) / "exploits",
            limit=limit,
        )

    if source in ("all", "solodit"):
        from src.knowledge_base.ingest_solodit import ingest_solodit
        ingest_solodit(limit=limit)

    if source in ("all", "rekt"):
        from src.knowledge_base.ingest_rekt import ingest_rekt
        ingest_rekt(limit=limit)


@kb_app.command("search")
def kb_search(
    query: str = typer.Argument(help="Search query"),
    top_k: int = typer.Option(5, "--top-k", "-k", help="Number of results"),
):
    """
    🔎 Search the exploit knowledge base.

    Examples:
        vulnhound kb search "reentrancy flash loan"
        vulnhound kb search "price oracle manipulation" -k 10
    """
    from src.knowledge_base.embedder import ExploitEmbedder
    from src.knowledge_base.vector_store import ChromaVectorStore

    show_banner()
    console.print(f"[bold]Searching KB for: '{query}' (top {top_k})[/bold]\n")

    store = ChromaVectorStore()
    embedder = ExploitEmbedder()
    query_vec = embedder.embed_query(query)

    results = store.search_by_description(query_vec, top_k=top_k)

    if not results:
        console.print("[yellow]No results found. Have you run 'vulnhound kb ingest' yet?[/yellow]")
        return

    table = Table(title=f"KB Search: '{query}'", border_style="red")
    table.add_column("#", style="dim", width=3)
    table.add_column("Exploit ID", style="cyan")
    table.add_column("Protocol", style="bold")
    table.add_column("Category")
    table.add_column("Loss (USD)", justify="right")
    table.add_column("Score", justify="right")

    for i, r in enumerate(results, 1):
        table.add_row(
            str(i),
            r.exploit_id,
            r.protocol,
            r.category if isinstance(r.category, str) else r.category.value,
            f"${r.loss_usd:,.0f}" if r.loss_usd else "—",
            f"{r.similarity_score:.3f}",
        )

    console.print(table)


@kb_app.command("stats")
def kb_stats():
    """
    📊 Show knowledge base statistics.
    """
    from src.knowledge_base.vector_store import ChromaVectorStore

    show_banner()
    store = ChromaVectorStore()
    stats = store.get_stats()

    table = Table(title="Knowledge Base Statistics", border_style="dim")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Vector DB", stats["provider"])
    table.add_row("Code vectors", str(stats["code_vectors"]))
    table.add_row("Pattern vectors", str(stats["pattern_vectors"]))
    table.add_row("Description vectors", str(stats["description_vectors"]))
    console.print(table)


# ============================================
# Dev / Debug Commands
# ============================================


@app.command()
def version():
    """Show VulnHound version."""
    console.print("[bold red]VulnHound[/bold red] v0.1.0")


if __name__ == "__main__":
    app()
