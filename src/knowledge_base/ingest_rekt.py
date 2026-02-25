"""
Rekt News Ingestion Pipeline (via DefiLlama Hacks API)

Fetches 460+ DeFi hack incidents from DefiLlama's public hacks API.
Each entry includes protocol name, chain, loss amount, technique,
and a link to the original Rekt News post-mortem.

Data source: https://api.llama.fi/hacks
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import httpx
from rich.console import Console
from rich.progress import track

from src.models import (
    Chain,
    CodeContext,
    ExploitDocument,
    ExploitMechanism,
    VulnCategory,
    VulnerabilityPattern,
)

console = Console()

API_URL = "https://api.llama.fi/hacks"

# Map DefiLlama classification strings to VulnCategory
CLASSIFICATION_MAP: dict[str, VulnCategory] = {
    "Protocol Logic": VulnCategory.LOGIC_ERROR,
    "Access Control": VulnCategory.ACCESS_CONTROL,
    "Price Manipulation": VulnCategory.PRICE_MANIPULATION,
    "Flash Loan Attack": VulnCategory.FLASH_LOAN,
    "Reentrancy": VulnCategory.REENTRANCY,
    "Oracle Manipulation": VulnCategory.ORACLE_MANIPULATION,
    "Bridge": VulnCategory.CROSS_CHAIN,
    "Cross-Chain": VulnCategory.CROSS_CHAIN,
    "Input Validation": VulnCategory.INPUT_VALIDATION,
    "Integer Overflow": VulnCategory.INTEGER_OVERFLOW,
    "Governance": VulnCategory.GOVERNANCE,
    "Rugpull": VulnCategory.ACCESS_CONTROL,
}

CHAIN_MAP: dict[str, Chain] = {
    "Ethereum": Chain.ETHEREUM,
    "BSC": Chain.BSC,
    "Arbitrum": Chain.ARBITRUM,
    "Optimism": Chain.OPTIMISM,
    "Base": Chain.BASE,
    "Polygon": Chain.POLYGON,
    "Avalanche": Chain.AVALANCHE,
    "Fantom": Chain.FANTOM,
    "Solana": Chain.SOLANA,
}


def _map_chain(chains) -> Chain:
    if not chains or not isinstance(chains, list):
        return Chain.ETHEREUM
    for c in chains:
        if isinstance(c, str) and c in CHAIN_MAP:
            return CHAIN_MAP[c]
    return Chain.OTHER


def _safe_id(protocol: str, date_str: str, index: int) -> str:
    """Create a filesystem-safe ID from protocol name."""
    import re
    safe = re.sub(r'[^\w\-]', '_', protocol.strip())[:30]
    return f"REKT-{date_str}-{safe}-{index}"


def _map_category(classification: str, technique: str) -> VulnCategory:
    combined = f"{classification} {technique}".lower()

    if "reentrancy" in combined:
        return VulnCategory.REENTRANCY
    if "flash loan" in combined or "flashloan" in combined:
        return VulnCategory.FLASH_LOAN
    if "oracle" in combined or "price manip" in combined:
        return VulnCategory.ORACLE_MANIPULATION
    if "bridge" in combined or "cross-chain" in combined or "cross chain" in combined:
        return VulnCategory.CROSS_CHAIN
    if "access control" in combined or "privilege" in combined or "unauthorized" in combined:
        return VulnCategory.ACCESS_CONTROL
    if "governance" in combined:
        return VulnCategory.GOVERNANCE
    if "overflow" in combined or "underflow" in combined:
        return VulnCategory.INTEGER_OVERFLOW

    return CLASSIFICATION_MAP.get(classification, VulnCategory.LOGIC_ERROR)


def fetch_rekt_data() -> list[dict]:
    """Fetch all hack incidents from DefiLlama hacks API."""
    console.print(f"[bold]Fetching Rekt/DefiLlama hacks from {API_URL}...[/bold]")
    try:
        r = httpx.get(API_URL, timeout=30, follow_redirects=True)
        r.raise_for_status()
        data = r.json()
        console.print(f"[green]Fetched {len(data)} hack incidents[/green]")
        return data
    except Exception as e:
        console.print(f"[red]Failed to fetch Rekt data: {e}[/red]")
        return []


def parse_rekt_entry(entry: dict, index: int) -> Optional[ExploitDocument]:
    """Convert a DefiLlama hack entry into an ExploitDocument."""
    try:
        protocol = (entry.get("name") or "Unknown").strip().replace("\n", " ")
        timestamp = entry.get("date", 0)
        date = datetime.fromtimestamp(timestamp, tz=timezone.utc) if timestamp else datetime(2024, 1, 1)
        chains = entry.get("chain") or []
        chain = _map_chain(chains)
        loss_usd = float(entry.get("amount") or 0)
        returned = entry.get("returnedFunds") or 0
        recovered = returned > 0
        classification = (entry.get("classification") or "Protocol Logic").strip()
        technique = (entry.get("technique") or "").strip()
        source_url = (entry.get("source") or "").strip()
        category = _map_category(classification, technique)
        chains_str = [c for c in chains if isinstance(c, str)]

        doc = ExploitDocument(
            id=_safe_id(protocol, date.strftime('%Y%m%d'), index),
            protocol=protocol,
            date=date,
            chain=chain,
            loss_usd=loss_usd,
            recovered=recovered,
            vulnerability=VulnerabilityPattern(
                category=category,
                description=f"{technique}" if technique else f"{classification} exploit",
                root_cause=f"{classification}: {technique}",
                affected_functions=[],
            ),
            code_context=CodeContext(
                vulnerable_snippet=f"// {protocol} exploit\n// Technique: {technique}\n// Classification: {classification}",
                contract_name=protocol,
            ),
            exploit_mechanism=ExploitMechanism(
                attack_steps=[
                    f"Exploit type: {classification}",
                    f"Technique: {technique}",
                    f"Chain(s): {', '.join(chains_str)}",
                    f"Loss: ${loss_usd:,.0f}",
                ],
            ),
            source="rekt",
            source_url=source_url,
            tags=[category.value, chain.value, "rekt"]
            + (["bridge"] if entry.get("bridgeHack") else [])
            + chains_str,
        )
        return doc
    except Exception as e:
        console.print(f"[red]Error parsing entry {index}: {e}[/red]")
        return None


def ingest_rekt(
    output_dir=None,
    vector_store=None,
    limit: Optional[int] = None,
) -> list[ExploitDocument]:
    """
    Full ingestion pipeline for Rekt/DefiLlama hacks.

    1. Fetch from DefiLlama API
    2. Parse into ExploitDocuments
    3. Embed + store in ChromaDB
    """
    from pathlib import Path
    from src.knowledge_base.embedder import ExploitEmbedder
    from src.knowledge_base.vector_store import ChromaVectorStore
    from src.config import get_settings

    settings = get_settings()
    output_dir = output_dir or (Path(settings.knowledge_base_dir) / "exploits")

    raw = fetch_rekt_data()
    if limit:
        raw = raw[:limit]

    documents = []
    for i, entry in enumerate(track(raw, description="Parsing Rekt entries...")):
        doc = parse_rekt_entry(entry, i)
        if doc:
            documents.append(doc)

    # Save raw JSON
    output_dir.mkdir(parents=True, exist_ok=True)
    for doc in documents:
        path = output_dir / f"{doc.id}.json"
        path.write_text(doc.model_dump_json(indent=2))
    console.print(f"[green]OK Saved {len(documents)} Rekt documents[/green]")

    # Embed + store
    store = vector_store or ChromaVectorStore()
    embedder = ExploitEmbedder()
    console.print(f"[bold]Embedding {len(documents)} Rekt exploits...[/bold]")
    all_embeddings = embedder.embed_batch(documents)

    for doc, embeddings in track(
        zip(documents, all_embeddings), description="Storing Rekt in ChromaDB...", total=len(documents)
    ):
        store.store_exploit(doc, embeddings)

    stats = store.get_stats()
    console.print("[bold green]OK Rekt ingestion complete![/bold green]")
    console.print(f"  Total description vectors: {stats['description_vectors']}")
    return documents
