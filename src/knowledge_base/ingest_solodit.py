"""
Solodit / Code4rena Findings Ingestion Pipeline

Ingests audit contest findings from the Web3Bugs dataset (ZhangZhuoSJTU),
which is a curated set of 490+ High/Medium severity findings from Code4rena
contests — the same source Solodit aggregates.

Data source: https://github.com/ZhangZhuoSJTU/Web3Bugs
Each finding has: bug description, severity, category label, Code4rena reference URL.

Note: Solodit's full API is private. This covers the core Code4rena audit
contest findings which are the highest-quality findings Solodit aggregates.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime
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

BUGS_CSV_URL = "https://raw.githubusercontent.com/ZhangZhuoSJTU/Web3Bugs/main/results/bugs.csv"
CONTESTS_CSV_URL = "https://raw.githubusercontent.com/ZhangZhuoSJTU/Web3Bugs/main/results/contests.csv"

# Web3Bugs uses custom labels — map to VulnCategory
# L = Logic, S = Semantic, SE = Semantic Error, SC = Specification Confusion
LABEL_MAP: dict[str, VulnCategory] = {
    "L1": VulnCategory.REENTRANCY,
    "L2": VulnCategory.ACCESS_CONTROL,
    "L3": VulnCategory.INTEGER_OVERFLOW,
    "L4": VulnCategory.INPUT_VALIDATION,
    "L5": VulnCategory.LOGIC_ERROR,
    "L6": VulnCategory.LOGIC_ERROR,
    "L7": VulnCategory.DELEGATE_CALL,
    "L8": VulnCategory.TOKEN_STANDARD,
    "SE-1": VulnCategory.LOGIC_ERROR,
    "SE-2": VulnCategory.PRICE_MANIPULATION,
    "SE-3": VulnCategory.ORACLE_MANIPULATION,
    "SE-4": VulnCategory.INPUT_VALIDATION,
    "SE-5": VulnCategory.LOGIC_ERROR,
    "SE-6": VulnCategory.ACCESS_CONTROL,
    "S1-1": VulnCategory.PRICE_MANIPULATION,
    "S1-2": VulnCategory.FLASH_LOAN,
    "S2": VulnCategory.FRONT_RUNNING,
    "S3": VulnCategory.GOVERNANCE,
    "S4": VulnCategory.DENIAL_OF_SERVICE,
    "S5": VulnCategory.CROSS_CHAIN,
    "S6-1": VulnCategory.LOGIC_ERROR,
    "S6-2": VulnCategory.LOGIC_ERROR,
    "S6-3": VulnCategory.LOGIC_ERROR,
    "S6-4": VulnCategory.LOGIC_ERROR,
    "S6-5": VulnCategory.LOGIC_ERROR,
    "SC": VulnCategory.LOGIC_ERROR,
}

KEYWORD_CATEGORY_MAP: dict[str, VulnCategory] = {
    "reentrancy": VulnCategory.REENTRANCY,
    "re-entrancy": VulnCategory.REENTRANCY,
    "access control": VulnCategory.ACCESS_CONTROL,
    "unauthorized": VulnCategory.ACCESS_CONTROL,
    "overflow": VulnCategory.INTEGER_OVERFLOW,
    "underflow": VulnCategory.INTEGER_OVERFLOW,
    "flash loan": VulnCategory.FLASH_LOAN,
    "flashloan": VulnCategory.FLASH_LOAN,
    "price manip": VulnCategory.PRICE_MANIPULATION,
    "oracle": VulnCategory.ORACLE_MANIPULATION,
    "front.run": VulnCategory.FRONT_RUNNING,
    "sandwich": VulnCategory.FRONT_RUNNING,
    "bridge": VulnCategory.CROSS_CHAIN,
    "cross-chain": VulnCategory.CROSS_CHAIN,
    "dos": VulnCategory.DENIAL_OF_SERVICE,
    "denial of service": VulnCategory.DENIAL_OF_SERVICE,
    "governance": VulnCategory.GOVERNANCE,
    "delegate": VulnCategory.DELEGATE_CALL,
    "storage collision": VulnCategory.STORAGE_COLLISION,
}


def _map_category(label: str, description: str) -> VulnCategory:
    # First try the label map
    cat = LABEL_MAP.get(label)
    if cat:
        return cat
    # Then keyword search on description
    desc_lower = description.lower()
    for keyword, category in KEYWORD_CATEGORY_MAP.items():
        if keyword in desc_lower:
            return category
    return VulnCategory.LOGIC_ERROR


def fetch_csv_data() -> tuple[list[dict], dict[str, str]]:
    """Fetch bugs CSV and contests CSV, return (bugs, contest_id->name map)."""
    console.print("[bold]Fetching Web3Bugs/Code4rena findings...[/bold]")

    # Fetch bugs
    r1 = httpx.get(BUGS_CSV_URL, timeout=20, follow_redirects=True)
    r1.raise_for_status()

    # Fetch contests for protocol name lookup
    r2 = httpx.get(CONTESTS_CSV_URL, timeout=20, follow_redirects=True)
    r2.raise_for_status()

    # Parse contests: Contest ID -> Protocol Name
    contests = {}
    reader = csv.DictReader(io.StringIO(r2.text))
    for row in reader:
        cid = row.get("Contest ID", "").strip()
        name = row.get("Contest Name", row.get("Name", f"Contest-{cid}")).strip()
        if cid:
            contests[cid] = name

    # Parse bugs
    bugs = []
    reader = csv.reader(io.StringIO(r1.text))
    headers = next(reader)  # skip header
    for row in reader:
        if len(row) >= 6:
            bugs.append({
                "contest_id": row[0].strip(),
                "bug_id": row[1].strip(),
                "label": row[2].strip(),
                "difficulty": row[3].strip(),
                "description": row[4].strip().strip('"'),
                "reference": row[5].strip().strip('"'),
                "comment": row[6].strip().strip('"') if len(row) > 6 else "",
            })

    console.print(f"[green]Fetched {len(bugs)} Code4rena findings from {len(contests)} contests[/green]")
    return bugs, contests


def parse_finding(bug: dict, contests: dict[str, str], index: int) -> Optional[ExploitDocument]:
    """Convert a Web3Bugs finding into an ExploitDocument."""
    try:
        contest_id = bug["contest_id"]
        protocol = contests.get(contest_id, f"Contest-{contest_id}")
        description = bug["description"]
        label = bug["label"]
        reference = bug["reference"]
        bug_id = bug["bug_id"]
        severity = "HIGH" if bug_id.startswith("H-") else "MEDIUM"
        category = _map_category(label, description)

        doc = ExploitDocument(
            id=f"C4-{contest_id}-{bug_id.replace('-', '')}-{index}",
            protocol=protocol,
            date=datetime(2023, 1, 1),  # approximate — contest date not in CSV
            chain=Chain.ETHEREUM,  # Code4rena contests are mostly EVM
            loss_usd=0.0,  # audit findings — no real loss
            recovered=False,
            vulnerability=VulnerabilityPattern(
                category=category,
                description=description,
                root_cause=f"Code4rena finding {bug_id}: {description[:200]}",
                affected_functions=[],
                owasp_mapping=None,
            ),
            code_context=CodeContext(
                vulnerable_snippet=f"// Audit finding: {description}\n// Severity: {severity}\n// Label: {label}",
                contract_name=protocol,
            ),
            exploit_mechanism=ExploitMechanism(
                attack_steps=[
                    f"Severity: {severity}",
                    f"Category: {label}",
                    description[:300],
                ],
                poc_reference=reference,
            ),
            source="solodit",
            source_url=reference,
            tags=[category.value, severity.lower(), "code4rena", "audit-finding"],
        )
        return doc
    except Exception as e:
        console.print(f"[red]Error parsing finding {index}: {e}[/red]")
        return None


def ingest_solodit(
    output_dir=None,
    vector_store=None,
    limit: Optional[int] = None,
) -> list[ExploitDocument]:
    """
    Full ingestion pipeline for Solodit/Code4rena findings.

    1. Fetch Web3Bugs CSV (Code4rena H/M findings)
    2. Parse into ExploitDocuments
    3. Embed + store in ChromaDB
    """
    from pathlib import Path
    from src.knowledge_base.embedder import ExploitEmbedder
    from src.knowledge_base.vector_store import ChromaVectorStore
    from src.config import get_settings

    settings = get_settings()
    output_dir = output_dir or (Path(settings.knowledge_base_dir) / "exploits")

    bugs, contests = fetch_csv_data()
    if limit:
        bugs = bugs[:limit]

    documents = []
    for i, bug in enumerate(track(bugs, description="Parsing Code4rena findings...")):
        doc = parse_finding(bug, contests, i)
        if doc:
            documents.append(doc)

    # Save raw JSON
    output_dir.mkdir(parents=True, exist_ok=True)
    for doc in documents:
        path = output_dir / f"{doc.id}.json"
        path.write_text(doc.model_dump_json(indent=2))
    console.print(f"[green]OK Saved {len(documents)} Solodit/C4 documents[/green]")

    # Embed + store
    store = vector_store or ChromaVectorStore()
    embedder = ExploitEmbedder()
    console.print(f"[bold]Embedding {len(documents)} Solodit/C4 findings...[/bold]")
    all_embeddings = embedder.embed_batch(documents)

    for doc, embeddings in track(
        zip(documents, all_embeddings), description="Storing Solodit in ChromaDB...", total=len(documents)
    ):
        store.store_exploit(doc, embeddings)

    stats = store.get_stats()
    console.print("[bold green]OK Solodit ingestion complete![/bold green]")
    console.print(f"  Total description vectors: {stats['description_vectors']}")
    return documents
