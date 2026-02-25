"""
Exploit Embedder

Generates embeddings for ExploitDocuments using sentence-transformers.
No API key required — runs fully locally.

Each exploit gets 3 embeddings for different retrieval strategies:
1. code_embedding      → find exploits with similar vulnerable code
2. pattern_embedding   → find exploits with similar attack patterns
3. description_embedding → semantic search on natural language descriptions
"""

from __future__ import annotations

from rich.console import Console

from src.models import ExploitDocument

console = Console()

# Model choice: all-MiniLM-L6-v2 — small (80MB), fast, great for semantic similarity
EMBEDDING_MODEL = "all-MiniLM-L6-v2"


class ExploitEmbedder:
    """
    Generates 3 embeddings per ExploitDocument using sentence-transformers.
    Model is loaded once and reused across all documents.
    """

    def __init__(self, model_name: str = EMBEDDING_MODEL):
        from sentence_transformers import SentenceTransformer

        console.print(f"[dim]Loading embedding model: {model_name}...[/dim]")
        self.model = SentenceTransformer(model_name)
        self.model_name = model_name
        console.print(f"[dim]Embedding model loaded (dim={self.model.get_sentence_embedding_dimension()})[/dim]")

    def embed_exploit(self, doc: ExploitDocument) -> dict[str, list[float]]:
        """
        Generate 3 embeddings for a single exploit document.

        Returns:
            {
                "code": [...],        # 384-dim vector from vulnerable code snippet
                "pattern": [...],     # 384-dim vector from attack pattern description
                "description": [...], # 384-dim vector from natural language description
            }
        """
        # 1. Code embedding — the actual vulnerable code snippet
        code_text = self._build_code_text(doc)

        # 2. Pattern embedding — structured attack pattern info
        pattern_text = self._build_pattern_text(doc)

        # 3. Description embedding — human-readable description
        description_text = self._build_description_text(doc)

        embeddings = self.model.encode(
            [code_text, pattern_text, description_text],
            show_progress_bar=False,
            normalize_embeddings=True,  # cosine similarity ready
        )

        return {
            "code": embeddings[0].tolist(),
            "pattern": embeddings[1].tolist(),
            "description": embeddings[2].tolist(),
        }

    def embed_batch(
        self, docs: list[ExploitDocument], batch_size: int = 32
    ) -> list[dict[str, list[float]]]:
        """
        Embed a batch of exploit documents efficiently.
        Processes all 3 text types in bulk for speed.
        """
        code_texts = [self._build_code_text(d) for d in docs]
        pattern_texts = [self._build_pattern_text(d) for d in docs]
        description_texts = [self._build_description_text(d) for d in docs]

        console.print(f"[dim]Embedding {len(docs)} documents in batches of {batch_size}...[/dim]")

        code_vecs = self.model.encode(
            code_texts, batch_size=batch_size, show_progress_bar=True, normalize_embeddings=True
        )
        pattern_vecs = self.model.encode(
            pattern_texts, batch_size=batch_size, show_progress_bar=False, normalize_embeddings=True
        )
        desc_vecs = self.model.encode(
            description_texts, batch_size=batch_size, show_progress_bar=False, normalize_embeddings=True
        )

        return [
            {
                "code": code_vecs[i].tolist(),
                "pattern": pattern_vecs[i].tolist(),
                "description": desc_vecs[i].tolist(),
            }
            for i in range(len(docs))
        ]

    def embed_query(self, query: str) -> list[float]:
        """Embed a search query for KB retrieval."""
        vec = self.model.encode(query, normalize_embeddings=True)
        return vec.tolist()

    # ----------------------------------------
    # Text builders — what we actually embed
    # ----------------------------------------

    def _build_code_text(self, doc: ExploitDocument) -> str:
        """Build text for code embedding — focuses on the vulnerable snippet."""
        parts = []
        if doc.code_context.contract_name:
            parts.append(f"Contract: {doc.code_context.contract_name}")
        if doc.code_context.solidity_version:
            parts.append(f"Solidity: {doc.code_context.solidity_version}")
        parts.append(doc.code_context.vulnerable_snippet[:800])
        return "\n".join(parts)

    def _build_pattern_text(self, doc: ExploitDocument) -> str:
        """Build text for pattern embedding — focuses on the attack mechanics."""
        vuln = doc.vulnerability
        mech = doc.exploit_mechanism
        parts = [
            f"Vulnerability: {vuln.category.value}",
            f"Root cause: {vuln.root_cause}",
            f"Description: {vuln.description}",
        ]
        if vuln.affected_functions:
            parts.append(f"Functions: {', '.join(vuln.affected_functions)}")
        if mech.attack_steps:
            steps = " -> ".join(mech.attack_steps[:5])
            parts.append(f"Attack: {steps}")
        return "\n".join(parts)

    def _build_description_text(self, doc: ExploitDocument) -> str:
        """Build text for description embedding — human-readable summary."""
        loss_str = f"${doc.loss_usd:,.0f}" if doc.loss_usd else "unknown amount"
        parts = [
            f"{doc.protocol} exploit on {doc.chain.value}",
            f"Lost {loss_str} due to {doc.vulnerability.category.value}",
            doc.vulnerability.description,
            doc.vulnerability.root_cause,
        ]
        if doc.tags:
            parts.append(f"Tags: {', '.join(doc.tags)}")
        return " | ".join(parts)
