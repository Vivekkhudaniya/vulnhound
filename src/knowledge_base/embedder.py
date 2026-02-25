"""
Exploit Embedder

Generates embeddings for ExploitDocuments using nomic-embed-text-v1.
- Code-aware: trained on 650M+ text+code pairs
- 768 dimensions (vs 384 for MiniLM) — higher fidelity
- Requires task prefixes: search_document: / search_query:
- No API key — runs fully locally

Each exploit gets 3 embeddings for different retrieval strategies:
1. code_embedding      → find exploits with similar vulnerable code
2. pattern_embedding   → find exploits with similar attack patterns
3. description_embedding → semantic search on natural language descriptions
"""

from __future__ import annotations

from rich.console import Console

from src.models import ExploitDocument

console = Console()

# nomic-embed-text-v1: 768-dim, code+text aware, requires trust_remote_code=True
# Task prefixes are required for best quality:
#   "search_document: " → when indexing documents
#   "search_query: "    → when embedding search queries
EMBEDDING_MODEL = "nomic-ai/nomic-embed-text-v1"
EMBEDDING_DIM = 768


class ExploitEmbedder:
    """
    Generates 3 embeddings per ExploitDocument using nomic-embed-text-v1.
    Model is loaded once and reused across all documents.
    """

    def __init__(self, model_name: str = EMBEDDING_MODEL):
        from sentence_transformers import SentenceTransformer

        console.print(f"[dim]Loading embedding model: {model_name}...[/dim]")
        self.model = SentenceTransformer(model_name, trust_remote_code=True)
        self.model_name = model_name
        dim = self.model.get_sentence_embedding_dimension()
        console.print(f"[dim]Embedding model loaded (dim={dim})[/dim]")

    def embed_exploit(self, doc: ExploitDocument) -> dict[str, list[float]]:
        """
        Generate 3 embeddings for a single exploit document.

        Returns:
            {
                "code": [...],        # 768-dim vector from vulnerable code snippet
                "pattern": [...],     # 768-dim vector from attack pattern description
                "description": [...], # 768-dim vector from natural language description
            }
        """
        code_text = "search_document: " + self._build_code_text(doc)
        pattern_text = "search_document: " + self._build_pattern_text(doc)
        description_text = "search_document: " + self._build_description_text(doc)

        embeddings = self.model.encode(
            [code_text, pattern_text, description_text],
            show_progress_bar=False,
            normalize_embeddings=True,
        )

        return {
            "code": embeddings[0].tolist(),
            "pattern": embeddings[1].tolist(),
            "description": embeddings[2].tolist(),
        }

    def embed_batch(
        self, docs: list[ExploitDocument], batch_size: int = 32
    ) -> list[dict[str, list[float]]]:
        """Embed a batch of exploit documents efficiently."""
        code_texts    = ["search_document: " + self._build_code_text(d) for d in docs]
        pattern_texts = ["search_document: " + self._build_pattern_text(d) for d in docs]
        desc_texts    = ["search_document: " + self._build_description_text(d) for d in docs]

        console.print(f"[dim]Embedding {len(docs)} documents in batches of {batch_size}...[/dim]")

        code_vecs = self.model.encode(
            code_texts, batch_size=batch_size, show_progress_bar=True, normalize_embeddings=True
        )
        pattern_vecs = self.model.encode(
            pattern_texts, batch_size=batch_size, show_progress_bar=False, normalize_embeddings=True
        )
        desc_vecs = self.model.encode(
            desc_texts, batch_size=batch_size, show_progress_bar=False, normalize_embeddings=True
        )

        return [
            {
                "code":        code_vecs[i].tolist(),
                "pattern":     pattern_vecs[i].tolist(),
                "description": desc_vecs[i].tolist(),
            }
            for i in range(len(docs))
        ]

    def embed_query(self, query: str) -> list[float]:
        """Embed a search query for KB retrieval. Uses search_query: prefix."""
        vec = self.model.encode(
            "search_query: " + query,
            normalize_embeddings=True,
        )
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
