"""
Vector Store Abstraction

Provides a unified interface for storing and retrieving exploit
embeddings from ChromaDB (dev) or Pinecone (production).

Each exploit gets 3 embedding vectors:
1. code_embedding   → similarity search on vulnerable code patterns
2. pattern_embedding → similarity search on attack pattern descriptions
3. description_embedding → semantic search on natural language descriptions
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Optional

from rich.console import Console

from src.config import get_settings
from src.models import ExploitDocument, RetrievedExploit

console = Console()


class VectorStore(ABC):
    """Abstract base class for vector stores."""

    @abstractmethod
    def store_exploit(self, doc: ExploitDocument, embeddings: dict[str, list[float]]) -> None:
        """Store an exploit document with its embeddings."""
        ...

    @abstractmethod
    def search_by_code(self, code_embedding: list[float], top_k: int = 5) -> list[RetrievedExploit]:
        """Find exploits with similar vulnerable code patterns."""
        ...

    @abstractmethod
    def search_by_pattern(
        self, pattern_embedding: list[float], top_k: int = 5
    ) -> list[RetrievedExploit]:
        """Find exploits with similar attack patterns."""
        ...

    @abstractmethod
    def search_by_description(
        self, desc_embedding: list[float], top_k: int = 5
    ) -> list[RetrievedExploit]:
        """Semantic search on exploit descriptions."""
        ...

    @abstractmethod
    def get_stats(self) -> dict:
        """Return stats about the vector store."""
        ...


class ChromaVectorStore(VectorStore):
    """
    ChromaDB implementation for local development.

    Uses 3 separate collections for the 3 embedding types.
    """

    def __init__(self, persist_dir: Optional[str] = None):
        import chromadb

        settings = get_settings()
        persist_dir = persist_dir or settings.chromadb_dir

        self.client = chromadb.PersistentClient(path=persist_dir)

        # 3 collections for 3 retrieval strategies
        self.code_collection = self.client.get_or_create_collection(
            name="exploit_code",
            metadata={"description": "Vulnerable code pattern embeddings"},
        )
        self.pattern_collection = self.client.get_or_create_collection(
            name="exploit_patterns",
            metadata={"description": "Attack pattern embeddings"},
        )
        self.description_collection = self.client.get_or_create_collection(
            name="exploit_descriptions",
            metadata={"description": "Natural language description embeddings"},
        )

        console.print(f"[dim]ChromaDB initialized at {persist_dir}[/dim]")

    def store_exploit(self, doc: ExploitDocument, embeddings: dict[str, list[float]]) -> None:
        """Store exploit with 3 embedding types."""
        metadata = {
            "protocol": doc.protocol,
            "chain": doc.chain.value,
            "category": doc.vulnerability.category.value,
            "loss_usd": doc.loss_usd,
            "date": doc.date.isoformat(),
            "source": doc.source,
        }

        # Store in each collection
        if "code" in embeddings:
            self.code_collection.upsert(
                ids=[doc.id],
                embeddings=[embeddings["code"]],
                metadatas=[metadata],
                documents=[doc.code_context.vulnerable_snippet[:1000]],
            )

        if "pattern" in embeddings:
            self.pattern_collection.upsert(
                ids=[doc.id],
                embeddings=[embeddings["pattern"]],
                metadatas=[metadata],
                documents=[
                    f"{doc.vulnerability.category.value}: {doc.vulnerability.description}"
                ],
            )

        if "description" in embeddings:
            self.description_collection.upsert(
                ids=[doc.id],
                embeddings=[embeddings["description"]],
                metadatas=[metadata],
                documents=[doc.vulnerability.description],
            )

    def _results_to_exploits(self, results: dict) -> list[RetrievedExploit]:
        """Convert ChromaDB results to RetrievedExploit objects."""
        exploits = []
        if not results or not results.get("ids") or not results["ids"][0]:
            return exploits

        for i, exploit_id in enumerate(results["ids"][0]):
            meta = results["metadatas"][0][i] if results.get("metadatas") else {}
            distance = results["distances"][0][i] if results.get("distances") else 1.0
            doc_text = results["documents"][0][i] if results.get("documents") else ""

            exploits.append(
                RetrievedExploit(
                    exploit_id=exploit_id,
                    protocol=meta.get("protocol", "Unknown"),
                    similarity_score=max(0, 1 - distance),  # convert distance to similarity
                    category=meta.get("category", "other"),
                    description=doc_text[:500],
                    loss_usd=meta.get("loss_usd", 0),
                    attack_summary=doc_text[:300],
                )
            )

        return exploits

    def search_by_code(self, code_embedding: list[float], top_k: int = 5) -> list[RetrievedExploit]:
        results = self.code_collection.query(
            query_embeddings=[code_embedding],
            n_results=top_k,
        )
        return self._results_to_exploits(results)

    def search_by_pattern(
        self, pattern_embedding: list[float], top_k: int = 5
    ) -> list[RetrievedExploit]:
        results = self.pattern_collection.query(
            query_embeddings=[pattern_embedding],
            n_results=top_k,
        )
        return self._results_to_exploits(results)

    def search_by_description(
        self, desc_embedding: list[float], top_k: int = 5
    ) -> list[RetrievedExploit]:
        results = self.description_collection.query(
            query_embeddings=[desc_embedding],
            n_results=top_k,
        )
        return self._results_to_exploits(results)

    def get_stats(self) -> dict:
        return {
            "provider": "chromadb",
            "code_vectors": self.code_collection.count(),
            "pattern_vectors": self.pattern_collection.count(),
            "description_vectors": self.description_collection.count(),
        }


# ============================================
# Factory
# ============================================


def get_vector_store() -> VectorStore:
    """Create the appropriate vector store based on config."""
    settings = get_settings()

    if settings.vector_db_provider == "pinecone":
        # TODO: Implement PineconeVectorStore for production
        raise NotImplementedError("Pinecone support coming in Phase 5")

    return ChromaVectorStore()
