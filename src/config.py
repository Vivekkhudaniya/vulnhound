"""
VulnHound Configuration

Centralized config that loads from .env and provides
sensible defaults for development.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # === LLM ===
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    llm_model: str = "claude-sonnet-4-20250514"
    llm_model_heavy: str = "claude-opus-4-5-20250929"
    llm_model_fast: str = "claude-haiku-4-5-20251001"

    # === Blockchain RPCs ===
    eth_rpc_url: str = ""
    arb_rpc_url: str = ""
    op_rpc_url: str = ""
    base_rpc_url: str = ""

    # === Block Explorer APIs ===
    etherscan_api_key: str = ""
    arbiscan_api_key: str = ""
    basescan_api_key: str = ""

    # === Vector DB ===
    vector_db_provider: str = "chromadb"  # chromadb | pinecone
    pinecone_api_key: str = ""
    pinecone_index: str = "vulnhound-exploits"
    chromadb_dir: str = "./data/chromadb"

    # === Optional ===
    cohere_api_key: str = ""

    # === Agent Config ===
    max_concurrent_analyses: int = 5
    finding_confidence_threshold: float = 0.7
    max_retries: int = 3
    request_timeout: int = 120

    # === Paths ===
    knowledge_base_dir: str = "./knowledge"
    reports_dir: str = "./reports"

    # === Embedding Config ===
    embedding_model: str = "text-embedding-3-large"
    embedding_dimensions: int = 1536
    retrieval_top_k: int = 5

    # === Analysis Config ===
    max_function_tokens: int = 4000  # max tokens per function context
    max_contract_tokens: int = 16000  # max tokens per contract
    enable_mythril: bool = False  # slow, enable for thorough analysis
    enable_semgrep: bool = True

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    @property
    def knowledge_path(self) -> Path:
        return Path(self.knowledge_base_dir)

    @property
    def chromadb_path(self) -> Path:
        return Path(self.chromadb_dir)

    @property
    def reports_path(self) -> Path:
        return Path(self.reports_dir)

    def get_rpc_url(self, chain: str) -> Optional[str]:
        """Get RPC URL for a given chain."""
        rpc_map = {
            "ethereum": self.eth_rpc_url,
            "arbitrum": self.arb_rpc_url,
            "optimism": self.op_rpc_url,
            "base": self.base_rpc_url,
        }
        return rpc_map.get(chain.lower())


# Singleton
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get or create the global settings instance."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
