"""
VulnHound Core Data Models

These are the foundational schemas that flow through the entire pipeline.
Every stage reads and writes these structures — get these right and
everything else becomes easier.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ============================================
# Enums
# ============================================


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class VulnCategory(str, Enum):
    """Vulnerability categories based on OWASP SC Top 10 + DeFiHackLabs taxonomy."""

    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    LOGIC_ERROR = "logic_error"
    INPUT_VALIDATION = "input_validation"
    PRICE_MANIPULATION = "price_manipulation"
    FLASH_LOAN = "flash_loan"
    FRONT_RUNNING = "front_running"
    ORACLE_MANIPULATION = "oracle_manipulation"
    CROSS_CHAIN = "cross_chain"
    GOVERNANCE = "governance"
    INTEGER_OVERFLOW = "integer_overflow"
    UNCHECKED_EXTERNAL_CALL = "unchecked_external_call"
    DELEGATE_CALL = "delegate_call"
    STORAGE_COLLISION = "storage_collision"
    DENIAL_OF_SERVICE = "denial_of_service"
    TOKEN_STANDARD = "token_standard"
    GAS_OPTIMIZATION = "gas_optimization"
    OTHER = "other"


class Chain(str, Enum):
    ETHEREUM = "ethereum"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    BASE = "base"
    BSC = "bsc"
    POLYGON = "polygon"
    AVALANCHE = "avalanche"
    FANTOM = "fantom"
    SOLANA = "solana"
    MULTI_CHAIN = "multi_chain"
    OTHER = "other"


class AnalysisPass(str, Enum):
    SCOPE_MAPPING = "pass_a_scope"
    FUNCTION_AUDIT = "pass_b_function"
    CROSS_CONTRACT = "pass_c_cross_contract"
    ECONOMIC_AUDIT = "pass_d_economic"
    VALIDATION = "pass_e_validation"
    POC_GENERATION = "pass_f_poc"


class FindingSource(str, Enum):
    SLITHER = "slither"
    ADERYN = "aderyn"
    MYTHRIL = "mythril"
    SEMGREP = "semgrep"
    LLM_FUNCTION_AUDIT = "llm_function_audit"
    LLM_CROSS_CONTRACT = "llm_cross_contract"
    LLM_ECONOMIC = "llm_economic"


# ============================================
# Exploit Knowledge Base Models
# ============================================


class ExploitMechanism(BaseModel):
    """How the exploit was actually executed."""

    attack_steps: list[str] = Field(description="Step-by-step attack flow")
    tx_hash: Optional[str] = None
    attacker_address: Optional[str] = None
    poc_reference: Optional[str] = Field(
        None, description="Path to PoC test file (e.g., DeFiHackLabs reference)"
    )


class VulnerabilityPattern(BaseModel):
    """The vulnerability pattern extracted from a real exploit."""

    category: VulnCategory
    subcategory: Optional[str] = None
    description: str
    root_cause: str
    affected_functions: list[str] = Field(default_factory=list)
    owasp_mapping: Optional[str] = Field(None, description="e.g., SC01:2025")


class CodeContext(BaseModel):
    """Code snippets from the vulnerable contract."""

    vulnerable_snippet: str
    fix_snippet: Optional[str] = None
    contract_name: Optional[str] = None
    solidity_version: Optional[str] = None
    file_path: Optional[str] = None


class ExploitDocument(BaseModel):
    """
    A single historical exploit — the fundamental unit of the Knowledge Base.

    This is what gets embedded and stored in the vector DB. Each exploit
    generates 3 embedding vectors for different retrieval strategies:
    1. code_embedding   → find exploits with similar vulnerable code
    2. pattern_embedding → find exploits with similar attack patterns
    3. description_embedding → semantic search on descriptions
    """

    id: str = Field(description="Unique ID, e.g., HACK-2024-0142")
    protocol: str
    date: datetime
    chain: Chain
    loss_usd: float
    recovered: bool = False

    vulnerability: VulnerabilityPattern
    code_context: CodeContext
    exploit_mechanism: ExploitMechanism

    # Data source tracking
    source: str = Field(description="e.g., 'defihacklabs', 'solodit', 'rekt'")
    source_url: Optional[str] = None

    # Tags for filtering
    tags: list[str] = Field(default_factory=list)


# ============================================
# Audit Pipeline Models
# ============================================


class ContractInfo(BaseModel):
    """Metadata about a parsed contract."""

    name: str
    file_path: str
    solidity_version: Optional[str] = None
    is_proxy: bool = False
    proxy_type: Optional[str] = None  # UUPS, Transparent, Diamond
    inherits_from: list[str] = Field(default_factory=list)
    external_calls: list[str] = Field(default_factory=list)
    loc: int = Field(0, description="Lines of code")


class FunctionInfo(BaseModel):
    """Metadata about a contract function."""

    name: str
    contract: str
    visibility: str  # public, external, internal, private
    modifiers: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    return_types: list[str] = Field(default_factory=list)
    state_mutability: Optional[str] = None  # view, pure, payable, nonpayable
    source_code: str = ""
    start_line: int = 0
    end_line: int = 0


class ProjectScope(BaseModel):
    """Output of Stage 1: The full picture of the project being audited."""

    repo_url: Optional[str] = None
    repo_path: str
    contracts: list[ContractInfo] = Field(default_factory=list)
    total_loc: int = 0
    framework: Optional[str] = None  # foundry, hardhat, truffle
    compiler_version: Optional[str] = None
    dependency_graph: dict[str, list[str]] = Field(
        default_factory=dict, description="contract_name → [called_contracts]"
    )


class StaticAnalysisFinding(BaseModel):
    """Output from a static analysis tool (Slither, Aderyn, etc.)."""

    tool: FindingSource
    detector_name: str
    severity: Severity
    confidence: str  # high, medium, low
    description: str
    contract: str
    function: Optional[str] = None
    file_path: str
    line_start: int
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None


class RetrievedExploit(BaseModel):
    """An exploit retrieved from the KB that's similar to current code."""

    exploit_id: str
    protocol: str
    similarity_score: float
    category: VulnCategory
    description: str
    loss_usd: float
    attack_summary: str
    code_snippet: Optional[str] = None


class FunctionContext(BaseModel):
    """
    The enriched context package for a single function.
    This is what gets fed to the LLM for analysis.

    function code + static analysis flags + similar historical exploits
    """

    function: FunctionInfo
    contract: ContractInfo
    static_findings: list[StaticAnalysisFinding] = Field(default_factory=list)
    similar_exploits: list[RetrievedExploit] = Field(default_factory=list)
    cross_contract_calls: list[str] = Field(
        default_factory=list, description="Functions this function calls in other contracts"
    )


class Finding(BaseModel):
    """
    A vulnerability finding — the primary output of VulnHound.

    Each finding goes through:
    1. Discovery (by static analysis or LLM)
    2. Validation (dedup, false positive check, reachability)
    3. PoC generation (Foundry test)
    4. Report inclusion
    """

    id: str = Field(description="Finding ID, e.g., VH-001")
    title: str
    severity: Severity
    category: VulnCategory
    confidence: float = Field(ge=0.0, le=1.0, description="0.0 to 1.0")

    # Location
    contract: str
    function: Optional[str] = None
    file_path: str
    line_start: int
    line_end: Optional[int] = None

    # Description
    description: str
    impact: str
    exploit_scenario: str
    recommendation: str

    # Code
    vulnerable_code: Optional[str] = None
    suggested_fix: Optional[str] = None

    # Source & validation
    source: FindingSource
    analysis_pass: AnalysisPass
    validated: bool = False
    false_positive: bool = False

    # PoC
    poc_test_code: Optional[str] = None
    poc_test_passed: Optional[bool] = None
    poc_trace: Optional[str] = None

    # Historical reference
    similar_exploits: list[RetrievedExploit] = Field(default_factory=list)

    # Metadata
    created_at: datetime = Field(default_factory=datetime.now)


class AuditReport(BaseModel):
    """The final audit report — output of the entire pipeline."""

    id: str
    repo_url: Optional[str] = None
    scope: ProjectScope
    findings: list[Finding] = Field(default_factory=list)

    # Stats
    total_contracts: int = 0
    total_loc: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    informational_count: int = 0

    # Metadata
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    llm_model: str = ""
    agent_version: str = "0.1.0"

    def compute_stats(self) -> None:
        """Recompute finding stats."""
        self.total_findings = len(self.findings)
        self.critical_count = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        self.high_count = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        self.medium_count = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        self.low_count = sum(1 for f in self.findings if f.severity == Severity.LOW)
        self.informational_count = sum(
            1 for f in self.findings if f.severity == Severity.INFORMATIONAL
        )
