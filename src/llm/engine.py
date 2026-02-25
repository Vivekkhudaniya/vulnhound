"""
VulnHound LLM Engine — Stage 5: Multi-Pass Analysis

Orchestrates three analysis passes against Claude to produce structured
Finding objects from enriched FunctionContext inputs.

Pass B — Function Audit
    One API call per FunctionContext (function source + static findings + KB exploits).
    Uses sonnet. Produces code-level vulnerability findings.

Pass C — Cross-Contract Analysis
    One API call per contract that has external dependencies.
    Uses sonnet. Produces trust-boundary and callback vulnerabilities.

Pass D — Economic Audit
    Single API call covering the whole project summary.
    Uses haiku (cheaper — broad-sweep pattern recognition, no full source).
    Produces economic attack findings (flash loan, oracle, MEV, etc.).

Structured output via tool use
    The `report_finding` tool forces Claude to emit each finding as a structured
    JSON object, eliminating fragile regex/JSON-extraction on free-form text.
    Every tool_use block in the response is converted to a Finding object.

Token tracking
    LLMClient accumulates input + output tokens across all calls.
    After analysis, engine.usage shows the total cost footprint.

Usage
-----
    engine = LLMEngine()
    findings = engine.analyze(function_contexts, scope)
    print(f"Found {len(findings)} vulnerabilities, {engine.usage.total_tokens} tokens")
"""

from __future__ import annotations

import dataclasses
import time
from typing import Optional

import anthropic
from rich.console import Console

from src.config import Settings, get_settings
from src.llm.prompts.templates import (
    REPORT_FINDING_TOOL,
    SYSTEM_PROMPT,
    build_pass_b_prompt,
    build_pass_c_prompt,
    build_pass_d_prompt,
)
from src.models import (
    AnalysisPass,
    ContractInfo,
    Finding,
    FindingSource,
    FunctionContext,
    ProjectScope,
    RetrievedExploit,
    Severity,
    VulnCategory,
)

console = Console()


# ---------------------------------------------------------------------------
# Token usage tracker
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class TokenUsage:
    """Accumulates token consumption across all API calls."""

    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def add(self, usage: object) -> None:
        """Add token counts from an anthropic Usage object (duck-typed)."""
        self.input_tokens += getattr(usage, "input_tokens", 0)
        self.output_tokens += getattr(usage, "output_tokens", 0)

    def __str__(self) -> str:
        return (
            f"input={self.input_tokens:,} "
            f"output={self.output_tokens:,} "
            f"total={self.total_tokens:,}"
        )


# ---------------------------------------------------------------------------
# Finding ID counter
# ---------------------------------------------------------------------------


class _FindingIDCounter:
    """Generates sequential VH-001, VH-002, ... IDs across all passes."""

    def __init__(self, start: int = 1) -> None:
        self._n = start

    def next_id(self) -> str:
        id_ = f"VH-{self._n:03d}"
        self._n += 1
        return id_


# ---------------------------------------------------------------------------
# LLM client wrapper with retry
# ---------------------------------------------------------------------------


class LLMClient:
    """
    Thin wrapper around anthropic.Anthropic that adds:
    - Exponential backoff on RateLimitError and 529 overloaded errors
    - Token usage accumulation into self.usage

    Designed to be injectable for testing (pass a pre-constructed instance
    to LLMEngine instead of having the engine create its own).
    """

    def __init__(
        self,
        api_key: str,
        max_retries: int = 3,
        request_timeout: int = 120,
    ) -> None:
        self._client = anthropic.Anthropic(
            api_key=api_key,
            timeout=float(request_timeout),
        )
        self._max_retries = max_retries
        self.usage = TokenUsage()

    def create(
        self,
        *,
        model: str,
        system: str,
        messages: list[dict],
        tools: list[dict],
        max_tokens: int = 4096,
    ) -> anthropic.types.Message:
        """
        Call messages.create with exponential backoff on rate limits.

        Raises the last exception if all retries are exhausted.
        Accumulates token usage on success.
        """
        last_exc: Exception | None = None

        for attempt in range(self._max_retries):
            try:
                response = self._client.messages.create(
                    model=model,
                    system=system,
                    messages=messages,
                    tools=tools,  # type: ignore[arg-type]
                    max_tokens=max_tokens,
                )
                self.usage.add(response.usage)
                return response

            except anthropic.RateLimitError as exc:
                last_exc = exc
                wait = 2 ** attempt
                console.log(
                    f"[yellow][LLM] Rate limit hit — waiting {wait}s "
                    f"(attempt {attempt + 1}/{self._max_retries})[/yellow]"
                )
                time.sleep(wait)

            except anthropic.APIStatusError as exc:
                if exc.status_code == 529:
                    last_exc = exc
                    wait = 2 ** attempt
                    console.log(
                        f"[yellow][LLM] API overloaded — waiting {wait}s "
                        f"(attempt {attempt + 1}/{self._max_retries})[/yellow]"
                    )
                    time.sleep(wait)
                else:
                    raise  # non-retryable API error

        raise last_exc  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Main LLM engine
# ---------------------------------------------------------------------------


class LLMEngine:
    """
    Orchestrates three LLM analysis passes and assembles Finding objects.

    Parameters
    ----------
    settings:
        Optional Settings override. Defaults to global get_settings().
    client:
        Optional pre-built LLMClient. Pass one in tests to inject mocks.
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        client: Optional[LLMClient] = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._client = client or LLMClient(
            api_key=self._settings.anthropic_api_key,
            max_retries=self._settings.max_retries,
            request_timeout=self._settings.request_timeout,
        )
        self._counter = _FindingIDCounter()

    @property
    def usage(self) -> TokenUsage:
        """Total token usage across all API calls made by this engine."""
        return self._client.usage

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(
        self,
        contexts: list[FunctionContext],
        scope: ProjectScope,
    ) -> list[Finding]:
        """
        Run all three analysis passes and return combined Finding list.

        Passes run sequentially: B → C → D.
        Findings from all passes share a single ID counter (VH-001…VH-N).
        Findings below the configured confidence threshold are excluded before
        being returned (threshold applied per-finding inside _extract_findings).

        Parameters
        ----------
        contexts:
            Enriched FunctionContext list from Stage 4 (retriever output).
        scope:
            ProjectScope from Stage 1 — required for Pass D project summary.

        Returns
        -------
        list[Finding] in Pass B → C → D order within each pass, highest risk first.
        """
        console.rule("[bold cyan]Stage 5: LLM Multi-Pass Analysis[/bold cyan]")

        if not contexts:
            console.log("[yellow][LLM] No function contexts — skipping analysis.[/yellow]")
            return []

        all_findings: list[Finding] = []

        # Pass B: one call per function
        b_findings = self.run_pass_b(contexts)
        all_findings.extend(b_findings)
        console.log(f"  [bold]Pass B[/bold] (function audit):   {len(b_findings)} finding(s)")

        # Pass C: one call per contract with external deps
        c_findings = self.run_pass_c(contexts, scope)
        all_findings.extend(c_findings)
        console.log(f"  [bold]Pass C[/bold] (cross-contract):   {len(c_findings)} finding(s)")

        # Pass D: single call for whole project
        d_findings = self.run_pass_d(contexts, scope)
        all_findings.extend(d_findings)
        console.log(f"  [bold]Pass D[/bold] (economic audit):   {len(d_findings)} finding(s)")

        console.log(f"  [dim]Token usage: {self.usage}[/dim]")
        console.log(
            f"  [bold green]Total findings: {len(all_findings)}[/bold green] "
            f"(CRIT={sum(1 for f in all_findings if f.severity == Severity.CRITICAL)}, "
            f"HIGH={sum(1 for f in all_findings if f.severity == Severity.HIGH)}, "
            f"MED={sum(1 for f in all_findings if f.severity == Severity.MEDIUM)})"
        )

        return all_findings

    # ------------------------------------------------------------------
    # Pass B: per-function audit
    # ------------------------------------------------------------------

    def run_pass_b(self, contexts: list[FunctionContext]) -> list[Finding]:
        """
        Deep code-level audit — one API call per FunctionContext.

        Model: settings.llm_model (sonnet — best code reasoning).
        Source: FindingSource.LLM_FUNCTION_AUDIT
        """
        findings: list[Finding] = []

        for i, ctx in enumerate(contexts, start=1):
            label = f"{ctx.contract.name}.{ctx.function.name}"
            console.log(
                f"  [Pass B {i}/{len(contexts)}] {label} "
                f"(static: {len(ctx.static_findings)}, "
                f"kb: {len(ctx.similar_exploits)})"
            )

            user_prompt = build_pass_b_prompt(
                ctx,
                max_source_chars=self._settings.max_function_tokens,
            )

            try:
                response = self._client.create(
                    model=self._settings.llm_model,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_prompt}],
                    tools=[REPORT_FINDING_TOOL],
                    max_tokens=4096,
                )
            except Exception as exc:
                console.log(f"[yellow]  [Pass B] Failed for {label}: {exc}[/yellow]")
                continue

            new_findings = self._extract_findings(
                response=response,
                source=FindingSource.LLM_FUNCTION_AUDIT,
                analysis_pass=AnalysisPass.FUNCTION_AUDIT,
                contract=ctx.contract.name,
                file_path=ctx.contract.file_path,
                function_name=ctx.function.name,
                similar_exploits=ctx.similar_exploits,
            )
            findings.extend(new_findings)

        return findings

    # ------------------------------------------------------------------
    # Pass C: cross-contract analysis
    # ------------------------------------------------------------------

    def run_pass_c(
        self,
        contexts: list[FunctionContext],
        scope: ProjectScope,
    ) -> list[Finding]:
        """
        Trust-boundary and callback vulnerability analysis.
        One API call per contract that has cross-contract dependencies.
        Contracts with no external calls are skipped entirely.

        Model: settings.llm_model (sonnet).
        Source: FindingSource.LLM_CROSS_CONTRACT
        """
        findings: list[Finding] = []

        # Group contexts by contract
        by_contract: dict[str, list[FunctionContext]] = {}
        for ctx in contexts:
            by_contract.setdefault(ctx.contract.name, []).append(ctx)

        for contract_name, contract_contexts in by_contract.items():
            # Skip contracts with no external deps
            has_external = (
                any(ctx.cross_contract_calls for ctx in contract_contexts)
                or any(ctx.contract.external_calls for ctx in contract_contexts)
            )
            if not has_external:
                continue

            contract = contract_contexts[0].contract
            console.log(f"  [Pass C] {contract_name}")

            user_prompt = build_pass_c_prompt(contract, contract_contexts)

            try:
                response = self._client.create(
                    model=self._settings.llm_model,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_prompt}],
                    tools=[REPORT_FINDING_TOOL],
                    max_tokens=4096,
                )
            except Exception as exc:
                console.log(
                    f"[yellow]  [Pass C] Failed for {contract_name}: {exc}[/yellow]"
                )
                continue

            new_findings = self._extract_findings(
                response=response,
                source=FindingSource.LLM_CROSS_CONTRACT,
                analysis_pass=AnalysisPass.CROSS_CONTRACT,
                contract=contract_name,
                file_path=contract.file_path,
                function_name=None,
                similar_exploits=[],
            )
            findings.extend(new_findings)

        return findings

    # ------------------------------------------------------------------
    # Pass D: economic / DeFi audit
    # ------------------------------------------------------------------

    def run_pass_d(
        self,
        contexts: list[FunctionContext],
        scope: ProjectScope,
    ) -> list[Finding]:
        """
        Project-wide economic attack surface scan.
        Single API call using project summary (not full source).

        Model: settings.llm_model_fast (haiku — cheaper for broad sweep).
        Source: FindingSource.LLM_ECONOMIC
        """
        if not scope.contracts:
            return []

        console.log("  [Pass D] Economic audit (project-wide)")
        user_prompt = build_pass_d_prompt(scope, contexts)

        try:
            response = self._client.create(
                model=self._settings.llm_model_fast,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_prompt}],
                tools=[REPORT_FINDING_TOOL],
                max_tokens=4096,
            )
        except Exception as exc:
            console.log(f"[yellow]  [Pass D] Failed: {exc}[/yellow]")
            return []

        # Economic findings are project-level — attach to the primary contract
        primary = scope.contracts[0]

        return self._extract_findings(
            response=response,
            source=FindingSource.LLM_ECONOMIC,
            analysis_pass=AnalysisPass.ECONOMIC_AUDIT,
            contract=primary.name,
            file_path=primary.file_path,
            function_name=None,
            similar_exploits=[],
        )

    # ------------------------------------------------------------------
    # Tool call → Finding conversion
    # ------------------------------------------------------------------

    def _extract_findings(
        self,
        response: object,
        *,
        source: FindingSource,
        analysis_pass: AnalysisPass,
        contract: str,
        file_path: str,
        function_name: Optional[str],
        similar_exploits: list[RetrievedExploit],
    ) -> list[Finding]:
        """
        Walk response content blocks, convert every `report_finding` tool_use
        block into a Finding object.

        Non-tool-use blocks (text, thinking) are silently ignored.
        Findings below the confidence threshold are discarded.
        Malformed tool calls are skipped with a warning log.
        """
        threshold = self._settings.finding_confidence_threshold
        findings: list[Finding] = []

        content = getattr(response, "content", [])
        for block in content:
            if getattr(block, "type", None) != "tool_use":
                continue
            if getattr(block, "name", None) != "report_finding":
                continue

            args: dict = getattr(block, "input", {})

            confidence = float(args.get("confidence", 0.0))
            if confidence < threshold:
                console.log(
                    f"[dim]    Skipping low-confidence finding "
                    f"({confidence:.2f} < {threshold}): "
                    f"{args.get('title', '?')[:60]}[/dim]"
                )
                continue

            try:
                finding = Finding(
                    id=self._counter.next_id(),
                    title=args["title"],
                    severity=Severity(args["severity"]),
                    category=VulnCategory(args["category"]),
                    confidence=confidence,
                    contract=contract,
                    function=function_name,
                    file_path=file_path,
                    line_start=int(args.get("line_start", 0)),
                    line_end=args.get("line_end"),
                    description=args["description"],
                    impact=args["impact"],
                    exploit_scenario=args["exploit_scenario"],
                    recommendation=args["recommendation"],
                    vulnerable_code=args.get("vulnerable_code"),
                    suggested_fix=args.get("suggested_fix"),
                    source=source,
                    analysis_pass=analysis_pass,
                    similar_exploits=similar_exploits,
                )
                findings.append(finding)
                console.log(
                    f"    [green]+[/green] [{finding.severity.value.upper()}] "
                    f"{finding.title[:70]} (conf={confidence:.2f})"
                )
            except (KeyError, ValueError) as exc:
                console.log(
                    f"[yellow]    Failed to parse tool call: {exc} "
                    f"(title={args.get('title', '?')[:40]})[/yellow]"
                )

        return findings
