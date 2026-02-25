"""
Tests for src/llm/engine.py and src/llm/prompts/templates.py

All Anthropic API calls are mocked — no API key needed.

Run with: pytest tests/unit/test_llm_engine.py -v
"""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

import anthropic

from src.config import get_settings
from src.llm.engine import (
    LLMClient,
    LLMEngine,
    TokenUsage,
    _FindingIDCounter,
)
from src.llm.prompts.templates import (
    build_pass_b_prompt,
    build_pass_c_prompt,
    build_pass_d_prompt,
    format_similar_exploits,
    format_static_findings,
    truncate_source,
)
from src.models import (
    AnalysisPass,
    ContractInfo,
    FindingSource,
    FunctionContext,
    FunctionInfo,
    ProjectScope,
    RetrievedExploit,
    Severity,
    StaticAnalysisFinding,
    VulnCategory,
)


# ---------------------------------------------------------------------------
# Test fixtures / factories
# ---------------------------------------------------------------------------


def _make_function(
    name: str = "withdraw",
    visibility: str = "external",
    mutability: str = "nonpayable",
    source: str = "function withdraw(uint256 amount) external {\n    token.transfer(msg.sender, amount);\n}",
    start_line: int = 10,
) -> FunctionInfo:
    return FunctionInfo(
        name=name,
        contract="Vault",
        visibility=visibility,
        state_mutability=mutability,
        source_code=source,
        start_line=start_line,
        parameters=["uint256 amount"],
    )


def _make_contract(
    name: str = "Vault",
    external_calls: list | None = None,
    is_proxy: bool = False,
) -> ContractInfo:
    return ContractInfo(
        name=name,
        file_path="contracts/Vault.sol",
        external_calls=external_calls or ["erc20_transfer"],
        is_proxy=is_proxy,
        loc=200,
    )


def _make_finding_static(
    detector: str = "reentrancy-eth",
    severity: Severity = Severity.HIGH,
    fn: str = "withdraw",
) -> StaticAnalysisFinding:
    return StaticAnalysisFinding(
        tool=FindingSource.SLITHER,
        detector_name=detector,
        severity=severity,
        confidence="high",
        description=f"{detector} in {fn}",
        contract="Vault",
        function=fn,
        file_path="contracts/Vault.sol",
        line_start=12,
    )


def _make_exploit(exploit_id: str = "HACK-001", score: float = 0.85) -> RetrievedExploit:
    return RetrievedExploit(
        exploit_id=exploit_id,
        protocol="TestDeFi",
        similarity_score=score,
        category=VulnCategory.REENTRANCY,
        description="Classic reentrancy exploit via withdraw()",
        loss_usd=1_000_000,
        attack_summary="Flash loan + reentrancy in withdraw drains vault",
    )


def _make_context(
    fn_name: str = "withdraw",
    cross_calls: list | None = None,
    exploits: list | None = None,
    findings: list | None = None,
) -> FunctionContext:
    return FunctionContext(
        function=_make_function(name=fn_name),
        contract=_make_contract(),
        static_findings=findings or [_make_finding_static()],
        cross_contract_calls=cross_calls or ["Token"],
        similar_exploits=exploits or [_make_exploit()],
    )


def _make_scope(contracts: list | None = None) -> ProjectScope:
    return ProjectScope(
        repo_path="./contracts",
        contracts=contracts or [_make_contract()],
        total_loc=500,
        dependency_graph={"Vault": ["Token"]},
    )


def _make_tool_call(
    title: str = "Reentrancy in withdraw()",
    severity: str = "high",
    category: str = "reentrancy",
    confidence: float = 0.9,
    line_start: int = 12,
) -> dict:
    """Build a valid report_finding tool call input dict."""
    return {
        "title": title,
        "severity": severity,
        "category": category,
        "confidence": confidence,
        "description": "The withdraw() function is vulnerable to reentrancy.",
        "impact": "Attacker can drain all ETH from the contract.",
        "exploit_scenario": (
            "1. Attacker calls withdraw(). "
            "2. In fallback, re-enters withdraw() before balance update. "
            "3. Repeats until contract is drained."
        ),
        "recommendation": "Apply CEI pattern or use ReentrancyGuard.",
        "line_start": line_start,
    }


def _make_mock_response(tool_calls: list[dict]) -> MagicMock:
    """Build a mock anthropic.types.Message with given tool_use blocks."""
    response = MagicMock()
    response.usage = MagicMock()
    response.usage.input_tokens = 500
    response.usage.output_tokens = 200

    content_blocks = []
    for tc in tool_calls:
        block = MagicMock()
        block.type = "tool_use"
        block.name = "report_finding"
        block.input = tc
        content_blocks.append(block)

    response.content = content_blocks
    return response


def _make_empty_response() -> MagicMock:
    """Mock response with no tool calls (no findings)."""
    return _make_mock_response([])


def _make_engine(mock_responses: list | None = None) -> tuple[LLMEngine, MagicMock]:
    """
    Build an LLMEngine with a mock LLMClient.
    mock_responses: side_effect list for client.create().
    """
    mock_client = MagicMock(spec=LLMClient)
    mock_client.usage = TokenUsage()

    if mock_responses is not None:
        mock_client.create.side_effect = mock_responses
    else:
        mock_client.create.return_value = _make_empty_response()

    engine = LLMEngine.__new__(LLMEngine)
    engine._settings = get_settings()
    engine._client = mock_client
    engine._counter = _FindingIDCounter()
    return engine, mock_client


# ===========================================================================
# Group 1 — TokenUsage
# ===========================================================================


def test_token_usage_initial_zero():
    u = TokenUsage()
    assert u.input_tokens == 0
    assert u.output_tokens == 0
    assert u.total_tokens == 0


def test_token_usage_add():
    u = TokenUsage()
    mock_usage = MagicMock()
    mock_usage.input_tokens = 300
    mock_usage.output_tokens = 150
    u.add(mock_usage)
    assert u.input_tokens == 300
    assert u.output_tokens == 150
    assert u.total_tokens == 450


def test_token_usage_accumulates_multiple_adds():
    u = TokenUsage()
    for _ in range(3):
        m = MagicMock()
        m.input_tokens = 100
        m.output_tokens = 50
        u.add(m)
    assert u.input_tokens == 300
    assert u.output_tokens == 150


def test_token_usage_str():
    u = TokenUsage(input_tokens=1000, output_tokens=500)
    s = str(u)
    assert "1,000" in s
    assert "500" in s


# ===========================================================================
# Group 2 — _FindingIDCounter
# ===========================================================================


def test_finding_id_counter_starts_at_001():
    c = _FindingIDCounter()
    assert c.next_id() == "VH-001"


def test_finding_id_counter_increments():
    c = _FindingIDCounter()
    ids = [c.next_id() for _ in range(5)]
    assert ids == ["VH-001", "VH-002", "VH-003", "VH-004", "VH-005"]


def test_finding_id_counter_pads_to_three_digits():
    c = _FindingIDCounter(start=9)
    assert c.next_id() == "VH-009"
    assert c.next_id() == "VH-010"


def test_finding_id_counter_custom_start():
    c = _FindingIDCounter(start=42)
    assert c.next_id() == "VH-042"


# ===========================================================================
# Group 3 — LLMClient retry logic
# ===========================================================================


def _build_real_llm_client() -> LLMClient:
    """Build an LLMClient with a dummy key (not used in tests)."""
    with patch("anthropic.Anthropic"):
        return LLMClient(api_key="sk-test", max_retries=3, request_timeout=30)


def test_llm_client_retries_on_rate_limit():
    client = _build_real_llm_client()

    # First two calls raise RateLimitError, third succeeds
    good_response = MagicMock()
    good_response.usage = MagicMock()
    good_response.usage.input_tokens = 100
    good_response.usage.output_tokens = 50

    mock_request = MagicMock()
    client._client.messages.create.side_effect = [
        anthropic.RateLimitError("rate limit", response=mock_request, body={}),
        anthropic.RateLimitError("rate limit", response=mock_request, body={}),
        good_response,
    ]

    with patch("time.sleep"):  # don't actually sleep in tests
        result = client.create(
            model="claude-test",
            system="sys",
            messages=[{"role": "user", "content": "test"}],
            tools=[],
        )

    assert client._client.messages.create.call_count == 3
    assert result is good_response


def test_llm_client_raises_after_max_retries():
    client = _build_real_llm_client()
    client._max_retries = 2

    mock_request = MagicMock()
    client._client.messages.create.side_effect = [
        anthropic.RateLimitError("rate limit", response=mock_request, body={}),
        anthropic.RateLimitError("rate limit", response=mock_request, body={}),
    ]

    with patch("time.sleep"):
        with pytest.raises(anthropic.RateLimitError):
            client.create(
                model="claude-test",
                system="sys",
                messages=[{"role": "user", "content": "test"}],
                tools=[],
            )


def test_llm_client_does_not_retry_non_rate_limit_error():
    client = _build_real_llm_client()

    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.headers = {}
    client._client.messages.create.side_effect = anthropic.BadRequestError(
        "bad request", response=mock_resp, body={}
    )

    with pytest.raises(anthropic.BadRequestError):
        client.create(
            model="claude-test",
            system="sys",
            messages=[{"role": "user", "content": "test"}],
            tools=[],
        )

    # Should only be called once (no retry)
    assert client._client.messages.create.call_count == 1


def test_llm_client_accumulates_token_usage():
    client = _build_real_llm_client()

    def make_response(inp: int, out: int) -> MagicMock:
        r = MagicMock()
        r.usage = MagicMock()
        r.usage.input_tokens = inp
        r.usage.output_tokens = out
        return r

    client._client.messages.create.side_effect = [
        make_response(300, 100),
        make_response(200, 80),
    ]

    for _ in range(2):
        client.create(
            model="claude-test",
            system="sys",
            messages=[{"role": "user", "content": "test"}],
            tools=[],
        )

    assert client.usage.input_tokens == 500
    assert client.usage.output_tokens == 180


# ===========================================================================
# Group 4 — _extract_findings
# ===========================================================================


def test_extract_findings_parses_valid_tool_call():
    engine, _ = _make_engine()
    response = _make_mock_response([_make_tool_call()])

    findings = engine._extract_findings(
        response=response,
        source=FindingSource.LLM_FUNCTION_AUDIT,
        analysis_pass=AnalysisPass.FUNCTION_AUDIT,
        contract="Vault",
        file_path="contracts/Vault.sol",
        function_name="withdraw",
        similar_exploits=[],
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.id == "VH-001"
    assert f.title == "Reentrancy in withdraw()"
    assert f.severity == Severity.HIGH
    assert f.category == VulnCategory.REENTRANCY
    assert f.confidence == 0.9
    assert f.source == FindingSource.LLM_FUNCTION_AUDIT
    assert f.analysis_pass == AnalysisPass.FUNCTION_AUDIT
    assert f.contract == "Vault"
    assert f.function == "withdraw"


def test_extract_findings_skips_low_confidence():
    engine, _ = _make_engine()
    engine._settings = get_settings()
    low_conf = _make_tool_call(confidence=0.3)  # below default threshold 0.7
    response = _make_mock_response([low_conf])

    findings = engine._extract_findings(
        response=response,
        source=FindingSource.LLM_FUNCTION_AUDIT,
        analysis_pass=AnalysisPass.FUNCTION_AUDIT,
        contract="Vault",
        file_path="contracts/Vault.sol",
        function_name="withdraw",
        similar_exploits=[],
    )

    assert findings == []


def test_extract_findings_multiple_tool_calls():
    engine, _ = _make_engine()
    calls = [
        _make_tool_call(title="Reentrancy in withdraw()"),
        _make_tool_call(title="Missing access control on setOwner()", category="access_control"),
    ]
    response = _make_mock_response(calls)

    findings = engine._extract_findings(
        response=response,
        source=FindingSource.LLM_FUNCTION_AUDIT,
        analysis_pass=AnalysisPass.FUNCTION_AUDIT,
        contract="Vault",
        file_path="contracts/Vault.sol",
        function_name="withdraw",
        similar_exploits=[],
    )

    assert len(findings) == 2
    assert findings[0].id == "VH-001"
    assert findings[1].id == "VH-002"
    assert findings[1].category == VulnCategory.ACCESS_CONTROL


def test_extract_findings_ignores_text_blocks():
    engine, _ = _make_engine()

    text_block = MagicMock()
    text_block.type = "text"
    text_block.text = "Here is my analysis..."

    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.name = "report_finding"
    tool_block.input = _make_tool_call()

    response = MagicMock()
    response.usage = MagicMock()
    response.usage.input_tokens = 100
    response.usage.output_tokens = 50
    response.content = [text_block, tool_block]

    findings = engine._extract_findings(
        response=response,
        source=FindingSource.LLM_FUNCTION_AUDIT,
        analysis_pass=AnalysisPass.FUNCTION_AUDIT,
        contract="Vault",
        file_path="contracts/Vault.sol",
        function_name="withdraw",
        similar_exploits=[],
    )

    assert len(findings) == 1


def test_extract_findings_skips_invalid_severity():
    engine, _ = _make_engine()
    bad_call = _make_tool_call()
    bad_call["severity"] = "extreme"  # not a valid Severity value

    response = _make_mock_response([bad_call])

    # Should not raise, should skip the malformed finding
    findings = engine._extract_findings(
        response=response,
        source=FindingSource.LLM_FUNCTION_AUDIT,
        analysis_pass=AnalysisPass.FUNCTION_AUDIT,
        contract="Vault",
        file_path="contracts/Vault.sol",
        function_name="withdraw",
        similar_exploits=[],
    )

    assert findings == []


def test_extract_findings_skips_invalid_category():
    engine, _ = _make_engine()
    bad_call = _make_tool_call()
    bad_call["category"] = "magic_vulnerability"  # not a valid VulnCategory

    response = _make_mock_response([bad_call])

    findings = engine._extract_findings(
        response=response,
        source=FindingSource.LLM_FUNCTION_AUDIT,
        analysis_pass=AnalysisPass.FUNCTION_AUDIT,
        contract="Vault",
        file_path="contracts/Vault.sol",
        function_name="withdraw",
        similar_exploits=[],
    )

    assert findings == []


def test_extract_findings_attaches_similar_exploits():
    engine, _ = _make_engine()
    exploits = [_make_exploit("HACK-001"), _make_exploit("HACK-002")]
    response = _make_mock_response([_make_tool_call()])

    findings = engine._extract_findings(
        response=response,
        source=FindingSource.LLM_FUNCTION_AUDIT,
        analysis_pass=AnalysisPass.FUNCTION_AUDIT,
        contract="Vault",
        file_path="contracts/Vault.sol",
        function_name="withdraw",
        similar_exploits=exploits,
    )

    assert len(findings[0].similar_exploits) == 2


# ===========================================================================
# Group 5 — run_pass_b
# ===========================================================================


def test_run_pass_b_calls_api_once_per_context():
    contexts = [_make_context("withdraw"), _make_context("deposit"), _make_context("mint")]
    engine, mock_client = _make_engine([_make_empty_response()] * 3)

    engine.run_pass_b(contexts)

    assert mock_client.create.call_count == 3


def test_run_pass_b_uses_sonnet_model():
    ctx = _make_context()
    engine, mock_client = _make_engine([_make_empty_response()])

    engine.run_pass_b([ctx])

    model_used = mock_client.create.call_args.kwargs["model"]
    assert model_used == engine._settings.llm_model


def test_run_pass_b_assigns_correct_source():
    ctx = _make_context()
    engine, mock_client = _make_engine([_make_mock_response([_make_tool_call()])])

    findings = engine.run_pass_b([ctx])

    assert all(f.source == FindingSource.LLM_FUNCTION_AUDIT for f in findings)


def test_run_pass_b_continues_on_api_error():
    """If Pass B fails for one context, remaining contexts are still processed."""
    contexts = [_make_context("withdraw"), _make_context("deposit")]
    engine, mock_client = _make_engine()

    mock_client.create.side_effect = [
        RuntimeError("Network error"),
        _make_mock_response([_make_tool_call(title="Finding in deposit()")]),
    ]

    findings = engine.run_pass_b(contexts)

    # First context errored — second still returned a finding
    assert len(findings) == 1
    assert "deposit" in findings[0].title


def test_run_pass_b_empty_contexts():
    engine, mock_client = _make_engine()
    findings = engine.run_pass_b([])
    assert findings == []
    mock_client.create.assert_not_called()


def test_run_pass_b_ids_are_sequential():
    contexts = [_make_context("withdraw"), _make_context("deposit")]
    engine, _ = _make_engine([
        _make_mock_response([_make_tool_call()]),
        _make_mock_response([_make_tool_call(title="Deposit issue")]),
    ])

    findings = engine.run_pass_b(contexts)

    assert findings[0].id == "VH-001"
    assert findings[1].id == "VH-002"


# ===========================================================================
# Group 6 — run_pass_c
# ===========================================================================


def test_run_pass_c_skips_contracts_without_deps():
    # Contract with no external calls or cross-contract calls
    ctx = FunctionContext(
        function=_make_function(),
        contract=ContractInfo(name="Simple", file_path="Simple.sol", external_calls=[]),
        static_findings=[],
        cross_contract_calls=[],
        similar_exploits=[],
    )
    engine, mock_client = _make_engine()

    engine.run_pass_c([ctx], _make_scope())

    mock_client.create.assert_not_called()


def test_run_pass_c_groups_by_contract():
    """3 contexts from 2 contracts → 2 API calls (not 3)."""
    ctx_vault_1 = _make_context("withdraw")
    ctx_vault_2 = _make_context("deposit")
    ctx_token = FunctionContext(
        function=_make_function(name="transfer"),
        contract=_make_contract(name="Token", external_calls=["erc20_transfer"]),
        cross_contract_calls=["Vault"],
        static_findings=[],
        similar_exploits=[],
    )

    engine, mock_client = _make_engine([_make_empty_response(), _make_empty_response()])

    engine.run_pass_c([ctx_vault_1, ctx_vault_2, ctx_token], _make_scope())

    assert mock_client.create.call_count == 2


def test_run_pass_c_uses_sonnet_model():
    ctx = _make_context()
    engine, mock_client = _make_engine([_make_empty_response()])

    engine.run_pass_c([ctx], _make_scope())

    model_used = mock_client.create.call_args.kwargs["model"]
    assert model_used == engine._settings.llm_model


def test_run_pass_c_assigns_correct_source():
    ctx = _make_context()
    engine, mock_client = _make_engine([_make_mock_response([_make_tool_call()])])

    findings = engine.run_pass_c([ctx], _make_scope())

    assert all(f.source == FindingSource.LLM_CROSS_CONTRACT for f in findings)


def test_run_pass_c_continues_on_error():
    ctx = _make_context()
    engine, mock_client = _make_engine()
    mock_client.create.side_effect = RuntimeError("API error")

    findings = engine.run_pass_c([ctx], _make_scope())

    assert findings == []


# ===========================================================================
# Group 7 — run_pass_d
# ===========================================================================


def test_run_pass_d_makes_single_api_call():
    contexts = [_make_context(f"fn{i}") for i in range(10)]
    engine, mock_client = _make_engine([_make_empty_response()])

    engine.run_pass_d(contexts, _make_scope())

    assert mock_client.create.call_count == 1


def test_run_pass_d_uses_fast_model():
    engine, mock_client = _make_engine([_make_empty_response()])

    engine.run_pass_d([_make_context()], _make_scope())

    model_used = mock_client.create.call_args.kwargs["model"]
    assert model_used == engine._settings.llm_model_fast


def test_run_pass_d_assigns_correct_source():
    engine, mock_client = _make_engine([_make_mock_response([_make_tool_call()])])

    findings = engine.run_pass_d([_make_context()], _make_scope())

    assert all(f.source == FindingSource.LLM_ECONOMIC for f in findings)


def test_run_pass_d_returns_empty_on_api_error():
    engine, mock_client = _make_engine()
    mock_client.create.side_effect = RuntimeError("API error")

    findings = engine.run_pass_d([_make_context()], _make_scope())

    assert findings == []


def test_run_pass_d_returns_empty_when_no_contracts():
    engine, mock_client = _make_engine()
    empty_scope = ProjectScope(repo_path=".", contracts=[])

    findings = engine.run_pass_d([], empty_scope)

    assert findings == []
    mock_client.create.assert_not_called()


# ===========================================================================
# Group 8 — analyze() end-to-end
# ===========================================================================


def test_analyze_combines_all_passes():
    """One finding per pass → 3 total, plus Pass D always runs once."""
    engine, mock_client = _make_engine()

    # Pass B: 1 context → 1 finding
    # Pass C: 1 context with deps → 1 finding
    # Pass D: 1 project-level finding
    mock_client.create.side_effect = [
        _make_mock_response([_make_tool_call(title="B finding")]),   # Pass B call 1
        _make_mock_response([_make_tool_call(title="C finding")]),   # Pass C call 1
        _make_mock_response([_make_tool_call(title="D finding")]),   # Pass D call
    ]

    findings = engine.analyze([_make_context()], _make_scope())

    assert len(findings) == 3
    titles = [f.title for f in findings]
    assert "B finding" in titles
    assert "C finding" in titles
    assert "D finding" in titles


def test_analyze_finding_ids_are_sequential_across_passes():
    engine, mock_client = _make_engine()

    mock_client.create.side_effect = [
        _make_mock_response([_make_tool_call(title="F1")]),  # Pass B
        _make_mock_response([_make_tool_call(title="F2")]),  # Pass C
        _make_mock_response([_make_tool_call(title="F3")]),  # Pass D
    ]

    findings = engine.analyze([_make_context()], _make_scope())

    ids = [f.id for f in findings]
    assert ids == ["VH-001", "VH-002", "VH-003"]


def test_analyze_empty_contexts_skips_b_and_c():
    engine, mock_client = _make_engine()

    findings = engine.analyze([], _make_scope())

    assert findings == []
    mock_client.create.assert_not_called()


# ===========================================================================
# Group 9 — Template helpers
# ===========================================================================


def test_truncate_source_short_string_unchanged():
    src = "function foo() {}"
    assert truncate_source(src, max_chars=4000) == src


def test_truncate_source_caps_at_max_chars():
    src = "x" * 5000
    result = truncate_source(src, max_chars=4000)
    assert len(result) < 5000
    assert "truncated" in result


def test_truncate_source_empty_string():
    result = truncate_source("", max_chars=4000)
    assert "unavailable" in result


def test_format_static_findings_empty():
    result = format_static_findings([])
    assert "none" in result.lower() or "passed" in result.lower()


def test_format_static_findings_includes_detector_and_severity():
    finding = _make_finding_static("reentrancy-eth", Severity.HIGH)
    result = format_static_findings([finding])
    assert "reentrancy-eth" in result
    assert "HIGH" in result


def test_format_similar_exploits_empty():
    result = format_similar_exploits([])
    assert "no similar" in result.lower() or "none" in result.lower()


def test_format_similar_exploits_caps_at_max_count():
    exploits = [_make_exploit(f"HACK-{i:03d}") for i in range(10)]
    result = format_similar_exploits(exploits, max_count=3)
    # Only 3 numbered entries should appear (format: "  1.", "  2.", "  3.")
    assert result.count("  1.") == 1
    assert result.count("  3.") == 1
    assert "  4." not in result


def test_format_similar_exploits_shows_protocol_and_score():
    exploit = _make_exploit("HACK-001", score=0.92)
    result = format_similar_exploits([exploit], max_count=3)
    assert "TestDeFi" in result
    assert "0.92" in result


def test_build_pass_b_prompt_includes_function_details():
    ctx = _make_context()
    prompt = build_pass_b_prompt(ctx)
    assert "Vault" in prompt
    assert "withdraw" in prompt
    assert "reentrancy" in prompt  # from static finding description


def test_build_pass_b_prompt_truncates_long_source():
    long_source = "x" * 8000
    fn = _make_function(source=long_source)
    ctx = FunctionContext(function=fn, contract=_make_contract())
    prompt = build_pass_b_prompt(ctx, max_source_chars=4000)
    assert "truncated" in prompt


def test_build_pass_c_prompt_includes_contract_name():
    ctx = _make_context()
    prompt = build_pass_c_prompt(ctx.contract, [ctx])
    assert "Vault" in prompt


def test_build_pass_c_prompt_includes_dependencies():
    ctx = _make_context(cross_calls=["Token", "Oracle"])
    prompt = build_pass_c_prompt(ctx.contract, [ctx])
    assert "Token" in prompt or "Oracle" in prompt


def test_build_pass_d_prompt_includes_all_contracts():
    contracts = [_make_contract("Vault"), _make_contract("Token"), _make_contract("Oracle")]
    scope = ProjectScope(repo_path="./", contracts=contracts, total_loc=1000)
    ctx = _make_context()
    prompt = build_pass_d_prompt(scope, [ctx])
    assert "Vault" in prompt
    assert "Token" in prompt
    assert "Oracle" in prompt


def test_build_pass_d_prompt_highlights_payable_functions():
    fn = _make_function(mutability="payable")
    ctx = FunctionContext(function=fn, contract=_make_contract())
    scope = _make_scope()
    prompt = build_pass_d_prompt(scope, [ctx])
    assert "payable" in prompt
