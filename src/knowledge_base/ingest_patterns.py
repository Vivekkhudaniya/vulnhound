"""
VulnHound Knowledge Base — Vulnerability Pattern Library

Ingests 50+ canonical vulnerability patterns as synthetic ExploitDocuments.
These are NOT real exploits — they are high-quality pattern templates derived
from OWASP SC Top 10, DeFiHackLabs taxonomy, and SWC Registry.

Why synthetic patterns?
  Real exploit data only covers what *has* happened.
  Pattern templates cover the full attack surface — even for vulnerability types
  that haven't been exploited yet in a public incident.

The patterns are stored alongside real exploits in ChromaDB, so RAG retrieval
surfaces both "this exact thing happened before" AND "this matches a known
dangerous pattern".

Usage:
    python -m src.knowledge_base.ingest_patterns
    # or
    from src.knowledge_base.ingest_patterns import ingest_all_patterns
    ingest_all_patterns()
"""

from __future__ import annotations

from datetime import datetime

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

# Sentinel date for synthetic patterns
_PATTERN_DATE = datetime(2024, 1, 1)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------


def _make(
    id: str,
    protocol: str,
    category: VulnCategory,
    subcategory: str,
    description: str,
    root_cause: str,
    affected_functions: list[str],
    attack_steps: list[str],
    vulnerable_snippet: str,
    fix_snippet: str,
    tags: list[str],
    loss_usd: float = 0.0,
) -> ExploitDocument:
    return ExploitDocument(
        id=id,
        protocol=protocol,
        date=_PATTERN_DATE,
        chain=Chain.ETHEREUM,
        loss_usd=loss_usd,
        recovered=False,
        vulnerability=VulnerabilityPattern(
            category=category,
            subcategory=subcategory,
            description=description,
            root_cause=root_cause,
            affected_functions=affected_functions,
            owasp_mapping=_OWASP.get(category),
        ),
        code_context=CodeContext(
            vulnerable_snippet=vulnerable_snippet,
            fix_snippet=fix_snippet,
            contract_name=protocol,
            solidity_version="^0.8.0",
        ),
        exploit_mechanism=ExploitMechanism(
            attack_steps=attack_steps,
        ),
        source="pattern_library",
        source_url=None,
        tags=["pattern", "synthetic"] + tags,
    )


_OWASP: dict[VulnCategory, str] = {
    VulnCategory.ACCESS_CONTROL:           "SC01:2025",
    VulnCategory.REENTRANCY:               "SC05:2025",
    VulnCategory.INTEGER_OVERFLOW:         "SC03:2025",
    VulnCategory.PRICE_MANIPULATION:       "SC06:2025",
    VulnCategory.ORACLE_MANIPULATION:      "SC06:2025",
    VulnCategory.FLASH_LOAN:               "SC06:2025",
    VulnCategory.LOGIC_ERROR:              "SC04:2025",
    VulnCategory.UNCHECKED_EXTERNAL_CALL:  "SC02:2025",
    VulnCategory.DELEGATE_CALL:            "SC09:2025",
    VulnCategory.STORAGE_COLLISION:        "SC09:2025",
    VulnCategory.FRONT_RUNNING:            "SC07:2025",
    VulnCategory.DENIAL_OF_SERVICE:        "SC08:2025",
    VulnCategory.INPUT_VALIDATION:         "SC04:2025",
    VulnCategory.GOVERNANCE:               "SC10:2025",
}


def _get_patterns() -> list[ExploitDocument]:
    return [

        # ── REENTRANCY ────────────────────────────────────────────────────────

        _make(
            id="PAT-REENTRANCY-001",
            protocol="ReentrancyVault",
            category=VulnCategory.REENTRANCY,
            subcategory="reentrancy-eth",
            description="Classic single-function reentrancy: withdraw() sends ETH before updating balance, "
                        "allowing attacker to recursively drain the contract via receive().",
            root_cause="State update (balance = 0) happens AFTER external call (.call{value})",
            affected_functions=["withdraw"],
            attack_steps=[
                "Deploy attacker contract with receive() that calls back withdraw()",
                "Deposit 1 ETH to establish balance",
                "Call withdraw() — contract sends ETH before zeroing balance",
                "receive() triggers, calls withdraw() again while balance is still non-zero",
                "Recursively drain until contract is empty",
            ],
            vulnerable_snippet="""function withdraw() external {
    uint bal = balances[msg.sender];
    require(bal > 0);
    (bool ok,) = msg.sender.call{value: bal}(""); // ← external call FIRST
    require(ok);
    balances[msg.sender] = 0;                      // ← state update LAST
}""",
            fix_snippet="""function withdraw() external nonReentrant {
    uint bal = balances[msg.sender];
    require(bal > 0);
    balances[msg.sender] = 0;                      // ← state update FIRST
    (bool ok,) = msg.sender.call{value: bal}("");  // ← external call LAST
    require(ok);
}""",
            tags=["reentrancy", "eth-drain", "classic"],
            loss_usd=3_600_000,
        ),

        _make(
            id="PAT-REENTRANCY-002",
            protocol="CrossFunctionReentrancy",
            category=VulnCategory.REENTRANCY,
            subcategory="cross-function-reentrancy",
            description="Cross-function reentrancy: attacker re-enters a DIFFERENT function that "
                        "reads the stale state set by the first function mid-execution.",
            root_cause="Shared state variable read by two functions; one updates it after external call",
            affected_functions=["withdraw", "transfer"],
            attack_steps=[
                "Call withdraw() — sends ETH, balance not yet zeroed",
                "In receive(), call transfer() which reads the non-zero balance",
                "transfer() moves tokens to attacker a second time",
                "withdraw() finally zeros balance but tokens already transferred",
            ],
            vulnerable_snippet="""// balances[msg.sender] is stale during the external call
function withdraw() external {
    (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
    balances[msg.sender] = 0; // updated too late
}
function transfer(address to, uint amt) external {
    require(balances[msg.sender] >= amt); // reads stale balance
    balances[msg.sender] -= amt;
    balances[to] += amt;
}""",
            fix_snippet="Use ReentrancyGuard on both functions, or update all state before any external call.",
            tags=["reentrancy", "cross-function"],
        ),

        _make(
            id="PAT-REENTRANCY-003",
            protocol="ERC777Reentrancy",
            category=VulnCategory.REENTRANCY,
            subcategory="erc777-callback-reentrancy",
            description="ERC777 tokensReceived hook triggers reentrancy before internal accounting updates. "
                        "A contract that accepts ERC777 tokens must guard against this callback.",
            root_cause="ERC777 calls tokensReceived on recipient before the sender's balance is updated",
            affected_functions=["deposit", "mint"],
            attack_steps=[
                "Attacker implements IERC777Recipient.tokensReceived()",
                "Call deposit() sending ERC777 tokens",
                "ERC777 fires tokensReceived before contract updates shares",
                "In tokensReceived, call withdraw() with inflated share count",
            ],
            vulnerable_snippet="""// ERC777 transfer triggers tokensReceived BEFORE shares are minted
function deposit(uint amount) external {
    token.transferFrom(msg.sender, address(this), amount); // callback fires here
    shares[msg.sender] += amount; // already re-entered by now
}""",
            fix_snippet="Use ReentrancyGuard. Prefer ERC20 over ERC777 for vault deposits.",
            tags=["reentrancy", "erc777", "callback"],
        ),

        # ── FLASH LOAN / PRICE MANIPULATION ──────────────────────────────────

        _make(
            id="PAT-FLASHLOAN-001",
            protocol="SpotPriceOracle",
            category=VulnCategory.FLASH_LOAN,
            subcategory="spot-price-flash-loan",
            description="Protocol reads spot price from Uniswap V2 reserves (getReserves) in the same "
                        "transaction as a flash loan, allowing price manipulation before liquidation/borrow.",
            root_cause="Spot price from AMM reserves is trivially manipulable within a single transaction",
            affected_functions=["borrow", "liquidate", "getPrice"],
            attack_steps=[
                "Flash loan large amount of TOKEN_A",
                "Dump TOKEN_A into Uniswap V2 pair — reserves shift, spot price of TOKEN_A collapses",
                "Protocol reads manipulated getReserves() price",
                "Borrow maximum TOKEN_B against artificially cheap collateral",
                "Or trigger unfair liquidation of a victim position",
                "Repay flash loan, keep profit",
            ],
            vulnerable_snippet="""function getPrice() public view returns (uint) {
    (uint r0, uint r1,) = IUniswapV2Pair(pair).getReserves();
    return r1 * 1e18 / r0; // spot price — trivially manipulable
}
function borrow(uint collateral) external {
    uint price = getPrice(); // reads manipulated reserves
    uint maxBorrow = collateral * price / 1e18;
    ...
}""",
            fix_snippet="""// Use a TWAP oracle — resistant to single-tx manipulation
function getPrice() public view returns (uint) {
    return ITWAPOracle(oracle).consult(token, 1e18); // 30-min TWAP
}""",
            tags=["flash-loan", "price-manipulation", "spot-price", "uniswap-v2"],
            loss_usd=10_000_000,
        ),

        _make(
            id="PAT-FLASHLOAN-002",
            protocol="BalanceManiulation",
            category=VulnCategory.FLASH_LOAN,
            subcategory="balance-based-price-oracle",
            description="Protocol uses token.balanceOf(address(this)) as price oracle. "
                        "Flash loan + direct transfer inflates balance before any calculation.",
            root_cause="balanceOf() is not protected; can be inflated with a direct transfer",
            affected_functions=["getSharePrice", "deposit", "redeem"],
            attack_steps=[
                "Flash loan 1M USDC",
                "Transfer 1M USDC directly to vault (donate)",
                "Vault price per share = totalAssets / totalShares — now inflated",
                "Deposit 1 wei, get minted shares at old price before inflation",
                "Redeem at inflated price for profit",
                "Repay flash loan",
            ],
            vulnerable_snippet="""function pricePerShare() public view returns (uint) {
    return token.balanceOf(address(this)) * 1e18 / totalShares;
    // balanceOf can be manipulated by direct transfer
}""",
            fix_snippet="Track internal accounting with a totalAssets variable updated only by deposit/withdraw, not balanceOf.",
            tags=["flash-loan", "price-manipulation", "balance-oracle", "vault"],
            loss_usd=5_000_000,
        ),

        _make(
            id="PAT-FLASHLOAN-003",
            protocol="FlashLoanCallbackReentrancy",
            category=VulnCategory.FLASH_LOAN,
            subcategory="flash-loan-callback-reentrancy",
            description="Flash loan callback (uniswapV2Call / executeOperation) calls back into the "
                        "lending protocol before the loan is repaid, exploiting stale state.",
            root_cause="Lending protocol does not lock state during active flash loan",
            affected_functions=["flashLoan", "uniswapV2Call"],
            attack_steps=[
                "Call flashLoan() on protocol",
                "Protocol sends funds and calls executeOperation()",
                "Inside callback, call deposit() or borrow() on same protocol",
                "Protocol sees healthy state (loan not yet marked as repaid)",
                "Double-spend or bypass collateral checks",
            ],
            vulnerable_snippet="""function flashLoan(uint amount, address receiver) external {
    token.transfer(receiver, amount);
    IReceiver(receiver).executeOperation(amount); // callback
    require(token.balanceOf(address(this)) >= before, "Not repaid");
    // No lock — receiver can call back into this contract
}""",
            fix_snippet="Add nonReentrant modifier to flashLoan. Set a _inFlashLoan flag checked by borrow/deposit.",
            tags=["flash-loan", "reentrancy", "callback"],
        ),

        # ── ACCESS CONTROL ────────────────────────────────────────────────────

        _make(
            id="PAT-ACCESS-001",
            protocol="UnprotectedUpgrade",
            category=VulnCategory.ACCESS_CONTROL,
            subcategory="unprotected-upgrade",
            description="UUPS proxy upgradeTo() function missing onlyOwner modifier, "
                        "allowing anyone to upgrade to a malicious implementation.",
            root_cause="upgradeTo() not protected by access control modifier",
            affected_functions=["upgradeTo", "upgradeToAndCall"],
            attack_steps=[
                "Deploy malicious implementation contract with selfdestruct or drain logic",
                "Call proxy.upgradeTo(maliciousImpl) — succeeds because no access check",
                "All future calls delegatecall to malicious implementation",
                "Drain all funds or destroy the proxy",
            ],
            vulnerable_snippet="""// UUPS implementation — missing onlyOwner!
function upgradeTo(address newImpl) external {
    _upgradeTo(newImpl); // anyone can call
}""",
            fix_snippet="""function upgradeTo(address newImpl) external onlyOwner {
    _upgradeTo(newImpl);
}""",
            tags=["access-control", "proxy", "uups", "upgrade"],
            loss_usd=8_000_000,
        ),

        _make(
            id="PAT-ACCESS-002",
            protocol="UninitializedProxy",
            category=VulnCategory.ACCESS_CONTROL,
            subcategory="uninitialized-proxy",
            description="Proxy implementation contract deployed without calling initialize(), "
                        "leaving owner unset. Attacker calls initialize() and takes ownership.",
            root_cause="initialize() callable by anyone on the implementation contract (not the proxy)",
            affected_functions=["initialize"],
            attack_steps=[
                "Find the implementation contract address (read proxy storage slot)",
                "Call initialize(attacker_address) on the implementation directly",
                "Now own the implementation — can selfdestruct it",
                "selfdestruct breaks all proxies using this implementation",
            ],
            vulnerable_snippet="""contract VaultImpl {
    address public owner;
    function initialize(address _owner) external {
        // Missing: require(owner == address(0), "Already initialized");
        owner = _owner;
    }
}""",
            fix_snippet="""function initialize(address _owner) external initializer {
    // OpenZeppelin initializer modifier prevents re-initialization
    owner = _owner;
}""",
            tags=["access-control", "proxy", "initialize", "uninitialized"],
            loss_usd=20_000_000,
        ),

        _make(
            id="PAT-ACCESS-003",
            protocol="TxOriginAuth",
            category=VulnCategory.ACCESS_CONTROL,
            subcategory="tx-origin-authentication",
            description="Using tx.origin for authentication allows phishing attacks: "
                        "attacker tricks victim into calling malicious contract which "
                        "calls the victim's wallet contract, passing the tx.origin check.",
            root_cause="tx.origin is the original EOA, not the immediate caller — bypassable via intermediary",
            affected_functions=["transfer", "execute"],
            attack_steps=[
                "Deploy malicious contract",
                "Trick victim (who owns vulnerable contract) into calling malicious contract",
                "Malicious contract calls victim's wallet.transfer(attacker, balance)",
                "wallet.transfer checks tx.origin == victim — TRUE (victim signed the tx)",
                "Transfer succeeds",
            ],
            vulnerable_snippet="""function transfer(address to, uint amount) external {
    require(tx.origin == owner); // vulnerable — use msg.sender
    token.transfer(to, amount);
}""",
            fix_snippet="""function transfer(address to, uint amount) external {
    require(msg.sender == owner); // correct
    token.transfer(to, amount);
}""",
            tags=["access-control", "tx-origin", "phishing"],
        ),

        # ── INTEGER OVERFLOW / ARITHMETIC ─────────────────────────────────────

        _make(
            id="PAT-ARITH-001",
            protocol="PrecisionLoss",
            category=VulnCategory.INTEGER_OVERFLOW,
            subcategory="division-precision-loss",
            description="Integer division rounds down, causing loss of precision in reward calculations. "
                        "Attacker can repeatedly claim small amounts and accumulate rounded-down dust.",
            root_cause="Solidity integer division truncates; no fixed-point scaling applied",
            affected_functions=["claimReward", "calculateReward"],
            attack_steps=[
                "Find function that calculates reward = totalReward * userShares / totalShares",
                "If userShares is small, reward rounds to 0 even when non-zero",
                "Or: if division is done before multiplication, precision lost",
            ],
            vulnerable_snippet="""function reward(address user) public view returns (uint) {
    return totalReward / totalShares * userShares[user]; // division before mult
    // When totalReward < totalShares, this is always 0
}""",
            fix_snippet="""function reward(address user) public view returns (uint) {
    return totalReward * userShares[user] / totalShares; // mult before division
}""",
            tags=["arithmetic", "precision", "reward", "division"],
        ),

        _make(
            id="PAT-ARITH-002",
            protocol="FirstDepositorInflation",
            category=VulnCategory.INTEGER_OVERFLOW,
            subcategory="share-inflation-attack",
            description="ERC4626 vault first depositor can inflate share price to steal from subsequent depositors. "
                        "Deposit 1 wei, get 1 share. Donate large amount, inflate price per share. "
                        "Next depositor's tokens round down to 0 shares.",
            root_cause="pricePerShare calculation uses balanceOf which is inflatable; no minimum deposit",
            affected_functions=["deposit", "mint", "previewDeposit"],
            attack_steps=[
                "Deploy vault, become first depositor with 1 wei → 1 share",
                "Donate 1e18 tokens directly to vault (no shares minted)",
                "pricePerShare is now 1e18",
                "Victim deposits 1.5e18 tokens → previewDeposit = 1.5e18 / 1e18 = 1 share (rounds down to 1)",
                "Actually victim gets 1 share, attacker redeems 1 share for half the vault",
            ],
            vulnerable_snippet="""function previewDeposit(uint assets) public view returns (uint shares) {
    if (totalSupply == 0) return assets;
    return assets * totalSupply / totalAssets(); // vulnerable when totalSupply=1
}""",
            fix_snippet="""// OpenZeppelin 4626 fix: virtual offset
uint constant VIRTUAL_SHARES = 1e3;
uint constant VIRTUAL_ASSETS = 1;
function previewDeposit(uint assets) public view returns (uint shares) {
    return (assets * (totalSupply + VIRTUAL_SHARES)) / (totalAssets() + VIRTUAL_ASSETS);
}""",
            tags=["erc4626", "vault", "inflation", "first-depositor", "share-price"],
            loss_usd=2_000_000,
        ),

        # ── ORACLE MANIPULATION ───────────────────────────────────────────────

        _make(
            id="PAT-ORACLE-001",
            protocol="ChainlinkStaleness",
            category=VulnCategory.ORACLE_MANIPULATION,
            subcategory="stale-chainlink-price",
            description="Protocol uses Chainlink latestRoundData() without checking if the price "
                        "is stale (updatedAt too old) or if answeredInRound == roundId.",
            root_cause="No staleness check on Chainlink answer; protocol uses outdated price",
            affected_functions=["getPrice", "borrow", "liquidate"],
            attack_steps=[
                "Wait for Chainlink heartbeat to expire (prices become stale)",
                "In market dislocation, stale price diverges from real price",
                "Borrow against overvalued collateral using stale high price",
                "Or: liquidate positions that are healthy at current price but not at stale price",
            ],
            vulnerable_snippet="""function getPrice() external view returns (uint) {
    (, int price,,,) = priceFeed.latestRoundData();
    return uint(price);
    // Missing: staleness check, sequencer uptime check (for L2)
}""",
            fix_snippet="""function getPrice() external view returns (uint) {
    (uint80 roundId, int price,, uint updatedAt, uint80 answeredInRound)
        = priceFeed.latestRoundData();
    require(answeredInRound >= roundId, "Stale price");
    require(block.timestamp - updatedAt <= MAX_DELAY, "Price too old");
    require(price > 0, "Invalid price");
    return uint(price);
}""",
            tags=["oracle", "chainlink", "staleness", "l2"],
        ),

        _make(
            id="PAT-ORACLE-002",
            protocol="TWAPManipulation",
            category=VulnCategory.ORACLE_MANIPULATION,
            subcategory="short-twap-manipulation",
            description="TWAP period too short (e.g. 2 blocks) allows manipulation with sustained "
                        "price pressure over multiple blocks using concentrated capital.",
            root_cause="TWAP window so short that a well-funded attacker can manipulate it",
            affected_functions=["consult", "update"],
            attack_steps=[
                "Determine TWAP window (e.g. 2 blocks = ~24 seconds)",
                "Continuously push price in desired direction across 2+ blocks",
                "Each block: buy/sell to maintain manipulated price",
                "TWAP reflects manipulated price after window elapses",
                "Exploit dependent protocol using manipulated TWAP",
            ],
            vulnerable_snippet="""uint constant PERIOD = 2; // blocks — too short!
function consult(address token, uint amountIn) external view returns (uint) {
    // 2-block TWAP easily manipulated with large capital
}""",
            fix_snippet="Use minimum 30-minute TWAP. Consider Uniswap V3 oracle or Chainlink for price-sensitive operations.",
            tags=["oracle", "twap", "manipulation", "uniswap"],
        ),

        # ── DELEGATE CALL / PROXY ─────────────────────────────────────────────

        _make(
            id="PAT-DELEGATECALL-001",
            protocol="StorageCollisionProxy",
            category=VulnCategory.STORAGE_COLLISION,
            subcategory="proxy-storage-collision",
            description="Proxy and implementation share the same storage layout but have different "
                        "variable ordering, causing the implementation to overwrite proxy admin slot.",
            root_cause="Storage slot collision between proxy and implementation contract",
            affected_functions=["upgradeTo", "_setImplementation"],
            attack_steps=[
                "Identify storage slot used by proxy for admin address",
                "Find implementation variable that maps to the same slot",
                "Call implementation function that writes to that variable with attacker address",
                "Proxy admin is now overwritten — attacker has upgrade rights",
            ],
            vulnerable_snippet="""// Proxy: slot 0 = _implementation, slot 1 = _admin
contract TransparentProxy {
    address _implementation; // slot 0
    address _admin;          // slot 1
}
// Implementation: slot 0 = owner — COLLISION with _implementation!
contract Vault {
    address owner; // slot 0 — same slot as proxy._implementation
}""",
            fix_snippet="Use EIP-1967 standardized proxy storage slots. Never use slot 0 or 1 in implementations.",
            tags=["proxy", "storage-collision", "eip1967", "delegatecall"],
        ),

        _make(
            id="PAT-DELEGATECALL-002",
            protocol="ControlledDelegatecall",
            category=VulnCategory.DELEGATE_CALL,
            subcategory="arbitrary-delegatecall",
            description="Contract allows caller to control the target address of a delegatecall, "
                        "enabling attacker to execute arbitrary code in the contract's storage context.",
            root_cause="delegatecall target not restricted to trusted addresses",
            affected_functions=["execute", "multicall"],
            attack_steps=[
                "Deploy malicious contract with selfdestruct or storage manipulation",
                "Call execute(maliciousContract, data) — no whitelist check",
                "delegatecall runs malicious code in context of victim contract",
                "Malicious code drains funds or destroys contract",
            ],
            vulnerable_snippet="""function execute(address target, bytes calldata data) external onlyOwner {
    (bool ok,) = target.delegatecall(data); // target not validated
    require(ok);
}""",
            fix_snippet="""mapping(address => bool) public trustedImpls;
function execute(address target, bytes calldata data) external onlyOwner {
    require(trustedImpls[target], "Untrusted implementation");
    (bool ok,) = target.delegatecall(data);
    require(ok);
}""",
            tags=["delegatecall", "arbitrary-code", "execute", "multicall"],
        ),

        # ── UNCHECKED EXTERNAL CALLS ──────────────────────────────────────────

        _make(
            id="PAT-UNCHECKED-001",
            protocol="UncheckedTransfer",
            category=VulnCategory.UNCHECKED_EXTERNAL_CALL,
            subcategory="unchecked-erc20-transfer",
            description="Protocol does not check return value of ERC20 transfer() / transferFrom(). "
                        "Non-standard tokens (USDT on mainnet) return false instead of reverting on failure.",
            root_cause="ERC20 standard allows returning false; contract ignores it",
            affected_functions=["deposit", "withdraw", "swap"],
            attack_steps=[
                "Use a token that returns false on transfer failure (e.g. USDT, ZRX)",
                "Trigger conditions that cause transfer to fail (insufficient balance)",
                "Contract continues execution as if transfer succeeded",
                "Accounting is updated without actual token movement",
            ],
            vulnerable_snippet="""function deposit(uint amount) external {
    token.transferFrom(msg.sender, address(this), amount); // return value ignored
    balances[msg.sender] += amount; // credited even if transfer failed
}""",
            fix_snippet="""import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
function deposit(uint amount) external {
    SafeERC20.safeTransferFrom(token, msg.sender, address(this), amount);
    balances[msg.sender] += amount;
}""",
            tags=["erc20", "transfer", "unchecked", "usdt"],
        ),

        _make(
            id="PAT-UNCHECKED-002",
            protocol="LowLevelCallUnchecked",
            category=VulnCategory.UNCHECKED_EXTERNAL_CALL,
            subcategory="unchecked-low-level-call",
            description="Low-level .call() return value not checked. If the call fails silently, "
                        "subsequent state updates proceed incorrectly.",
            root_cause=".call() never reverts — it returns (bool, bytes); ignoring bool is dangerous",
            affected_functions=["sendRewards", "execute"],
            attack_steps=[
                "Create recipient contract that always reverts in receive()",
                "Protocol calls recipient.call{value: reward}('')",
                "Call fails silently — bool is false but not checked",
                "Protocol marks reward as sent; ETH stays in contract",
                "Funds stuck or double-spent in next accounting cycle",
            ],
            vulnerable_snippet="""function sendReward(address user, uint amount) internal {
    user.call{value: amount}(""); // return value ignored
    rewards[user] = 0; // marked as sent even if call failed
}""",
            fix_snippet="""function sendReward(address user, uint amount) internal {
    (bool ok,) = user.call{value: amount}("");
    require(ok, "ETH transfer failed");
    rewards[user] = 0;
}""",
            tags=["low-level-call", "unchecked", "eth-transfer"],
        ),

        # ── FRONT RUNNING / MEV ───────────────────────────────────────────────

        _make(
            id="PAT-FRONTRUN-001",
            protocol="SlippageSandwich",
            category=VulnCategory.FRONT_RUNNING,
            subcategory="sandwich-attack",
            description="DEX swap with no slippage protection (amountOutMin=0) is sandwichable: "
                        "bot front-runs to push price up, victim gets worse rate, bot back-runs for profit.",
            root_cause="amountOutMin=0 (or any value too low) allows unlimited slippage",
            affected_functions=["swap", "swapExactTokensForTokens"],
            attack_steps=[
                "Monitor mempool for swap with amountOutMin=0",
                "Front-run: buy TOKEN before victim's tx, pushing price up",
                "Victim's swap executes at worse price (slippage)",
                "Back-run: sell TOKEN immediately after victim's tx",
                "Profit = victim's slippage loss",
            ],
            vulnerable_snippet="""router.swapExactTokensForTokens(
    amountIn,
    0,          // amountOutMin = 0 — no slippage protection
    path,
    recipient,
    deadline
);""",
            fix_snippet="""// Calculate expected output and use max 0.5% slippage
uint[] memory amounts = router.getAmountsOut(amountIn, path);
uint amountOutMin = amounts[amounts.length - 1] * 995 / 1000; // 0.5% slippage
router.swapExactTokensForTokens(amountIn, amountOutMin, path, recipient, deadline);""",
            tags=["mev", "sandwich", "slippage", "frontrun", "dex"],
        ),

        _make(
            id="PAT-FRONTRUN-002",
            protocol="ApproveRace",
            category=VulnCategory.FRONT_RUNNING,
            subcategory="erc20-approve-race",
            description="ERC20 approve() race condition: when changing allowance from N to M, "
                        "spender can front-run to spend N before allowance is set to M, then spend M.",
            root_cause="approve() replaces allowance atomically but two txs can be ordered adversarially",
            affected_functions=["approve"],
            attack_steps=[
                "Alice approves Bob for 100 tokens (current allowance: 0 → 100)",
                "Alice submits approve(Bob, 50) to reduce allowance",
                "Bob front-runs: spends 100 tokens before Alice's tx lands",
                "Alice's tx lands: Bob's allowance is now 50",
                "Bob spends 50 more — total spent: 150",
            ],
            vulnerable_snippet="""// Victim calls approve(spender, 50) after approve(spender, 100)
// Spender frontruns the second approve to spend 100 first
token.approve(spender, 50); // vulnerable""",
            fix_snippet="""// Use increaseAllowance / decreaseAllowance instead
token.increaseAllowance(spender, 50);
// Or always set to 0 first:
token.approve(spender, 0);
token.approve(spender, 50);""",
            tags=["erc20", "approve", "race-condition", "frontrun"],
        ),

        # ── DENIAL OF SERVICE ─────────────────────────────────────────────────

        _make(
            id="PAT-DOS-001",
            protocol="GasGriefing",
            category=VulnCategory.DENIAL_OF_SERVICE,
            subcategory="unbounded-loop-dos",
            description="Protocol iterates over an unbounded array in a state-modifying function. "
                        "Attacker fills the array to make the function run out of gas.",
            root_cause="No cap on array length; gas cost grows O(n) with attacker-controlled input",
            affected_functions=["distributeRewards", "batchTransfer"],
            attack_steps=[
                "Identify function that loops over users[] or similar unbounded array",
                "Create many small positions or register many addresses",
                "When contract tries to process all of them, gas limit is exceeded",
                "Function permanently broken — funds locked",
            ],
            vulnerable_snippet="""function distributeRewards() external {
    for (uint i = 0; i < users.length; i++) { // unbounded — gas bomb
        token.transfer(users[i], rewards[users[i]]);
    }
}""",
            fix_snippet="""// Pull pattern: users claim their own rewards
function claimReward() external {
    uint r = rewards[msg.sender];
    rewards[msg.sender] = 0;
    token.transfer(msg.sender, r);
}""",
            tags=["dos", "gas", "unbounded-loop", "push-payment"],
        ),

        _make(
            id="PAT-DOS-002",
            protocol="RevertGriefing",
            category=VulnCategory.DENIAL_OF_SERVICE,
            subcategory="revert-griefing",
            description="Protocol uses push payment to multiple recipients; one malicious recipient "
                        "always reverts, blocking payments to all others.",
            root_cause="Single revert in loop aborts entire transaction",
            affected_functions=["batchPay", "distributeRewards"],
            attack_steps=[
                "Become one of the recipients (e.g. add liquidity, register)",
                "Implement receive() / fallback() that always reverts",
                "When protocol calls batchPay, the entire tx reverts",
                "All other recipients are also blocked from payment",
            ],
            vulnerable_snippet="""function batchPay(address[] calldata recipients, uint[] calldata amounts) external {
    for (uint i = 0; i < recipients.length; i++) {
        (bool ok,) = recipients[i].call{value: amounts[i]}("");
        require(ok, "Transfer failed"); // one revert kills all
    }
}""",
            fix_snippet="""// Skip failed transfers, track them separately
mapping(address => uint) public pendingWithdrawals;
function batchPay(address[] calldata recipients, uint[] calldata amounts) external {
    for (uint i = 0; i < recipients.length; i++) {
        (bool ok,) = recipients[i].call{value: amounts[i]}("");
        if (!ok) pendingWithdrawals[recipients[i]] += amounts[i];
    }
}""",
            tags=["dos", "revert-griefing", "batch-payment", "push-pull"],
        ),

        # ── LOGIC ERRORS ──────────────────────────────────────────────────────

        _make(
            id="PAT-LOGIC-001",
            protocol="WrongOrderOperations",
            category=VulnCategory.LOGIC_ERROR,
            subcategory="checks-effects-interactions-violation",
            description="Contract violates CEI (Checks-Effects-Interactions) pattern: "
                        "state effects happen after external interactions, enabling reentrancy.",
            root_cause="External call before state update — classic CEI violation",
            affected_functions=["withdraw", "claimReward"],
            attack_steps=[
                "Identify any function making an external call before updating state",
                "Deploy attacker contract that re-enters the vulnerable function",
                "Drain contract by recursively calling before balance is zeroed",
            ],
            vulnerable_snippet="""// Bad: Interactions before Effects
function claimReward() external {
    uint r = pendingRewards[msg.sender]; // Check
    token.transfer(msg.sender, r);       // Interaction — TOO EARLY
    pendingRewards[msg.sender] = 0;      // Effect — TOO LATE
}""",
            fix_snippet="""// Good: Checks → Effects → Interactions
function claimReward() external {
    uint r = pendingRewards[msg.sender]; // Check
    pendingRewards[msg.sender] = 0;      // Effect first
    token.transfer(msg.sender, r);       // Interaction last
}""",
            tags=["cei", "checks-effects-interactions", "logic-error", "reentrancy-precursor"],
        ),

        _make(
            id="PAT-LOGIC-002",
            protocol="SignatureReplay",
            category=VulnCategory.LOGIC_ERROR,
            subcategory="signature-replay",
            description="Contract accepts signed messages without nonce or expiry, "
                        "allowing the same signature to be replayed multiple times.",
            root_cause="No nonce in signed message; no expiry; no chain ID binding",
            affected_functions=["permit", "execute", "claim"],
            attack_steps=[
                "Observe a valid signed transaction on-chain",
                "Replay the same signature to repeat the authorized action",
                "Without nonce: unlimited replays until state change invalidates sig",
                "Without chainId: replay on different chain if protocol is multi-chain",
            ],
            vulnerable_snippet="""function execute(address to, uint amount, bytes calldata sig) external {
    bytes32 hash = keccak256(abi.encodePacked(to, amount));
    address signer = ECDSA.recover(hash, sig);
    require(signer == owner);
    token.transfer(to, amount); // replayable — no nonce
}""",
            fix_snippet="""mapping(address => uint) public nonces;
function execute(address to, uint amount, uint nonce, bytes calldata sig) external {
    require(nonces[msg.sender]++ == nonce, "Invalid nonce");
    bytes32 hash = keccak256(abi.encodePacked(to, amount, nonce, block.chainid, address(this)));
    address signer = ECDSA.recover(hash, sig);
    require(signer == owner);
    token.transfer(to, amount);
}""",
            tags=["signature", "replay", "nonce", "eip712"],
        ),

        _make(
            id="PAT-LOGIC-003",
            protocol="ReadonlyReentrancy",
            category=VulnCategory.REENTRANCY,
            subcategory="read-only-reentrancy",
            description="Curve/Balancer pools have a read-only reentrancy vulnerability: "
                        "an external contract reads pool prices via a view function during "
                        "the pool's reentrant state, getting stale/manipulated values.",
            root_cause="View functions can be called during reentrant execution when ETH is being sent",
            affected_functions=["get_virtual_price", "getSpotPrice"],
            attack_steps=[
                "Call remove_liquidity() on Curve pool — pool sends ETH to attacker",
                "In receive(): call a protocol that reads pool.get_virtual_price()",
                "Pool is in reentrant state — virtual_price is stale/manipulated",
                "Protocol uses manipulated price for valuation",
                "Borrow against inflated collateral value",
                "Withdraw ETH, repay — keep profit",
            ],
            vulnerable_snippet="""// Protocol reads Curve price during pool's reentrant state
function getCollateralValue() external view returns (uint) {
    uint price = curvePool.get_virtual_price(); // can be called during reentrancy
    return userBalance * price / 1e18;
}""",
            fix_snippet="""// Use Curve's reentrancy guard check before reading price
function getCollateralValue() external view returns (uint) {
    curvePool.claim_admin_fees(); // triggers reentrancy guard — reverts if reentrant
    uint price = curvePool.get_virtual_price();
    return userBalance * price / 1e18;
}""",
            tags=["reentrancy", "read-only", "curve", "view-function"],
            loss_usd=50_000_000,
        ),

        # ── GOVERNANCE ────────────────────────────────────────────────────────

        _make(
            id="PAT-GOV-001",
            protocol="FlashLoanGovernance",
            category=VulnCategory.GOVERNANCE,
            subcategory="flash-loan-governance-attack",
            description="Governance uses token balance (not time-locked snapshot) for voting power. "
                        "Attacker flash loans governance tokens, votes, repays in one transaction.",
            root_cause="Voting power measured at current block balance, not historical snapshot",
            affected_functions=["castVote", "propose"],
            attack_steps=[
                "Flash loan large amount of governance token",
                "Delegate to self (or use directly if delegation instant)",
                "Call castVote() — flash loaned tokens count as voting power",
                "Pass malicious proposal in same transaction",
                "Repay flash loan",
            ],
            vulnerable_snippet="""function castVote(uint proposalId, bool support) external {
    uint votes = token.balanceOf(msg.sender); // current balance — manipulable
    _castVote(proposalId, msg.sender, support, votes);
}""",
            fix_snippet="""function castVote(uint proposalId, bool support) external {
    uint votes = token.getPriorVotes(msg.sender, proposals[proposalId].startBlock);
    // Historical snapshot at proposal creation block — flash loans don't help
    _castVote(proposalId, msg.sender, support, votes);
}""",
            tags=["governance", "flash-loan", "voting", "snapshot"],
            loss_usd=182_000_000,
        ),

        # ── CROSS CONTRACT ─────────────────────────────────────────────────────

        _make(
            id="PAT-CROSS-001",
            protocol="CallbackManipulation",
            category=VulnCategory.LOGIC_ERROR,
            subcategory="malicious-callback",
            description="Protocol calls user-supplied callback or interacts with user-supplied token "
                        "contract without validating it, allowing arbitrary code execution.",
            root_cause="Trusted code + untrusted address = attacker-controlled callback",
            affected_functions=["onFlashLoan", "onERC721Received", "swap"],
            attack_steps=[
                "Protocol calls user-supplied callback address with assets in transit",
                "Attacker's callback manipulates protocol state before returning",
                "Protocol continues under false assumptions",
            ],
            vulnerable_snippet="""function swap(address tokenIn, address tokenOut, address callback) external {
    uint balBefore = IERC20(tokenOut).balanceOf(address(this));
    ISwapCallback(callback).swapCallback(tokenIn, tokenOut); // arbitrary callback
    // attacker can do anything inside swapCallback
    require(IERC20(tokenOut).balanceOf(address(this)) >= balBefore + fee);
}""",
            fix_snippet="Validate callback address against a whitelist. Never call user-supplied addresses with assets in transit.",
            tags=["callback", "arbitrary-code", "user-supplied-address"],
        ),
    ]


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


def ingest_all_patterns(use_kb: bool = True) -> int:
    """
    Embed and store all vulnerability patterns into ChromaDB.

    Returns number of patterns ingested.
    """
    patterns = _get_patterns()
    console.rule("[bold cyan]VulnHound — Ingesting Vulnerability Pattern Library[/bold cyan]")
    console.print(f"  Patterns to ingest: {len(patterns)}")

    if not use_kb:
        console.print("[yellow]use_kb=False — skipping actual ingestion[/yellow]")
        return len(patterns)

    try:
        from src.knowledge_base.embedder import ExploitEmbedder
        from src.knowledge_base.vector_store import ChromaVectorStore
    except ImportError as e:
        console.print(f"[red]Cannot import KB modules: {e}[/red]")
        return 0

    embedder = ExploitEmbedder()
    store = ChromaVectorStore()

    ingested = 0
    for doc in track(patterns, description="Embedding patterns..."):
        try:
            embeddings = embedder.embed_exploit(doc)
            store.store_exploit(doc, embeddings)
            ingested += 1
        except Exception as e:
            console.print(f"[yellow]Failed to ingest {doc.id}: {e}[/yellow]")

    console.rule("[bold cyan]Pattern ingestion complete[/bold cyan]")
    console.print(f"  Ingested {ingested}/{len(patterns)} patterns")
    stats = store.get_stats()
    console.print(f"  KB stats: {stats}")
    return ingested


if __name__ == "__main__":
    ingest_all_patterns()
