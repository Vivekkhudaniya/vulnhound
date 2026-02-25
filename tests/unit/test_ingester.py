"""
Tests for Stage 1: Repo Ingester

Tests the parser, proxy detector, resolver, and dependency graph
against inline Solidity snippets — no network calls needed.
"""

from pathlib import Path
import tempfile

from src.ingester.ast_parser import parse_sol_file, parse_functions
from src.ingester.proxy_detector import detect_proxy
from src.ingester.dependency_graph import build_dependency_graph, extract_called_contracts
from src.ingester.clone import detect_framework, is_git_repo
from src.ingester.resolver import find_sol_files
from src.models import ContractInfo


# ── helpers ──────────────────────────────────────────────────────────────────

def _write_sol(content: str, filename: str = "Test.sol") -> Path:
    """Write a temp .sol file and return its path."""
    tmp = Path(tempfile.mkdtemp())
    f = tmp / filename
    f.write_text(content, encoding="utf-8")
    return f


# ── ast_parser ────────────────────────────────────────────────────────────────

def test_parse_simple_contract():
    sol = """
pragma solidity ^0.8.0;
contract Vault {
    function deposit() external payable {}
    function withdraw(uint256 amount) external {}
}
"""
    f = _write_sol(sol)
    contracts = parse_sol_file(f)
    assert len(contracts) == 1
    assert contracts[0].name == "Vault"
    assert contracts[0].solidity_version == "^0.8.0"


def test_parse_inheritance():
    sol = """
pragma solidity ^0.8.0;
contract Token is ERC20, Ownable {
    function mint(address to, uint256 amount) external {}
}
"""
    f = _write_sol(sol)
    contracts = parse_sol_file(f)
    assert len(contracts) == 1
    assert "ERC20" in contracts[0].inherits_from
    assert "Ownable" in contracts[0].inherits_from


def test_parse_multiple_contracts():
    sol = """
pragma solidity ^0.8.0;
interface IVault {
    function deposit() external;
}
contract Vault is IVault {
    function deposit() external {}
}
"""
    f = _write_sol(sol)
    contracts = parse_sol_file(f)
    assert len(contracts) == 2
    names = {c.name for c in contracts}
    assert "IVault" in names
    assert "Vault" in names


def test_parse_functions():
    sol = """
pragma solidity ^0.8.0;
contract Vault {
    function deposit() external payable {}
    function withdraw(uint256 amount) external {}
    function _internal() internal view returns (uint256) {}
    function getBalance() public view returns (uint256) {}
}
"""
    funcs = parse_functions(sol, "Vault")
    names = {f.name for f in funcs}
    assert "deposit" in names
    assert "withdraw" in names
    assert "getBalance" in names


def test_parse_loc():
    sol = "\n".join(["pragma solidity ^0.8.0;"] + [f"// line {i}" for i in range(50)] + ["contract A {}"])
    f = _write_sol(sol)
    contracts = parse_sol_file(f)
    assert contracts[0].loc > 0


# ── proxy_detector ────────────────────────────────────────────────────────────

def test_detect_uups_proxy():
    sol = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
contract MyProxy is UUPSUpgradeable {
    function _authorizeUpgrade(address) internal override {}
}
"""
    is_proxy, proxy_type = detect_proxy(sol, "MyProxy")
    assert is_proxy is True
    assert proxy_type == "UUPS"


def test_detect_transparent_proxy():
    sol = """
pragma solidity ^0.8.0;
contract MyProxy is TransparentUpgradeableProxy {
    constructor(address impl) {}
}
"""
    is_proxy, proxy_type = detect_proxy(sol, "MyProxy")
    assert is_proxy is True
    assert proxy_type == "Transparent"


def test_detect_diamond_proxy():
    sol = """
pragma solidity ^0.8.0;
contract Diamond {
    function diamondCut(FacetCut[] calldata) external {}
    function facets() external view returns (Facet[] memory) {}
}
"""
    is_proxy, proxy_type = detect_proxy(sol, "Diamond")
    assert is_proxy is True
    assert proxy_type == "Diamond"


def test_no_proxy():
    sol = """
pragma solidity ^0.8.0;
contract SimpleVault {
    function deposit() external payable {}
}
"""
    is_proxy, proxy_type = detect_proxy(sol, "SimpleVault")
    assert is_proxy is False
    assert proxy_type is None


# ── dependency_graph ──────────────────────────────────────────────────────────

def test_build_dependency_graph():
    contracts = [
        ContractInfo(name="Vault", file_path="Vault.sol", inherits_from=["IVault"], external_calls=["IERC20"]),
        ContractInfo(name="IVault", file_path="IVault.sol"),
        ContractInfo(name="IERC20", file_path="IERC20.sol"),
    ]
    graph = build_dependency_graph(contracts)
    assert "IVault" in graph["Vault"]
    assert "IERC20" in graph["Vault"]


def test_extract_called_contracts():
    content = "IERC20(token).transfer(to, amount); IVault(vault).deposit();"
    known = {"IERC20", "IVault", "SafeMath"}
    called = extract_called_contracts(content, known)
    assert "IERC20" in called
    assert "IVault" in called


# ── clone / framework detection ───────────────────────────────────────────────

def test_detect_framework_foundry(tmp_path):
    (tmp_path / "foundry.toml").write_text("[profile.default]")
    assert detect_framework(tmp_path) == "foundry"


def test_detect_framework_hardhat(tmp_path):
    (tmp_path / "hardhat.config.js").write_text("module.exports = {}")
    assert detect_framework(tmp_path) == "hardhat"


def test_detect_framework_unknown(tmp_path):
    assert detect_framework(tmp_path) == "unknown"


def test_is_git_repo_false(tmp_path):
    assert is_git_repo(tmp_path) is False


# ── resolver ─────────────────────────────────────────────────────────────────

def test_find_sol_files_excludes_tests(tmp_path):
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "Vault.sol").write_text("contract Vault {}")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "Vault.t.sol").write_text("contract VaultTest {}")
    (tmp_path / "lib").mkdir()
    (tmp_path / "lib" / "ERC20.sol").write_text("contract ERC20 {}")

    files = find_sol_files(tmp_path, exclude_tests=True)
    names = {f.name for f in files}
    assert "Vault.sol" in names
    assert "Vault.t.sol" not in names
    assert "ERC20.sol" not in names


def test_find_sol_files_include_all(tmp_path):
    (tmp_path / "contracts").mkdir()
    (tmp_path / "contracts" / "Vault.sol").write_text("contract Vault {}")
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "Vault.t.sol").write_text("contract VaultTest {}")

    files = find_sol_files(tmp_path, exclude_tests=False)
    names = {f.name for f in files}
    assert "Vault.sol" in names
    assert "Vault.t.sol" in names
