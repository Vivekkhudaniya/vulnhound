from src.knowledge_base.embedder import ExploitEmbedder
from src.knowledge_base.vector_store import ChromaVectorStore

store = ChromaVectorStore()
embedder = ExploitEmbedder()

queries = [
    ("Flash loan / price oracle AMM",       "flash loan price oracle manipulation AMM uniswap"),
    ("Reentrancy liquidity pool",            "reentrancy uniswap liquidity pool mint burn"),
    ("Sandwich / front-running DEX",        "sandwich attack front running DEX swap"),
    ("Integer overflow uint112 truncation", "integer overflow uint112 reserve truncation cast"),
    ("Uniswap fork exploit",                "uniswap fork price manipulation exploit"),
]

for label, q in queries:
    vec = embedder.embed_query(q)
    results = store.search_by_description(vec, top_k=3)
    print(f"\n=== {label} ===")
    for r in results:
        cat = r.category if isinstance(r.category, str) else r.category.value
        loss = f"${r.loss_usd:>12,.0f}" if r.loss_usd else "            —"
        print(f"  [{r.similarity_score:.3f}] {r.protocol:<35} | {cat:<25} | {loss} | {r.source}")
