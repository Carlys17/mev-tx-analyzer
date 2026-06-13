"""Pattern detection algorithms for MEV transactions.

Pure-function style, no I/O. Easy to test.

A "transaction" is a dict with at least:
  - hash, from, to, input (hex), value (wei int), gasPrice, gas, blockNumber
"""
from __future__ import annotations
from typing import Iterable

# Function selectors (4-byte) for common DeFi / MEV operations.

def _addr(t): return (t.get("from") or t.get("from_addr") or "").lower()
def _to(t):   return (t.get("to")   or t.get("to_addr")   or "").lower()
def _bn(t):   return t.get("blockNumber", 0)

SIGS = {
    "0x38ed1739": "swapExactTokensForTokens",
    "0x8803dbee": "swapTokensForExactTokens",
    "0x7ff36ab5": "swapExactETHForTokens",
    "0x4a25d94a": "swapTokensForExactETH",
    "0x18cbafe5": "swapExactTokensForETH",
    "0xfb3bdb41": "swapETHForExactTokens",
    "0xe8e33700": "addLiquidity",
    "0xf305d719": "addLiquidityETH",
    "0xbaa2abde": "removeLiquidity",
    "0x02751cec": "removeLiquidityETH",
    "0x2e1a7d4d": "withdraw",
    "0xd0e30db0": "deposit",
    "0xa9059cbb": "transfer",
    "0x23b872dd": "transferFrom",
    "0x791ac947": "swapExactTokensForETHSupportingFeeOnTransferTokens",
    "0xb6b55f25": "deposit (WETH)",
    "0x2e17de78": "unwrapWETH9",
    "0x1e9a6950": "settleAll",
}


def selector(tx: dict) -> str:
    """Return the 4-byte function selector, or '' if input is malformed."""
    data = tx.get("input", "")
    if not isinstance(data, str) or not data.startswith("0x") or len(data) < 10:
        return ""
    return data[:10].lower()


def func_name(tx: dict) -> str:
    return SIGS.get(selector(tx), "unknown")


def is_swap(tx: dict) -> bool:
    return selector(tx) in {
        "0x38ed1739", "0x8803dbee", "0x7ff36ab5", "0x4a25d94a",
        "0x18cbafe5", "0xfb3bdb41", "0x791ac947",
    }


def is_liquidity_op(tx: dict) -> bool:
    return selector(tx) in {
        "0xe8e33700", "0xf305d719", "0xbaa2abde", "0x02751cec",
    }


def is_zero_gas_price(tx: dict) -> bool:
    """True if this is a Flashbots-style direct-to-builder tx."""
    gp = tx.get("gasPrice", 0)
    return gp == 0


def detect_sandwich(txs: list[dict]) -> list[dict]:
    """Naive sandwich detector: A, B, A in same block, same router, A has the same input prefix.
    Returns: [{'frontrun': txA1, 'victim': txB, 'backrun': txA2, 'attacker': addr}]
    """
    out = []
    for i in range(len(txs) - 2):
        a, b, c = txs[i], txs[i+1], txs[i+2]
        if (_addr(a) == _addr(c)
                and _addr(a) != _addr(b)
                and _to(a) == _to(b) == _to(c)
                and a["input"][:10] == b["input"][:10] == c["input"][:10]
                and is_swap(a)
                and _bn(b) == _bn(a) == _bn(c)):
            out.append({
                "frontrun": a.get("hash",""), "victim": b["hash"], "backrun": c["hash"],
                "attacker": _addr(a), "router": _to(a),
            })
    return out


def detect_jit_liquidity(txs: list[dict]) -> list[dict]:
    """JIT liquidity: addLiquidity + removeLiquidity in the same block, same address, same pool."""
    out = []
    adds = [t for t in txs if func_name(t) in ("addLiquidity", "addLiquidityETH")]
    rems = [t for t in txs if func_name(t) in ("removeLiquidity", "removeLiquidityETH")]
    for a in adds:
        for r in rems:
            if (_addr(a) == _addr(r).lower()
                    and _bn(a) == _bn(r)):
                out.append({"add": a.get("hash",""), "remove": r.get("hash",""), "lp": _addr(a)})
    return out


def detect_liquidation(txs: list[dict]) -> list[dict]:
    """Heuristic: a tx with selector 0x1e9a6950 (settleAll) is often an Aave/Compound liquidation."""
    out = []
    for t in txs:
        if selector(t) == "0x1e9a6950":
            out.append({"tx": t.get("hash",""), "from": _addr(t), "to": _to(t)})
    return out
