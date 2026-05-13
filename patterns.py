"""MEV pattern detection algorithms."""
from enum import Enum

class PatternType(Enum):
    SANDWICH = 'sandwich'
    JIT = 'jit_liquidity'
    BACKRUN = 'backrun'
    ARBITRAGE = 'arbitrage'

def detect_jit_liquidity(txs):
    results = []
    for tx in txs:
        sig = tx.get('input', '')[:10]
        if sig in ['0xe8e33700', '0xf305d719']:
            results.append({'type': 'jit', 'tx': tx['hash']})
    return results
