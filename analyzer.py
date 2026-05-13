#!/usr/bin/env python3
"""MEV Transaction Analyzer - Detect MEV patterns in Ethereum transactions."""

import json
import sys
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

class MEVType(Enum):
    SANDWICH = "sandwich"
    FRONTRUN = "frontrun"
    ARBITRAGE = "arbitrage"
    JIT_LIQUIDITY = "jit_liquidity"
    LIQUIDATION = "liquidation"
    BACKRUN = "backrun"
    UNKNOWN = "unknown"

@dataclass
class Transaction:
    hash: str
    from_addr: str
    to_addr: str
    value: int
    gas_price: int
    input_data: str
    block_number: int
    nonce: int
    chain: str = "ethereum"

@dataclass
class MEVResult:
    mev_type: MEVType
    confidence: float  # 0.0 - 1.0
    attacker: str
    victim: Optional[str]
    profit_estimate: float
    tx_hashes: List[str]
    description: str

# Common DEX function signatures
DEX_SIGNATURES = {
    "0x38ed1739": "swapExactTokensForTokens",
    "0x7ff36ab5": "swapExactETHForTokens",
    "0x18cbafe5": "swapExactTokensForETH",
    "0x8803dbee": "swapTokensForExactTokens",
    "0xfb3bdb41": "swapETHForExactTokens",
    "0x5c11d795": "swapExactTokensForTokensSupportingFeeOnTransferTokens",
    "0x02751cec": "removeLiquidityETH",
    "0xbaa2abde": "removeLiquidity",
    "0xe8e33700": "addLiquidity",
    "0xf305d719": "addLiquidityETH",
    "0x1249c58b": "mint",
    "0xa0712d68": "mint(uint256)",
}

UNISWAP_V3_SIGNATURES = {
    "0x414bf389": "exactInputSingle",
    "0xc04b8d59": "exactInput",
    "0xdb3e2198": "exactOutputSingle",
    "0xf28c0498": "exactOutput",
    "0x0c49ccbe": "decreaseLiquidity",
    "0x219f5d17": "increaseLiquidity",
    "0xfc6f7865": "collect",
}

def decode_function_selector(input_data: str) -> str:
    """Extract and identify function selector from input data."""
    if len(input_data) < 10:
        return "transfer or simple call"
    selector = input_data[:10].lower()
    
    all_sigs = {**DEX_SIGNATURES, **UNISWAP_V3_SIGNATURES}
    return all_sigs.get(selector, f"unknown ({selector})")

def detect_sandwich_pattern(txs: List[Transaction]) -> List[MEVResult]:
    """Detect sandwich attacks in a list of transactions."""
    results = []
    
    # Group by target function (same selector = potential sandwich)
    swap_txs = [tx for tx in txs if tx.input_data[:10].lower() in DEX_SIGNATURES]
    
    for i, victim_tx in enumerate(swap_txs):
        # Look for frontrun (higher gas, same token pair, before victim)
        for frontrun_tx in swap_txs[:i]:
            if (frontrun_tx.from_addr != victim_tx.from_addr and
                frontrun_tx.gas_price > victim_tx.gas_price and
                frontrun_tx.input_data[:10] == victim_tx.input_data[:10]):
                
                # Look for backrun (same sender as frontrun, after victim)
                for backrun_tx in swap_txs[i+1:]:
                    if (backrun_tx.from_addr == frontrun_tx.from_addr and
                        backrun_tx.input_data[:10] == frontrun_tx.input_data[:10]):
                        
                        profit = (backrun_tx.value - frontrun_tx.value) / 1e18
                        results.append(MEVResult(
                            mev_type=MEVType.SANDWICH,
                            confidence=0.85,
                            attacker=frontrun_tx.from_addr,
                            victim=victim_tx.from_addr,
                            profit_estimate=profit,
                            tx_hashes=[frontrun_tx.hash, victim_tx.hash, backrun_tx.hash],
                            description=f"Sandwich detected: {frontrun_tx.hash[:10]}... → {victim_tx.hash[:10]}... → {backrun_tx.hash[:10]}..."
                        ))
                        break
    
    return results

def detect_frontrunning(txs: List[Transaction]) -> List[MEVResult]:
    """Detect frontrunning patterns."""
    results = []
    
    for i, tx in enumerate(txs):
        for prev_tx in txs[:i]:
            if (prev_tx.from_addr != tx.from_addr and
                prev_tx.input_data[:10] == tx.input_data[:10] and
                prev_tx.gas_price > tx.gas_price * 1.1):  # 10% higher gas
                
                results.append(MEVResult(
                    mev_type=MEVType.FRONTRUN,
                    confidence=0.6,
                    attacker=prev_tx.from_addr,
                    victim=tx.from_addr,
                    profit_estimate=0,
                    tx_hashes=[prev_tx.hash, tx.hash],
                    description=f"Potential frontrun: {prev_tx.hash[:10]}... copied {tx.hash[:10]}..."
                ))
    
    return results

def analyze_transaction(tx: Transaction) -> Dict:
    """Analyze a single transaction for MEV indicators."""
    func_name = decode_function_selector(tx.input_data)
    
    analysis = {
        "hash": tx.hash,
        "function": func_name,
        "gas_price_gwei": tx.gas_price / 1e9,
        "value_eth": tx.value / 1e18,
        "is_swap": tx.input_data[:10].lower() in DEX_SIGNATURES,
        "is_lp_action": tx.input_data[:10].lower() in {
            "0xe8e33700", "0xf305d719", "0xbaa2abde", "0x02751cec"
        },
    }
    
    return analysis

def format_report(results: List[MEVResult]) -> str:
    """Format MEV detection results as markdown report."""
    if not results:
        return "No MEV activity detected."
    
    report = f"# MEV Analysis Report\n\n"
    report += f"**Detected:** {len(results)} MEV transactions\n\n"
    
    for r in results:
        icon = {"sandwich": "🥪", "frontrun": "🏃", "arbitrage": "⚡", "jit_liquidity": "💧"}.get(r.mev_type.value, "🔍")
        report += f"## {icon} {r.mev_type.value.upper()}\n"
        report += f"- **Confidence:** {r.confidence*100:.0f}%\n"
        report += f"- **Attacker:** `{r.attacker[:20]}...`\n"
        if r.victim:
            report += f"- **Victim:** `{r.victim[:20]}...`\n"
        report += f"- **Profit:** ~{r.profit_estimate:.4f} ETH\n"
        report += f"- **Txs:** {' → '.join(f'`{h[:10]}...`' for h in r.tx_hashes)}\n"
        report += f"- {r.description}\n\n"
    
    return report

if __name__ == "__main__":
    print("MEV Transaction Analyzer v0.1")
    print("Use --help for usage information")
    print(f"\nSupported DEX signatures: {len(DEX_SIGNATURES) + len(UNISWAP_V3_SIGNATURES)}")
