# MEV Transaction Analyzer

Analyze Ethereum transactions for MEV activity — sandwich attacks, frontrunning, arbitrage, and liquidations.

## Features
- Decode raw transaction input data
- Detect sandwich attack patterns (frontrun-victim-backrun)
- Identify frontrunning via gas price analysis
- Flashbots bundle detection
- JIT liquidity identification
- Multi-chain support (ETH, Arbitrum, Base)

## Usage
```bash
# Analyze single transaction
python3 analyzer.py --tx 0xabc...def --chain ethereum

# Detect sandwich in block range
python3 analyzer.py --sandwich-scan --block 18000000-18000100 --chain ethereum

# Check for MEV on specific pair
python3 analyzer.py --pair WETH/USDC --block 18000000 --chain ethereum
```

## Detection Patterns
| Pattern | Description |
|---------|-------------|
| Sandwich | Frontrun + victim tx + backrun in same block |
| Frontrun | Higher gas price tx before target with same function |
| Arbitrage | Price difference exploitation across DEXes |
| JIT | Large LP add + swap + remove in same block |
| Liquidation | Collateral seizure after price oracle update |

## Setup
```bash
pip install -r requirements.txt
export ETH_RPC_URL="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
python3 analyzer.py --help
```
