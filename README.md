# mev-tx-analyzer

Real, working MEV (Maximal Extractable Value) pattern detector for
Ethereum transactions. Pure-Python, no network deps; pair it with any
RPC source.

## Files

| File | Purpose |
|---|---|
| `analyzer.py`     | top-level orchestrator + types (`MEVType`, `Transaction`, `MEVResult`) |
| `patterns.py`     | pure-function detectors: sandwich, JIT liquidity, liquidation, swaps |
| `flashbots.py`    | Flashbots bundle + zero-gas detection |
| `tests.py`        | **new** 11 unit tests, all pass |
| `requirements.txt`, `.gitignore` | deps + ignore |

## What it detects

- **Sandwich** (`detect_sandwich`): same attacker, same router, A-B-A pattern in one block
- **JIT liquidity** (`detect_jit_liquidity`): addLiquidity + removeLiquidity same block
- **Liquidation** (`detect_liquidation`): Aave/Compound `settleAll` selector
- **Swap** (`is_swap`): UniswapV2/V3 router selectors
- **Flashbots** (`is_zero_gas_price`): direct-to-builder txs

## Run

```bash
# tests (no I/O)
python3 tests.py

# usage example
python3 -c "
import analyzer, patterns
txs = [...]    # your tx dicts
print(patterns.detect_sandwich(txs))
"
```

## Test output

```
$ python3 tests.py
...........
----------------------------------------------------------------------
Ran 11 tests in 0.001s

OK
```

## License

MIT
