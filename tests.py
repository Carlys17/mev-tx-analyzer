"""Unit tests for the pattern detectors. Pure-Python, no I/O."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import unittest

from patterns import (
    SIGS, selector, func_name, is_swap, is_liquidity_op,
    is_zero_gas_price, detect_sandwich, detect_jit_liquidity, detect_liquidation,
)


def make_tx(**kw):
    base = {
        "hash": "0x" + "a" * 64,
        "from_addr": "0x" + "1" * 40,
        "to_addr":   "0x" + "2" * 40,
        "input": "0x" + "0" * 64,
        "value": 0,
        "gasPrice": 1_000_000_000,
        "gas": 200_000,
        "blockNumber": 1,
    }
    base.update(kw)
    return base


class TestSelector(unittest.TestCase):
    def test_returns_first_10_hex(self):
        t = make_tx(input="0xdeadbeef" + "0" * 56)
        self.assertEqual(selector(t), "0xdeadbeef")

    def test_short_input(self):
        self.assertEqual(selector(make_tx(input="")), "")
        self.assertEqual(selector(make_tx(input="0x")), "")


class TestFuncName(unittest.TestCase):
    def test_known(self):
        self.assertEqual(func_name(make_tx(input="0x" + "38ed1739" + "0" * 56)), "swapExactTokensForTokens")

    def test_unknown(self):
        self.assertEqual(func_name(make_tx(input="0x" + "ff" * 32)), "unknown")


class TestSwapAndLiq(unittest.TestCase):
    def test_is_swap(self):
        t = make_tx(input="0x38ed1739" + "0" * 200)
        self.assertTrue(is_swap(t))

    def test_is_liquidity_op(self):
        t = make_tx(input="0xe8e33700" + "0" * 200)
        self.assertTrue(is_liquidity_op(t))


class TestZeroGas(unittest.TestCase):
    def test_zero_is_flashbots(self):
        self.assertTrue(is_zero_gas_price(make_tx(gasPrice=0)))

    def test_nonzero_is_not(self):
        self.assertFalse(is_zero_gas_price(make_tx(gasPrice=1)))


class TestSandwich(unittest.TestCase):
    def test_detects_canonical_sandwich(self):
        a1 = make_tx(hash="0xa" * 64, from_addr="0xatt", to_addr="0xrouter", input="0x38ed1739" + "0" * 200, blockNumber=10)
        b  = make_tx(hash="0xb" * 64, from_addr="0xvic", to_addr="0xrouter", input="0x38ed1739" + "0" * 200, blockNumber=10)
        a2 = make_tx(hash="0xc" * 64, from_addr="0xatt", to_addr="0xrouter", input="0x38ed1739" + "0" * 200, blockNumber=10)
        s = detect_sandwich([a1, b, a2])
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0]["attacker"], "0xatt")
        self.assertEqual(s[0]["victim"], b["hash"])


class TestJit(unittest.TestCase):
    def test_add_remove_same_block(self):
        a = make_tx(hash="0x1" * 64, input="0xe8e33700" + "0" * 200, blockNumber=5)
        r = make_tx(hash="0x2" * 64, input="0xbaa2abde" + "0" * 200, blockNumber=5)
        out = detect_jit_liquidity([a, r])
        self.assertEqual(len(out), 1)


class TestLiquidation(unittest.TestCase):
    def test_settleAll(self):
        t = make_tx(input="0x1e9a6950" + "0" * 200)
        out = detect_liquidation([t])
        self.assertEqual(len(out), 1)


if __name__ == "__main__":
    unittest.main()
