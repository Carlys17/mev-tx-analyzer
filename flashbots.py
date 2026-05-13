"""Flashbots bundle detection and analysis."""
FLASHBOTS_RELAY_URL = 'https://relay.flashbots.net'

class FlashbotsAnalyzer:
    def __init__(self, rpc_url):
        self.rpc_url = rpc_url

    def is_flashbots_tx(self, tx):
        return tx.get('gasPrice', 0) == 0

    def analyze_bundle(self, block_number):
        return []
