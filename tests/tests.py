import unittest
import sys
import os

# Ajoutez dynamiquement la racine du projet au PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from mnemonicToWallet import GetUniqueMnemonic, mnemonic_to_seed, seed_to_master_key, generate_address_from_private_key

class TestWalletFunctions(unittest.TestCase):
    def test_get_unique_mnemonic(self):
        len_seeds = [12, 24]
        mnemonic = GetUniqueMnemonic(len_seeds)
        self.assertIsInstance(mnemonic, str)
        self.assertIn(len(mnemonic.split()), len_seeds)

    def test_mnemonic_to_seed(self):
        mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        passphrase = "test"
        seed = mnemonic_to_seed(mnemonic, passphrase)
        self.assertEqual(len(seed), 64)

    def test_seed_to_master_key(self):
        seed = b"0" * 64
        master_key, chain_code = seed_to_master_key(seed)
        self.assertEqual(len(master_key), 32)
        self.assertEqual(len(chain_code), 32)

    def test_generate_address(self):
        private_key = b"1" * 32
        address = generate_address_from_private_key(private_key)
        self.assertIsInstance(address, str)
        self.assertTrue(address.startswith("1"))

if __name__ == "__main__":
    unittest.main()
