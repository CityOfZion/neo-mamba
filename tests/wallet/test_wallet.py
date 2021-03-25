import unittest
from neo3.wallet import Wallet, ScryptParameters
import os.path
import json


class WalletCreationTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_wallet_default_value(self):
        wallet = Wallet.default('wallet.json')
        self.assertEqual(None, wallet.name)
        self.assertEqual('3.0', wallet.version)
        self.assertEqual(ScryptParameters.default().n, wallet.scrypt.n)
        self.assertEqual(ScryptParameters.default().r, wallet.scrypt.r)
        self.assertEqual(ScryptParameters.default().p, wallet.scrypt.p)
        self.assertEqual([], wallet.accounts)
        self.assertEqual(None, wallet.extra)

    def test_wallet_save(self):
        wallet = Wallet.default('wallet_save.json', 'NEP6 Wallet')
        wallet.save()
        self.assertTrue(os.path.isfile('wallet_save.json'))

        with open('wallet_save.json') as json_file:
            data = json.load(json_file)
        self.assertEqual(data['name'], wallet.name)
        self.assertEqual(data['version'], wallet.version)
        self.assertEqual(data['scrypt']['n'], wallet.scrypt.n)
        self.assertEqual(data['scrypt']['r'], wallet.scrypt.r)
        self.assertEqual(data['scrypt']['p'], wallet.scrypt.p)
        self.assertEqual(data['accounts'], wallet.accounts)
        self.assertEqual(data['extra'], wallet.extra)

    def test_wallet_load(self):
        wallet = Wallet.default('wallet_load.json', 'NEP6 Wallet')
        wallet.save()
        self.assertTrue(os.path.isfile('wallet_load.json'))

        wallet_loaded = Wallet.from_file('wallet_load.json')
        self.assertEqual(wallet.name, wallet_loaded.name)
        self.assertEqual(wallet.version, wallet_loaded.version)
        self.assertEqual(wallet.scrypt.n, wallet_loaded.scrypt.n)
        self.assertEqual(wallet.scrypt.r, wallet_loaded.scrypt.r)
        self.assertEqual(wallet.scrypt.p, wallet_loaded.scrypt.p)
        self.assertEqual(wallet.accounts, wallet_loaded.accounts)
        self.assertEqual(wallet.extra, wallet_loaded.extra)

        with open('wallet_load.json') as json_file:
            data = json.load(json_file)
        wallet_loaded_json = Wallet.from_json(data)
        self.assertEqual(wallet.name, wallet_loaded_json.name)
        self.assertEqual(wallet.version, wallet_loaded_json.version)
        self.assertEqual(wallet.scrypt.n, wallet_loaded_json.scrypt.n)
        self.assertEqual(wallet.scrypt.r, wallet_loaded_json.scrypt.r)
        self.assertEqual(wallet.scrypt.p, wallet_loaded_json.scrypt.p)
        self.assertEqual(wallet.accounts, wallet_loaded_json.accounts)
        self.assertEqual(wallet.extra, wallet_loaded_json.extra)
