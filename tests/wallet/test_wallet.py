import json
import os.path
import unittest

from neo3.wallet.wallet import ScryptParameters, Wallet


class WalletCreationTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_wallet_new_wallet(self):
        wallet_file_name = 'test_wallet'
        wallet_file_path = '{0}.json'.format(wallet_file_name)

        # remove the file if it exists for proper testing
        if os.path.isfile(wallet_file_path):
            os.remove(wallet_file_path)

        wallet = Wallet.new_wallet(wallet_file_name)
        self.assertEqual(wallet_file_name, wallet.name)
        self.assertEqual('3.0', wallet.version)
        self.assertEqual(ScryptParameters.default().n, wallet.scrypt.n)
        self.assertEqual(ScryptParameters.default().r, wallet.scrypt.r)
        self.assertEqual(ScryptParameters.default().p, wallet.scrypt.p)
        self.assertEqual([], wallet.accounts)
        self.assertEqual(None, wallet.extra)

        # if the file exists, it should return None
        wallet = Wallet.new_wallet(wallet_file_name)
        self.assertIsNone(wallet)

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
