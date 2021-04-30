import json
import os.path
import unittest

from neo3 import wallet
from neo3.wallet.wallet import Wallet


class WalletCreationTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_wallet_new_wallet(self):
        wallet_file_name = 'new_wallet'
        wallet_file_path = '{0}.json'.format(wallet_file_name)

        # remove the file if it exists for proper testing
        if os.path.isfile(wallet_file_path):
            os.remove(wallet_file_path)

        test_wallet = Wallet.new_wallet(wallet_file_name)
        scrypt_parameters_default = wallet.ScryptParameters()

        self.assertEqual(wallet_file_name, test_wallet.name)
        self.assertEqual('3.0', test_wallet.version)
        self.assertEqual(scrypt_parameters_default.n, test_wallet.scrypt.n)
        self.assertEqual(scrypt_parameters_default.r, test_wallet.scrypt.r)
        self.assertEqual(scrypt_parameters_default.p, test_wallet.scrypt.p)
        self.assertEqual([], test_wallet.accounts)
        self.assertEqual(None, test_wallet.extra)

        # if the target file is not a json, it should fail
        with self.assertRaises(ValueError):
            test_wallet = Wallet.new_wallet('{0}.txt'.format(wallet_file_name))

        # if the file exists, it should fail
        with self.assertRaises(FileExistsError):
            test_wallet = Wallet.new_wallet(wallet_file_name)

        # unless the user wants to overwrite it
        test_wallet = Wallet.new_wallet(wallet_file_name, overwrite_if_exists=True)
        self.assertEqual(wallet_file_name, test_wallet.name)
        self.assertEqual('3.0', test_wallet.version)
        self.assertEqual(scrypt_parameters_default.n, test_wallet.scrypt.n)
        self.assertEqual(scrypt_parameters_default.r, test_wallet.scrypt.r)
        self.assertEqual(scrypt_parameters_default.p, test_wallet.scrypt.p)
        self.assertEqual(scrypt_parameters_default.length, test_wallet.scrypt.length)
        self.assertEqual([], test_wallet.accounts)
        self.assertEqual(None, test_wallet.extra)

    def test_wallet_default_value(self):
        test_wallet = Wallet.default()
        scrypt_parameters_default = wallet.ScryptParameters()

        self.assertEqual('wallet.json', test_wallet.name)
        self.assertEqual('3.0', test_wallet.version)
        self.assertEqual(scrypt_parameters_default.n, test_wallet.scrypt.n)
        self.assertEqual(scrypt_parameters_default.r, test_wallet.scrypt.r)
        self.assertEqual(scrypt_parameters_default.p, test_wallet.scrypt.p)
        self.assertEqual([], test_wallet.accounts)
        self.assertEqual(None, test_wallet.extra)

    def test_wallet_save(self):
        test_wallet = Wallet.default('wallet_save.json', 'NEP6 Wallet')
        test_wallet.save()
        self.assertTrue(os.path.isfile('wallet_save.json'))

        with open('wallet_save.json') as json_file:
            data = json.load(json_file)
        self.assertEqual(data['name'], test_wallet.name)
        self.assertEqual(data['version'], test_wallet.version)
        self.assertEqual(data['scrypt']['n'], test_wallet.scrypt.n)
        self.assertEqual(data['scrypt']['r'], test_wallet.scrypt.r)
        self.assertEqual(data['scrypt']['p'], test_wallet.scrypt.p)
        self.assertEqual(data['accounts'], test_wallet.accounts)
        self.assertEqual(data['extra'], test_wallet.extra)
