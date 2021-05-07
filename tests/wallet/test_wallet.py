import json
import os.path
import unittest

from neo3 import wallet
from neo3.wallet import nep6
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

        test_wallet = nep6.NEP6Wallet.new_wallet(wallet_file_name)
        scrypt_parameters_default = wallet.ScryptParameters()

        self.assertEqual(wallet_file_name, test_wallet.name)
        self.assertEqual('3.0', test_wallet.version)
        self.assertEqual(scrypt_parameters_default.n, test_wallet.scrypt.n)
        self.assertEqual(scrypt_parameters_default.r, test_wallet.scrypt.r)
        self.assertEqual(scrypt_parameters_default.p, test_wallet.scrypt.p)
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
        wallet_path = 'wallet_save.json'
        # remove the file if it exists for proper testing
        if os.path.isfile(wallet_path):
            os.remove(wallet_path)

        test_wallet = nep6.NEP6Wallet.default(wallet_path, 'NEP6 Wallet')
        test_wallet.save()
        self.assertTrue(os.path.isfile(wallet_path))

        with open('wallet_save.json') as json_file:
            data = json.load(json_file)
        self.assertEqual(data['name'], test_wallet.name)
        self.assertEqual(data['version'], test_wallet.version)
        self.assertEqual(data['scrypt']['n'], test_wallet.scrypt.n)
        self.assertEqual(data['scrypt']['r'], test_wallet.scrypt.r)
        self.assertEqual(data['scrypt']['p'], test_wallet.scrypt.p)
        self.assertEqual(data['accounts'], test_wallet.accounts)
        self.assertEqual(data['extra'], test_wallet.extra)

        default_path = Wallet._default_path
        # remove the file if it exists for proper testing
        if os.path.isfile(default_path):
            os.remove(default_path)

        # if the wallet class doesn't override `save` method, it shouldn't persist
        test_wallet = Wallet(name='Test Save Wallet')
        test_wallet.save()
        self.assertFalse(os.path.isfile(default_path))

        # remove the file if it exists for proper testing
        if os.path.isfile(wallet_path):
            os.remove(wallet_path)

        # save using context manager
        with nep6.NEP6Wallet.default(wallet_path, 'NEP6 Wallet'):
            pass
        self.assertTrue(os.path.isfile(wallet_path))

    def test_wallet_create_without_persisting(self):
        default_path = Wallet._default_path

        # remove the file if it exists for proper testing
        if os.path.isfile(default_path):
            os.remove(default_path)

        wallet_name = 'Wallet without persisting'
        scrypt_parameters_default = wallet.ScryptParameters()

        with Wallet(name=wallet_name) as test_wallet:
            self.assertEqual(wallet_name, test_wallet.name)
            self.assertEqual('3.0', test_wallet.version)
            self.assertEqual(scrypt_parameters_default.n, test_wallet.scrypt.n)
            self.assertEqual(scrypt_parameters_default.r, test_wallet.scrypt.r)
            self.assertEqual(scrypt_parameters_default.p, test_wallet.scrypt.p)
            self.assertEqual([], test_wallet.accounts)
            self.assertEqual(None, test_wallet.extra)

        # it shouldn't persist the wallet
        self.assertFalse(os.path.isfile(default_path))
