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
        wallet_file_name = 'unittest-wallet'
        wallet_file_path = f"{wallet_file_name}.json"

        # remove the file if it exists for proper testing
        if os.path.isfile(wallet_file_path):
            os.remove(wallet_file_path)

        test_wallet = nep6.NEP6DiskWallet(wallet_file_name)
        scrypt_parameters_default = wallet.ScryptParameters()

        self.assertEqual(wallet_file_name, test_wallet.name)
        self.assertEqual('1.0', test_wallet.version)
        self.assertEqual(scrypt_parameters_default.n, test_wallet.scrypt.n)
        self.assertEqual(scrypt_parameters_default.r, test_wallet.scrypt.r)
        self.assertEqual(scrypt_parameters_default.p, test_wallet.scrypt.p)
        self.assertEqual([], test_wallet.accounts)
        self.assertEqual({}, test_wallet.extra)

    def test_wallet_default_value(self):
        test_wallet = nep6.NEP6DiskWallet.default()
        scrypt_parameters_default = wallet.ScryptParameters()

        self.assertEqual('wallet.json', test_wallet.name)
        self.assertEqual('1.0', test_wallet.version)
        self.assertEqual(scrypt_parameters_default.n, test_wallet.scrypt.n)
        self.assertEqual(scrypt_parameters_default.r, test_wallet.scrypt.r)
        self.assertEqual(scrypt_parameters_default.p, test_wallet.scrypt.p)
        self.assertEqual([], test_wallet.accounts)
        self.assertEqual({}, test_wallet.extra)

    def test_wallet_save(self):
        wallet_path = 'unittest-wallet-save.json'
        # remove the file if it exists for proper testing
        if os.path.isfile(wallet_path):
            os.remove(wallet_path)

        test_wallet = nep6.NEP6DiskWallet.default(wallet_path, 'NEP6 Wallet')
        test_wallet.save()
        self.assertTrue(os.path.isfile(wallet_path))

        with open(wallet_path) as json_file:
            data = json.load(json_file)

        self.assertEqual(data['name'], test_wallet.name)
        self.assertEqual(data['version'], test_wallet.version)
        self.assertEqual(data['scrypt']['n'], test_wallet.scrypt.n)
        self.assertEqual(data['scrypt']['r'], test_wallet.scrypt.r)
        self.assertEqual(data['scrypt']['p'], test_wallet.scrypt.p)
        self.assertEqual(data['accounts'], test_wallet.accounts)
        self.assertEqual({}, test_wallet.extra)
        self.assertEqual(None, data['extra'])

        # remove the file if it exists for proper testing
        if os.path.isfile(wallet_path):
            os.remove(wallet_path)

        # save using context manager
        with nep6.NEP6DiskWallet.default(wallet_path, 'NEP6 Wallet'):
            pass
        self.assertTrue(os.path.isfile(wallet_path))

        # clean up after test
        if os.path.isfile(wallet_path):
            os.remove(wallet_path)

    def test_wallet_from_json(self):
        password = '123'

        new_wallet = nep6.NEP6DiskWallet.default()
        test_account = wallet.Account.create_new(password)
        new_wallet.accounts.append(test_account)
        new_wallet._default_account = test_account

        json_wallet = new_wallet.to_json()

        test_wallet = Wallet.from_json(json_wallet, password='123')
        self.assertEqual(new_wallet.name, test_wallet.name)
        self.assertEqual('1.0', test_wallet.version)
        self.assertEqual(1, len(test_wallet.accounts))
        self.assertEqual(test_account, test_wallet.accounts[0])
        self.assertEqual(test_wallet._default_account, test_wallet.accounts[0])

    def test_wallet_account_new(self):
        password = 'abcabc'
        wallet = nep6.NEP6DiskWallet.default()
        self.assertEqual(0, len(wallet.accounts))

        # create account without label
        account = wallet.account_new(password)
        self.assertEqual(1, len(wallet.accounts))
        self.assertEqual(None, account.label)
        self.assertEqual(wallet._default_account, account)

        # create account with label
        label = 'New Account'
        account = wallet.account_new(password, label)
        self.assertEqual(2, len(wallet.accounts))
        self.assertEqual(label, account.label)
        self.assertNotEqual(wallet._default_account, account)

        # create account with duplicated label
        with self.assertRaises(ValueError):
            # label already used
            wallet.account_new(password, label)

        # create account and set as default
        label = 'Other Account'
        account = wallet.account_new(password, label, is_default=True)
        self.assertEqual(3, len(wallet.accounts))
        self.assertEqual(label, account.label)
        self.assertEqual(wallet._default_account, account)

    def test_wallet_account_add(self):
        password = 'abcabc'
        test_wallet = nep6.NEP6DiskWallet.default()
        self.assertEqual(0, len(test_wallet.accounts))

        label = 'New Account'
        account_1 = wallet.Account(password=password)
        account_2 = wallet.Account(password=password,
                                   label=label)
        account_3 = wallet.Account(password=password)
        account_4 = wallet.Account(password=password,
                                   label=label)

        # add account, first account is set as default
        success = test_wallet.account_add(account_1)
        self.assertTrue(success)
        self.assertEqual(1, len(test_wallet.accounts))
        self.assertEqual(test_wallet._default_account, account_1)

        # add account
        success = test_wallet.account_add(account_2)
        self.assertTrue(success)
        self.assertEqual(2, len(test_wallet.accounts))
        self.assertNotEqual(test_wallet._default_account, account_2)

        # add account already added
        success = test_wallet.account_add(account_2)
        self.assertFalse(success)

        # add account and set it as default
        success = test_wallet.account_add(account_3, is_default=True)
        self.assertTrue(success)
        self.assertEqual(3, len(test_wallet.accounts))
        self.assertEqual(test_wallet._default_account, account_3)

        # add account with duplicated label
        with self.assertRaises(ValueError):
            # label already used
            test_wallet.account_add(account_4)

    def test_wallet_account_delete(self):
        password = 'abcabc'
        account_1 = wallet.Account(password=password)
        account_2 = wallet.Account(password=password)
        account_3 = wallet.Account(password=password)

        test_wallet = nep6.NEP6DiskWallet.default()
        test_wallet.account_add(account_1)
        test_wallet.account_add(account_2)
        test_wallet.account_add(account_3)

        self.assertEqual(account_1, test_wallet._default_account)

        # delete account that is not default
        success = test_wallet.account_delete(account_2)
        self.assertTrue(success)
        self.assertEqual(account_1, test_wallet._default_account)

        # delete account not included
        success = test_wallet.account_delete(account_2)
        self.assertFalse(success)

        # delete account default, with other existing
        success = test_wallet.account_delete(account_1)
        self.assertTrue(success)
        self.assertNotEqual(account_1, test_wallet._default_account)
        self.assertEqual(account_3, test_wallet._default_account)

        # delete account default and it's the only existing account
        success = test_wallet.account_delete(account_3)
        self.assertTrue(success)
        self.assertIsNone(test_wallet._default_account)

    def test_wallet_account_delete_by_label(self):
        label_1 = 'Account 1'
        label_2 = 'Account 2'
        label_not_used = 'Account 3'

        password = '123123'
        account_1 = wallet.Account(password=password,
                                   label=label_1)
        account_2 = wallet.Account(password=password,
                                   label=label_2)
        account_3 = wallet.Account(password=password)

        test_wallet = nep6.NEP6DiskWallet.default()
        test_wallet.account_add(account_1)
        test_wallet.account_add(account_2)
        test_wallet.account_add(account_3)

        self.assertEqual(account_1, test_wallet._default_account)

        # delete by label when account is not the default
        success = test_wallet.account_delete_by_label(label_2)
        self.assertTrue(success)
        self.assertEqual(account_1, test_wallet._default_account)

        # delete label not included
        success = test_wallet.account_delete_by_label(label_not_used)
        self.assertFalse(success)

        # delete by label when account is default
        success = test_wallet.account_delete_by_label(label_1)
        self.assertTrue(success)
        self.assertNotEqual(account_1, test_wallet._default_account)
        self.assertEqual(account_3, test_wallet._default_account)

    def test_from_json_with_multisig_account(self):
        p = os.path.join(os.path.dirname(__file__), 'rc2-wallet.json')
        with open(p) as f:
            data = json.load(f)

        w = wallet.Wallet.from_json(data, '123')
        self.assertEqual(2, len(w.accounts))
        self.assertEqual("NY9qiu8YScTM9oAc3nnaeNjaX5fnraaRTA", w.accounts[0].address)
        self.assertEqual("NcmoFiYqThZJFiEYVF1BjYEk6YwF5vtkFA", w.accounts[1].address)
