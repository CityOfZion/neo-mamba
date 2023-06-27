import json
import os.path
import unittest

from neo3.wallet import wallet, scrypt_parameters as scrypt, account


class WalletCreationTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_wallet_new_wallet(self):
        wallet_file_name = "unittest-wallet"
        wallet_file_path = f"{wallet_file_name}.json"

        # remove the file if it exists for proper testing
        if os.path.isfile(wallet_file_path):
            os.remove(wallet_file_path)

        test_wallet = wallet.DiskWallet(wallet_file_name)
        scrypt_parameters_default = scrypt.ScryptParameters()

        self.assertEqual(wallet_file_name, test_wallet.name)
        self.assertEqual("1.0", test_wallet.version)
        self.assertEqual(scrypt_parameters_default.n, test_wallet.scrypt.n)
        self.assertEqual(scrypt_parameters_default.r, test_wallet.scrypt.r)
        self.assertEqual(scrypt_parameters_default.p, test_wallet.scrypt.p)
        self.assertEqual([], test_wallet.accounts)
        self.assertEqual({}, test_wallet.extra)

    def test_wallet_default_value(self):
        test_wallet = wallet.DiskWallet.default()
        scrypt_parameters_default = scrypt.ScryptParameters()

        self.assertEqual("wallet.json", test_wallet.name)
        self.assertEqual("1.0", test_wallet.version)
        self.assertEqual(scrypt_parameters_default.n, test_wallet.scrypt.n)
        self.assertEqual(scrypt_parameters_default.r, test_wallet.scrypt.r)
        self.assertEqual(scrypt_parameters_default.p, test_wallet.scrypt.p)
        self.assertEqual([], test_wallet.accounts)
        self.assertEqual({}, test_wallet.extra)

    def test_wallet_save(self):
        wallet_path = "unittest-wallet-save.json"
        # remove the file if it exists for proper testing
        if os.path.isfile(wallet_path):
            os.remove(wallet_path)

        test_wallet = wallet.DiskWallet.default(wallet_path, "NEP6 Wallet")
        test_wallet.save()
        self.assertTrue(os.path.isfile(wallet_path))

        with open(wallet_path) as json_file:
            data = json.load(json_file)

        self.assertEqual(data["name"], test_wallet.name)
        self.assertEqual(data["version"], test_wallet.version)
        self.assertEqual(data["scrypt"]["n"], test_wallet.scrypt.n)
        self.assertEqual(data["scrypt"]["r"], test_wallet.scrypt.r)
        self.assertEqual(data["scrypt"]["p"], test_wallet.scrypt.p)
        self.assertEqual(data["accounts"], test_wallet.accounts)
        self.assertEqual({}, test_wallet.extra)
        self.assertEqual(None, data["extra"])

        # remove the file if it exists for proper testing
        if os.path.isfile(wallet_path):
            os.remove(wallet_path)

        # save using context manager
        with wallet.DiskWallet.default(wallet_path, "NEP6 Wallet"):
            pass
        self.assertTrue(os.path.isfile(wallet_path))

        # clean up after test
        if os.path.isfile(wallet_path):
            os.remove(wallet_path)

    def test_wallet_from_json(self):
        password = "123"

        new_wallet = wallet.DiskWallet.default()
        # override scrypt parameters for testing
        new_wallet.scrypt = scrypt.ScryptParameters(2, 8, 8)
        test_account = account.Account.create_new(
            password, scrypt_parameters=scrypt.ScryptParameters(2, 8, 8)
        )
        new_wallet.account_add(test_account, is_default=True)

        json_wallet = new_wallet.to_json()

        test_wallet = wallet.Wallet.from_json(json_wallet, passwords=["123"])
        self.assertEqual(new_wallet.name, test_wallet.name)
        self.assertEqual("1.0", test_wallet.version)
        self.assertEqual(1, len(test_wallet.accounts))
        self.assertEqual(test_account, test_wallet.accounts[0])
        self.assertEqual(test_wallet._default_account, test_wallet.accounts[0])

    def test_wallet_account_new(self):
        password = "abcabc"
        test_wallet = wallet.DiskWallet.default()
        # override scrypt parameters for testing
        test_wallet.scrypt = scrypt.ScryptParameters(2, 8, 8)
        self.assertEqual(0, len(test_wallet.accounts))

        # create account without label
        acc = test_wallet.account_new(password)
        self.assertEqual(1, len(test_wallet.accounts))
        self.assertEqual(None, acc.label)
        self.assertEqual(test_wallet._default_account, acc)

        # create account with label
        label = "New Account"
        acc = test_wallet.account_new(password, label)
        self.assertEqual(2, len(test_wallet.accounts))
        self.assertEqual(label, acc.label)
        self.assertNotEqual(test_wallet._default_account, acc)

        # create account with duplicated label
        with self.assertRaises(ValueError) as context:
            test_wallet.account_new(password, label)
        self.assertIn("Label is already used by an account", str(context.exception))

        # create account and set as default
        label = "Other Account"
        acc = test_wallet.account_new(password, label, is_default=True)
        self.assertEqual(3, len(test_wallet.accounts))
        self.assertEqual(label, acc.label)
        self.assertEqual(test_wallet._default_account, acc)

    def test_wallet_account_add(self):
        password = "abcabc"
        test_wallet = wallet.DiskWallet.default()

        self.assertEqual(0, len(test_wallet.accounts))

        scryptp = scrypt.ScryptParameters(2, 8, 8)
        label = "New Account"
        account_1 = account.Account(password=password, scrypt_parameters=scryptp)
        account_2 = account.Account(
            password=password, label=label, scrypt_parameters=scryptp
        )
        account_3 = account.Account(password=password)
        account_4 = account.Account(
            password=password, label=label, scrypt_parameters=scryptp
        )

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
        with self.assertRaises(ValueError) as context:
            test_wallet.account_add(account_4)
        self.assertIn("Label is already used by an account", str(context.exception))

    def test_wallet_account_delete(self):
        scryptp = scrypt.ScryptParameters(2, 8, 8)
        password = "abcabc"
        account_1 = account.Account(password=password, scrypt_parameters=scryptp)
        account_2 = account.Account(password=password, scrypt_parameters=scryptp)
        account_3 = account.Account(password=password, scrypt_parameters=scryptp)

        test_wallet = wallet.DiskWallet.default()
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
        label_1 = "Account 1"
        label_2 = "Account 2"
        label_not_used = "Account 3"

        password = "123123"
        scryptp = scrypt.ScryptParameters(2, 8, 8)
        account_1 = account.Account(
            password=password, label=label_1, scrypt_parameters=scryptp
        )
        account_2 = account.Account(
            password=password, label=label_2, scrypt_parameters=scryptp
        )
        account_3 = account.Account(password=password, scrypt_parameters=scryptp)

        test_wallet = wallet.DiskWallet.default()
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
        p = os.path.join(os.path.dirname(__file__), "rc2-wallet.json")
        with open(p) as f:
            data = json.load(f)

        w = wallet.Wallet.from_json(data, ["123", "123"])
        self.assertEqual(2, len(w.accounts))
        self.assertEqual("NY9qiu8YScTM9oAc3nnaeNjaX5fnraaRTA", w.accounts[0].address)
        self.assertEqual("NcmoFiYqThZJFiEYVF1BjYEk6YwF5vtkFA", w.accounts[1].address)

    def test_from_json_with_multiple_accounts(self):
        label_1 = "Account 1"
        label_2 = "Account 2"

        password1 = "123123"
        password2 = "456456"
        scryptp = scrypt.ScryptParameters(2, 8, 8)
        account_1 = account.Account(
            password=password1, label=label_1, scrypt_parameters=scryptp
        )
        account_2 = account.Account(
            password=password2, label=label_2, scrypt_parameters=scryptp
        )
        w = wallet.Wallet(name="test wallet", scrypt_params=scryptp)
        w.account_add(account_1)
        w.account_add(account_2)
        w_json = w.to_json()

        # now test we can load it from_json
        w2_with_passwords = wallet.Wallet.from_json(w_json, [password1, password2])
        self.assertEqual(2, len(w2_with_passwords.accounts))
        self.assertFalse(w2_with_passwords.accounts[0].is_watchonly)
        self.assertFalse(w2_with_passwords.accounts[0].is_watchonly)

        w2_as_watchonly = wallet.Wallet.from_json(w_json)
        self.assertEqual(2, len(w2_with_passwords.accounts))
        self.assertTrue(w2_as_watchonly.accounts[0].is_watchonly)
        self.assertTrue(w2_as_watchonly.accounts[0].is_watchonly)

    def test_insufficient_passwords_provided_from_json(self):
        p = os.path.join(os.path.dirname(__file__), "rc2-wallet.json")
        with open(p) as f:
            data = json.load(f)

        with self.assertRaises(ValueError) as context:
            wallet.Wallet.from_json(data, ["123"])
        self.assertIn(
            "Incorrect number of passwords provided (1) for number of accounts in wallet (2)",
            str(context.exception),
        )
