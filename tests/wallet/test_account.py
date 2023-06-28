import unittest

from neo3.wallet import account, scrypt_parameters as scrypt

account_list = [
    {
        "address": "NRaKbRA5JAEJtfUgJJZzmeDnKvP3pJwKp1",
        "encrypted_key": "6PYKuriAL7pFeVTr3tKksbD1SpKUP7K82vjGuskZ5zpo9EWDhLRW6GcnyL",
        "password": "city of zion",
        "private_key": "58124574dfcca1a7a958775f6ea94e3d6c392ec3ba125b5bc591dd5e14f05e52",
        "script_hash": "18f13748e08d53c9a164227e1a3e8d8d9e78193e",
        "wif_key": "KzAuju4yBqBhmUzYpfEEppPW8jfxALTsdsUR8hLPv9R3PBD97CUv",
    },
    {
        "address": "NgPptMp2tcjnXuYbUrTozvwvLExGKk5jXc",
        "encrypted_key": "6PYMEujkLZiJrQ5AK9W4z1BtYZT2U27ZVKrjbEFt8zZh5CJANZdEx21Fyx",
        "password": "123",
        "private_key": "2032b737522d22e2b6faf30555faa91d95c5aa5113c18f218f45815b6934c558",
        "script_hash": "cfa9032d65b3d0fc1df3956a4ef01666f23ba7e0",
        "wif_key": "KxJJLmU1Nv7igx3RFM4siSvio7wasF3ZzMzi7SrJ1s78QDQeEtjs",
        "scrypt": {"n": 2, "r": 8, "p": 8},
    },
    {
        "address": "NZMHRJMPbyJJwtXpvS2mYAWcWp4qmZZFx8",
        "encrypted_key": "6PYL44vbRemjfwCJ8qprKKJJiuzcopnJhghPoMLRVJLpymDwm2BNj9v7fq",
        "password": "neo",
        "private_key": "4c5182d9041f416bee1a6adac6a03f3e0319a83e75e78e6ff739304095791f19",
        "script_hash": "0df27baba6baeeb6834bea0d6c2a78183b416393",
        "wif_key": "Kyn4fA6czAhktoAM9YXKv3m7jtt47AuQxCXqSusnBmj3GsZUZQ6M",
        "scrypt": {"n": 2, "r": 8, "p": 8},
    },
]


class AccountCreationTestCase(unittest.TestCase):
    def test_new_account(self):
        for testcase in account_list[1:]:
            scrypt_params = testcase.get("scrypt", None)
            if scrypt_params is not None:
                scrypt_params = scrypt.ScryptParameters.from_json(scrypt_params)
            acc = account.Account(testcase["password"], scrypt_parameters=scrypt_params)
            self.assertIsNotNone(acc)
            self.assertIsNotNone(acc.address)
            self.assertIsNotNone(acc.encrypted_key)
            self.assertIsNotNone(acc.public_key)

    def test_new_account_from_private_key(self):
        for testcase in account_list:
            scrypt_params = testcase.get("scrypt", None)
            if scrypt_params is not None:
                scrypt_params = scrypt.ScryptParameters.from_json(scrypt_params)
            acc = account.Account.from_private_key(
                bytes.fromhex(testcase["private_key"]),
                testcase["password"],
                scrypt_params,
            )
            self.assertEqual(testcase["address"], acc.address)
            self.assertEqual(
                testcase["encrypted_key"].encode("utf-8"), acc.encrypted_key
            )
            self.assertEqual(testcase["script_hash"], str(acc.script_hash))
            self.assertIsNotNone(acc.public_key)

    def test_new_account_from_encrypted_key(self):
        for testcase in account_list[1:]:
            scrypt_params = testcase.get("scrypt", None)
            if scrypt_params is not None:
                scrypt_params = scrypt.ScryptParameters.from_json(scrypt_params)

            acc = account.Account.from_encrypted_key(
                testcase["encrypted_key"], testcase["password"], scrypt_params
            )
            self.assertEqual(testcase["address"], acc.address)
            self.assertEqual(
                testcase["encrypted_key"].encode("utf-8"), acc.encrypted_key
            )
            self.assertEqual(testcase["script_hash"], str(acc.script_hash))
            self.assertIsNotNone(acc.public_key)

    def test_new_watch_only_account(self):
        from neo3.core.types import UInt160

        for testcase in account_list[1:]:
            acc = account.Account.watch_only(
                UInt160.from_string(testcase["script_hash"])
            )
            self.assertEqual(testcase["address"], acc.address)
            self.assertIsNone(acc.encrypted_key)
            self.assertEqual(testcase["script_hash"], str(acc.script_hash))
            self.assertIsNone(acc.public_key)
            self.assertTrue(acc.is_watchonly)

    def test_new_watch_only_account_from_address(self):
        for testcase in account_list[1:]:
            acc = account.Account.watch_only_from_address(testcase["address"])
            self.assertEqual(testcase["address"], acc.address)
            self.assertIsNone(acc.encrypted_key)
            self.assertEqual(testcase["script_hash"], str(acc.script_hash))
            self.assertIsNone(acc.public_key)

    def test_new_account_from_wif(self):
        for testcase in account_list[:1]:
            scrypt_params = testcase.get("scrypt", None)
            if scrypt_params is not None:
                scrypt_params = scrypt.ScryptParameters.from_json(scrypt_params)

            acc = account.Account.from_wif(
                testcase["wif_key"], testcase["password"], scrypt_params
            )
            self.assertEqual(testcase["address"], acc.address)
            self.assertEqual(
                testcase["encrypted_key"].encode("utf-8"), acc.encrypted_key
            )
            self.assertEqual(testcase["script_hash"], str(acc.script_hash))
            self.assertIsNotNone(acc.public_key)

    def test_new_account_wrong_password(self):
        for testcase in account_list:
            with self.assertRaises(ValueError) as context:
                account.Account.from_encrypted_key(
                    testcase["encrypted_key"], "wrong password"
                )
            self.assertIn("Wrong passphrase", str(context.exception))

    def test_new_account_no_password(self):
        with self.assertRaises(ValueError) as context:
            account.Account()
        self.assertIn(
            "Can't create an account without a password unless it is a watch only account",
            str(context.exception),
        )
