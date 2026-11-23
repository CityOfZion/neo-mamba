import json
import unittest

from neo3.core import types
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
            acc = account.Account(scrypt_parameters=scrypt_params)
            self.assertIsNotNone(acc)
            self.assertIsNotNone(acc.address)
            self.assertIsNotNone(acc.private_key)
            self.assertIsNotNone(acc.public_key)

    def test_new_account_from_private_key(self):
        for testcase in account_list:
            scrypt_params = testcase.get("scrypt", None)
            if scrypt_params is not None:
                scrypt_params = scrypt.ScryptParameters.from_json(scrypt_params)
            acc = account.Account.from_private_key(
                bytes.fromhex(testcase["private_key"]), scrypt_params
            )
            self.assertEqual(testcase["address"], acc.address)
            self.assertEqual(
                testcase["encrypted_key"].encode("utf-8"),
                account.Account.private_key_to_nep2(
                    bytes.fromhex(testcase["private_key"]),
                    testcase["password"],
                    scrypt_params,
                ),
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
                testcase["encrypted_key"].encode("utf-8"),
                account.Account.private_key_to_nep2(
                    bytes.fromhex(testcase["private_key"]),
                    testcase["password"],
                    scrypt_params,
                ),
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
            self.assertIsNone(acc.private_key)
            self.assertEqual(testcase["script_hash"], str(acc.script_hash))
            self.assertIsNone(acc.public_key)
            self.assertTrue(acc.is_watchonly)

    def test_new_watch_only_account_from_address(self):
        for testcase in account_list[1:]:
            acc = account.Account.watch_only_from_address(testcase["address"])
            self.assertEqual(testcase["address"], acc.address)
            self.assertIsNone(acc.private_key)
            self.assertEqual(testcase["script_hash"], str(acc.script_hash))
            self.assertIsNone(acc.public_key)

    def test_new_account_from_wif(self):
        for testcase in account_list[:1]:
            scrypt_params = testcase.get("scrypt", None)
            if scrypt_params is not None:
                scrypt_params = scrypt.ScryptParameters.from_json(scrypt_params)

            acc = account.Account.from_wif(testcase["wif_key"], scrypt_params)
            self.assertEqual(testcase["address"], acc.address)
            self.assertEqual(
                testcase["encrypted_key"].encode("utf-8"),
                account.Account.private_key_to_nep2(
                    bytes.fromhex(testcase["private_key"]),
                    testcase["password"],
                    scrypt_params,
                ),
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

    def test_to_wif(self):
        wif = "L5kx9QRKG9dwzSJF72pgps1d2scJZjnECWoKuUGVsz2D1WRBEaJ7"
        acc = account.Account.from_wif(wif)
        self.assertEqual(wif, account.Account.private_key_to_wif(acc.private_key))


class AccountTokensTestCase(unittest.TestCase):
    GAS = types.UInt160.from_string("d2a4cff31913016155e38e474a2c06d08be276cf")
    NEO = types.UInt160.from_string("ef4073a0f2b305a38ec4050e4d3d28bc40ea63f5")

    def setUp(self):
        # low scrypt cost to keep the tests fast
        self.scrypt = scrypt.ScryptParameters(2, 8, 8)
        self.acc = account.Account.create_new(self.scrypt)

    def test_add(self):
        self.assertTrue(self.acc.token_add(self.GAS, "GAS"))
        self.assertEqual({self.GAS: "GAS"}, self.acc.extra["tokens"])

    def test_add_multiple(self):
        self.assertTrue(self.acc.token_add(self.GAS, "GAS"))
        self.assertTrue(self.acc.token_add(self.NEO, "NEO"))
        self.assertEqual({self.GAS: "GAS", self.NEO: "NEO"}, self.acc.extra["tokens"])

    def test_add_existing_is_rejected_and_keeps_the_name(self):
        self.acc.token_add(self.GAS, "GAS")
        self.assertFalse(self.acc.token_add(self.GAS, "other name"))
        self.assertEqual({self.GAS: "GAS"}, self.acc.extra["tokens"])

    def test_delete(self):
        self.acc.token_add(self.GAS, "GAS")
        self.acc.token_add(self.NEO, "NEO")
        self.assertTrue(self.acc.token_delete(self.GAS))
        self.assertEqual({self.NEO: "NEO"}, self.acc.extra["tokens"])

    def test_delete_unknown(self):
        self.acc.token_add(self.NEO, "NEO")
        self.assertFalse(self.acc.token_delete(self.GAS))
        self.assertEqual({self.NEO: "NEO"}, self.acc.extra["tokens"])

    def test_delete_without_tokens(self):
        self.assertFalse(self.acc.token_delete(self.GAS))
        self.assertNotIn("tokens", self.acc.extra)

    def test_delete_by_name(self):
        self.acc.token_add(self.GAS, "GAS")
        self.acc.token_add(self.NEO, "NEO")
        self.assertTrue(self.acc.token_delete_by_name("NEO"))
        self.assertEqual({self.GAS: "GAS"}, self.acc.extra["tokens"])

    def test_delete_by_name_unknown(self):
        self.acc.token_add(self.GAS, "GAS")
        self.assertFalse(self.acc.token_delete_by_name("NEO"))
        self.assertEqual({self.GAS: "GAS"}, self.acc.extra["tokens"])

    def test_delete_by_name_without_tokens(self):
        self.assertFalse(self.acc.token_delete_by_name("GAS"))
        self.assertNotIn("tokens", self.acc.extra)

    def test_delete_by_name_only_deletes_the_first_match(self):
        self.acc.token_add(self.GAS, "same")
        self.acc.token_add(self.NEO, "same")
        self.assertTrue(self.acc.token_delete_by_name("same"))
        self.assertEqual({self.NEO: "same"}, self.acc.extra["tokens"])

    def test_json_round_trip(self):
        self.acc.token_add(self.GAS, "GAS")
        self.acc.token_add(self.NEO, "NEO")

        data = self.acc.to_json("password", self.scrypt)
        # tokens must be storable in a wallet file
        self.assertEqual(
            {"tokens": {str(self.GAS): "GAS", str(self.NEO): "NEO"}},
            json.loads(json.dumps(data["extra"])),
        )

        data["isDefault"] = False  # added by the wallet, required by the schema
        loaded = account.Account.from_json(data, None)
        self.assertEqual({self.GAS: "GAS", self.NEO: "NEO"}, loaded.extra["tokens"])
        self.assertTrue(loaded.token_delete(self.GAS))

    def test_to_json_does_not_change_the_account(self):
        self.acc.token_add(self.GAS, "GAS")
        self.acc.to_json("password", self.scrypt)
        self.assertEqual({self.GAS: "GAS"}, self.acc.extra["tokens"])

    def test_json_without_extra(self):
        data = self.acc.to_json("password", self.scrypt)
        self.assertIsNone(data["extra"])
        data["isDefault"] = False
        self.assertEqual({}, account.Account.from_json(data, None).extra)

    def test_json_keeps_other_extra_data(self):
        self.acc.extra["other"] = {"a": 1}
        self.acc.token_add(self.GAS, "GAS")
        data = self.acc.to_json("password", self.scrypt)
        data["isDefault"] = False
        loaded = account.Account.from_json(data, None)
        self.assertEqual({"a": 1}, loaded.extra["other"])
        self.assertEqual({self.GAS: "GAS"}, loaded.extra["tokens"])

    def test_json_with_foreign_tokens_data_is_left_alone(self):
        # `extra` is free-form. Wallet files from other software could use
        # "tokens" for something else and must keep loading.
        data = self.acc.to_json("password", self.scrypt)
        data["extra"] = {"tokens": ["something", "else"]}
        data["isDefault"] = False
        loaded = account.Account.from_json(data, None)
        self.assertEqual(["something", "else"], loaded.extra["tokens"])
        self.assertEqual(
            {"tokens": ["something", "else"]},
            loaded.to_json("password", self.scrypt)["extra"],
        )
