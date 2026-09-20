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


class AccountTokenManagementTestCase(unittest.TestCase):
    def test_token_add_new(self):
        """Test adding a new token to an account."""
        from neo3.core.types import UInt160

        acc = account.Account.create_new()
        token_hash = UInt160.from_string("d2a4cff31913016155e38e474a2c06d08be276cf")

        result = acc.token_add(token_hash, "TestToken")
        self.assertTrue(result)
        self.assertIn("tokens", acc.extra)
        self.assertEqual(len(acc.extra["tokens"]), 1)
        self.assertEqual(acc.extra["tokens"][0]["hash"], str(token_hash))
        self.assertEqual(acc.extra["tokens"][0]["name"], "TestToken")

    def test_token_add_duplicate(self):
        """Test that adding the same token twice returns False."""
        from neo3.core.types import UInt160

        acc = account.Account.create_new()
        token_hash = UInt160.from_string("d2a4cff31913016155e38e474a2c06d08be276cf")

        result1 = acc.token_add(token_hash, "TestToken")
        self.assertTrue(result1)

        result2 = acc.token_add(token_hash, "TestToken")
        self.assertFalse(result2)
        self.assertEqual(len(acc.extra["tokens"]), 1)

    def test_token_delete_existing(self):
        """Test deleting an existing token."""
        from neo3.core.types import UInt160

        acc = account.Account.create_new()
        token_hash = UInt160.from_string("d2a4cff31913016155e38e474a2c06d08be276cf")

        acc.token_add(token_hash, "TestToken")
        result = acc.token_delete(token_hash)
        self.assertTrue(result)
        self.assertEqual(len(acc.extra["tokens"]), 0)

    def test_token_delete_nonexistent(self):
        """Test deleting a token that doesn't exist."""
        from neo3.core.types import UInt160

        acc = account.Account.create_new()
        token_hash = UInt160.from_string("d2a4cff31913016155e38e474a2c06d08be276cf")

        result = acc.token_delete(token_hash)
        self.assertFalse(result)

    def test_token_delete_empty_list(self):
        """Test deleting from an account with no tokens."""
        from neo3.core.types import UInt160

        acc = account.Account.create_new()
        token_hash = UInt160.from_string("d2a4cff31913016155e38e474a2c06d08be276cf")

        result = acc.token_delete(token_hash)
        self.assertFalse(result)

    def test_token_add_multiple(self):
        """Test adding multiple different tokens."""
        from neo3.core.types import UInt160

        acc = account.Account.create_new()
        token_hash1 = UInt160.from_string("d2a4cff31913016155e38e474a2c06d08be276cf")
        token_hash2 = UInt160.from_string("ef4073a0f2b305a38ec4050e4d3d28bc40ea63f5")

        acc.token_add(token_hash1, "Token1")
        acc.token_add(token_hash2, "Token2")

        self.assertEqual(len(acc.extra["tokens"]), 2)
        self.assertEqual(acc.extra["tokens"][0]["hash"], str(token_hash1))
        self.assertEqual(acc.extra["tokens"][0]["name"], "Token1")
        self.assertEqual(acc.extra["tokens"][1]["hash"], str(token_hash2))
        self.assertEqual(acc.extra["tokens"][1]["name"], "Token2")

    def test_token_delete_by_name(self):
        """Test deleting a token by its name."""
        from neo3.core.types import UInt160

        acc = account.Account.create_new()
        token_hash1 = UInt160.from_string("d2a4cff31913016155e38e474a2c06d08be276cf")
        token_hash2 = UInt160.from_string("ef4073a0f2b305a38ec4050e4d3d28bc40ea63f5")

        acc.token_add(token_hash1, "Token1")
        acc.token_add(token_hash2, "Token2")

        result = acc.token_delete_by_name("Token1")
        self.assertTrue(result)
        self.assertEqual(len(acc.extra["tokens"]), 1)
        self.assertEqual(acc.extra["tokens"][0]["name"], "Token2")

    def test_token_delete_by_name_nonexistent(self):
        """Test deleting a token by name that doesn't exist."""
        from neo3.core.types import UInt160

        acc = account.Account.create_new()
        token_hash = UInt160.from_string("d2a4cff31913016155e38e474a2c06d08be276cf")

        acc.token_add(token_hash, "TestToken")

        result = acc.token_delete_by_name("NonExistent")
        self.assertFalse(result)
        self.assertEqual(len(acc.extra["tokens"]), 1)

    def test_token_persistence_in_json(self):
        """Test that tokens are persisted when converting to/from JSON."""
        from neo3.core.types import UInt160

        acc = account.Account.create_new()
        token_hash = UInt160.from_string("d2a4cff31913016155e38e474a2c06d08be276cf")
        acc.token_add(token_hash, "TestToken")

        password = "test_password"
        json_data = acc.to_json(password)

        # Verify tokens are in JSON
        self.assertIn("extra", json_data)
        self.assertIn("tokens", json_data["extra"])
        self.assertEqual(len(json_data["extra"]["tokens"]), 1)
        self.assertEqual(json_data["extra"]["tokens"][0]["hash"], str(token_hash))
        self.assertEqual(json_data["extra"]["tokens"][0]["name"], "TestToken")

        # Add isDefault field (normally added by Wallet class)
        json_data["isDefault"] = False

        # Load from JSON and verify tokens are restored
        acc2 = account.Account.from_json(json_data, password)
        self.assertIn("tokens", acc2.extra)
        self.assertEqual(len(acc2.extra["tokens"]), 1)
        self.assertEqual(acc2.extra["tokens"][0]["hash"], str(token_hash))
        self.assertEqual(acc2.extra["tokens"][0]["name"], "TestToken")
