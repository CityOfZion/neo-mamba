import unittest
from neo3.wallet import Account

# the accounts were generated using neo-cli v3.0.0-rc1
account_list = [
    {
        "address": "NM4Hq7DDaMrNvhhN16aDiS3fLxXaqjGePy",
        "encrypted_key": "6PYX6MzwNZHhxfUD82qTgATzUuGQgdajcnZQZuL5wKH77mo6JHLMB3o5zy",
        "password": "city of zion",
        "private_key": "58124574dfcca1a7a958775f6ea94e3d6c392ec3ba125b5bc591dd5e14f05e52",
        "script_hash": "23ec53ddbbd356acd4a5e730aa7f5ec346048b0c",
        "wif_key": "KzAuju4yBqBhmUzYpfEEppPW8jfxALTsdsUR8hLPv9R3PBD97CUv"
    },
    {
        "address": "NaeLNuvaTdB2pX3HjDrJdsjL2CxxkfLAKY",
        "encrypted_key": "6PYWxh9YyxvjQUYVUkb8B6QbEAEFmF1RiNEm9D3aqfiSNHmW5SNidrJ3R9",
        "password": "123",
        "private_key": "2032b737522d22e2b6faf30555faa91d95c5aa5113c18f218f45815b6934c558",
        "script_hash": "78f02e886e0e2cc8f3e679ca5da06868ffeb94a1",
        "wif_key": "KxJJLmU1Nv7igx3RFM4siSvio7wasF3ZzMzi7SrJ1s78QDQeEtjs"
    },
    {
        "address": "NRn16PPhEKpgLRKg4C11ZQjfKSekwjuUkn",
        "encrypted_key": "6PYUgEmLRdX4JkpBR6KLoQZZUKTSCBpp8VBNpGG148G1PuTqJyNsvXuUFh",
        "password": "neo",
        "private_key": "4c5182d9041f416bee1a6adac6a03f3e0319a83e75e78e6ff739304095791f19",
        "script_hash": "6c70044e25ca0fcbe1d43f85e3cf8099ed044f40",
        "wif_key": "Kyn4fA6czAhktoAM9YXKv3m7jtt47AuQxCXqSusnBmj3GsZUZQ6M"
    },
    {
        "address": "NUQnpUFs4Vw2nKyDtCK4tZNrdBUSYecXae",
        "encrypted_key": "6PYKMoTLa16CkxX2q5RTfyJ17tVCY2QDYyfbeWoh7SFfzD7ReL1MChhijn",
        "password": "neo-mamba",
        "private_key": "1c43f87ce2ce3ea676bdfec4928705f3e9fedbdb3acf1fed6b3cc0c3d87c4cad",
        "script_hash": "9f1992832dd88e3f8698e65058f645074d6a345d",
        "wif_key": "KxAexpL1F8FAoG72LCDkerLa8SKLutUSLafALB5zvdQ2asuRf6Wx"
    }
]


class AccountCreationTestCase(unittest.TestCase):

    def test_new_account(self):
        for testcase in account_list:
            account = Account(testcase['password'])
            self.assertIsNotNone(account)
            self.assertIsNotNone(account.address)
            self.assertIsNotNone(account.encrypted_key)
            self.assertIsNotNone(account.public_key)

    def test_new_account_from_private_key(self):
        for testcase in account_list:
            account = Account.from_private_key(bytes.fromhex(testcase['private_key']), testcase['password'])
            self.assertEqual(testcase['address'], account.address)
            self.assertEqual(testcase['encrypted_key'].encode('utf-8'), account.encrypted_key)
            self.assertEqual(testcase['script_hash'], str(account.script_hash))
            self.assertIsNotNone(account.public_key)

    def test_new_account_from_encrypted_key(self):
        for testcase in account_list:
            account = Account.from_encrypted_key(testcase['encrypted_key'], testcase['password'])
            self.assertEqual(testcase['address'], account.address)
            self.assertEqual(testcase['encrypted_key'].encode('utf-8'), account.encrypted_key)
            self.assertEqual(testcase['script_hash'], str(account.script_hash))
            self.assertIsNotNone(account.public_key)

    def test_new_watch_only_account(self):
        from neo3.core.types import UInt160
        for testcase in account_list:
            account = Account.watch_only(UInt160.from_string(testcase['script_hash']))
            self.assertEqual(testcase['address'], account.address)
            self.assertIsNone(account.encrypted_key)
            self.assertEqual(testcase['script_hash'], str(account.script_hash))
            self.assertIsNone(account.public_key)

    def test_new_watch_only_account_from_address(self):
        for testcase in account_list:
            account = Account.watch_only_from_address(testcase['address'])
            self.assertEqual(testcase['address'], account.address)
            self.assertIsNone(account.encrypted_key)
            self.assertEqual(testcase['script_hash'], str(account.script_hash))
            self.assertIsNone(account.public_key)

    def test_new_account_from_wif(self):
        for testcase in account_list:
            account = Account.from_wif(testcase['wif_key'], testcase['password'])
            self.assertEqual(testcase['address'], account.address)
            self.assertEqual(testcase['encrypted_key'].encode('utf-8'), account.encrypted_key)
            self.assertEqual(testcase['script_hash'], str(account.script_hash))
            self.assertIsNotNone(account.public_key)

    def test_new_account_wrong_password(self):
        wrong_password: bool = True
        for testcase in account_list:
            try:
                Account.from_encrypted_key(testcase['encrypted_key'], "wrong password")
                wrong_password = False
            except ValueError:
                continue

        self.assertEqual(True, wrong_password)
