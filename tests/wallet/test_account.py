import unittest
from neo3.wallet import Account

account_list = [
    {
        "address": "NdgRTnfiYyLr3N7dqTE7J33KRyvuyHzv7q",
        "encrypted_key": "6PYRrDT4mQyq3ieXVWn4KGgQ8E747s8sCDJ4jzoHj3QG3Z2RCg5Rr1prqY",
        "password": "city of zion",
        "private_key": "c54da3dc31b6a6247b8ff476c569b1452cf3790a68174e533eaaba2cc5af6c2a",
        "script_hash": "dcdd336dee6ad4f6bdba32fde98351070660e2c2",
    },
    {
        "address": "NjEafNb9EjStKrxbTLAkWGwYFwPWEZHzzH",
        "encrypted_key": "6PYM7Dm3aginArMuUTXQMSCkHMnQVYij7wy1uvffVzLsMckQiVH7Gsroyb",
        "password": "123",
        "private_key": "5784bb76c26788f177df17de1c014f3667ed1e7d6655c5c232b46b36415b4d63",
        "script_hash": "2d646d71d38f3468982d0ec851ce43488dfecfff",
    },
    {
        "address": "NLXsQj5Bw7FMevM8Zd5gkwGABDcHtub94p",
        "encrypted_key": "6PYURBhofSKgFSSQQrpUkGxKytWVeWtoXpwAwuVFxtztKKStW84FwRyRXC",
        "password": "neo",
        "private_key": "d7352d0c0bf4a82db05780a175fc2614ed09d28e03cc8ae93318d6c320e61f8a",
        "script_hash": "8b6542f5133a8c2177193402f2e464951a27ca06",
    },
    {
        "address": "NVZtTRsEFCbMMYjrQB5NguyqpjEFXpRHHZ",
        "encrypted_key": "6PYTo46szFt1YwgqTy5kc6vp1cuKJqLFJYXHCNcoXvHGetjK65WMVWVn8r",
        "password": "neo-mamba",
        "private_key": "25caf316e359781767d66feacc37b4f24bc5a86856842aeb4e645dfe260632a7",
        "script_hash": "76e83a307b5a21421511d8f30ffdc35b8afde469",
    }
]


class AccountCreationTestCase(unittest.TestCase):

    def test_account_from_password(self):
        for testcase in account_list:
            account = Account.from_password(testcase['password'])
            self.assertIsNotNone(account)
            self.assertIsNotNone(account.address)
            self.assertIsNotNone(account.encrypted_key)
            self.assertIsNotNone(account.public_key)

    def test_account_from_private_key(self):
        for testcase in account_list:
            account = Account.from_private_key(bytes.fromhex(testcase['private_key']), testcase['password'])
            self.assertEqual(testcase['address'], account.address)
            self.assertEqual(testcase['encrypted_key'].encode('utf-8'), account.encrypted_key)
            self.assertEqual(testcase['script_hash'], account.script_hash.__str__())
            self.assertIsNotNone(account.public_key)

    def test_account_from_encrypted_key(self):
        for testcase in account_list:
            account = Account.from_encrypted_key(testcase['encrypted_key'], testcase['password'])
            self.assertEqual(testcase['address'], account.address)
            self.assertEqual(testcase['encrypted_key'].encode('utf-8'), account.encrypted_key)
            self.assertEqual(testcase['script_hash'], account.script_hash.__str__())
            self.assertIsNotNone(account.public_key)

    def test_account_from_script_hash(self):
        from neo3.core.types import UInt160
        for testcase in account_list:
            account = Account.from_script_hash(UInt160.from_string(testcase['script_hash']))
            self.assertEqual(testcase['address'], account.address)
            self.assertIsNone(account.encrypted_key)
            self.assertEqual(testcase['script_hash'], account.script_hash.__str__())
            self.assertIsNone(account.public_key)

    def test_account_from_address(self):
        for testcase in account_list:
            account = Account.from_address(testcase['address'])
            self.assertEqual(testcase['address'], account.address)
            self.assertIsNone(account.encrypted_key)
            self.assertEqual(testcase['script_hash'], account.script_hash.__str__())
            self.assertIsNone(account.public_key)
