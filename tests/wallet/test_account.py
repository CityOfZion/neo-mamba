import unittest

from neo3 import contracts
from neo3.core.types import UInt160
from neo3.storage import Snapshot
from neo3.wallet import Account

account_list = [
    {
        "address": "NRaKbRA5JAEJtfUgJJZzmeDnKvP3pJwKp1",
        "encrypted_key": "6PYKuriAL7pFeVTr3tKksbD1SpKUP7K82vjGuskZ5zpo9EWDhLRW6GcnyL",
        "password": "city of zion",
        "private_key": "58124574dfcca1a7a958775f6ea94e3d6c392ec3ba125b5bc591dd5e14f05e52",
        "script_hash": "18f13748e08d53c9a164227e1a3e8d8d9e78193e",
        "wif_key": "KzAuju4yBqBhmUzYpfEEppPW8jfxALTsdsUR8hLPv9R3PBD97CUv"      
    },
    {
        "address": "NgPptMp2tcjnXuYbUrTozvwvLExGKk5jXc",
        "encrypted_key": "6PYMEujkLs249znmr3v59x3M12iPbdPTZftv8f2TapuLyHn8TQBZLVJUV6",
        "password": "123",
        "private_key": "2032b737522d22e2b6faf30555faa91d95c5aa5113c18f218f45815b6934c558",
        "script_hash": "cfa9032d65b3d0fc1df3956a4ef01666f23ba7e0",
        "wif_key": "KxJJLmU1Nv7igx3RFM4siSvio7wasF3ZzMzi7SrJ1s78QDQeEtjs"
    },
    {
        "address": "NZMHRJMPbyJJwtXpvS2mYAWcWp4qmZZFx8",
        "encrypted_key": "6PYL44vbS5e6ubYtV3JqDM7J92gCEYXWewVyFdyki6JLcQ7QaYzsW6YjTs",
        "password": "neo",
        "private_key": "4c5182d9041f416bee1a6adac6a03f3e0319a83e75e78e6ff739304095791f19",
        "script_hash": "0df27baba6baeeb6834bea0d6c2a78183b416393",
        "wif_key": "Kyn4fA6czAhktoAM9YXKv3m7jtt47AuQxCXqSusnBmj3GsZUZQ6M"
    },
    {
        "address": "NWxsLx9BFA558pVLZmFNuYsRKuXMMi2QSQ",
        "encrypted_key": "6PYQ5gTPAv4p5nfrb2ywPumSdtiXCjimuwDAbv93FPancd1dU9D9ajkPqd",
        "password": "neo-mamba",
        "private_key": "1c43f87ce2ce3ea676bdfec4928705f3e9fedbdb3acf1fed6b3cc0c3d87c4cad",
        "script_hash": "3b951421e8dc81552df3af1478ef72b05bc13579",
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

    def test_add_delete_tokens(self):
        from neo3.blockchain import Blockchain

        # initialized a Blockchain to not attribute a CachedContractAccess directly into _contract_cache in the Snapshot
        bl = Blockchain()
        snapshot: Snapshot = bl.currentSnapshot

        # creating fake contracts so that supported_standards could be tested
        dummy_method = contracts.ContractMethodDescriptor("test1", 0, [], contracts.ContractParameterType.VOID, True)
        nef1 = contracts.NEF(script=b'\x01\x02')
        nef2 = contracts.NEF(script=b'\x03\x04')
        nef3 = contracts.NEF(script=b'\x05\x06')
        token_hash1 = UInt160(bytes(range(20)))
        token_hash2 = UInt160(bytes(20))
        token_hash3 = UInt160(bytes(reversed(range(20))))
        contract1 = contracts.ContractState(1, nef1, contracts.ContractManifest(), 0, token_hash1)
        contract1.manifest.abi.methods.append(dummy_method)
        contract1.manifest.supported_standards.append("NEP-17")
        contract2 = contracts.ContractState(2, nef2, contracts.ContractManifest(), 0, token_hash2)
        contract2.manifest.abi.methods.append(dummy_method)
        contract2.manifest.supported_standards.append("NEP-17")
        contract3 = contracts.ContractState(3, nef3, contracts.ContractManifest(), 0, token_hash3)
        contract3.manifest.abi.methods.append(dummy_method)
        contract3.manifest.supported_standards.append("NEP-5")

        snapshot.contracts.put(contract1)
        snapshot.contracts.put(contract2)
        snapshot.contracts.put(contract3)

        account = Account("password")
        self.assertIsNone(account.extra.get("tokens"))

        # Adding a token script hash will return True
        result = account.token_add(token_hash1, snapshot)
        self.assertEqual(True, result)
        self.assertEqual([token_hash1], account.extra.get("tokens"))

        # Trying to add the same script hash will return False and won't change the extra property
        result = account.token_add(token_hash1, snapshot)
        self.assertEqual(False, result)
        self.assertEqual([token_hash1], account.extra.get("tokens"))

        # Adding another script hash will return True and will be added at the end of the list
        result = account.token_add(token_hash2, snapshot)
        self.assertEqual(True, result)
        self.assertEqual([token_hash1, token_hash2], account.extra.get("tokens"))

        # Making sure the tokens will be kept when transforming to json
        json_dict = account.to_json()
        self.assertEqual([token_hash1, token_hash2], json_dict["extra"]["tokens"])

        # Trying to add an already existing script hash will return False and won't change the extra property
        result = account.token_add(token_hash1, snapshot)
        self.assertEqual(False, result)
        self.assertEqual([token_hash1, token_hash2], account.extra.get("tokens"))
        result = account.token_add(token_hash2, snapshot)
        self.assertEqual(False, result)
        self.assertEqual([token_hash1, token_hash2], account.extra.get("tokens"))

        # Deleting a script hash will return True and remove it from the list
        result = account.token_delete(token_hash1)
        self.assertEqual(True, result)
        self.assertEqual([token_hash2], account.extra.get("tokens"))

        # Deleting a non existing script hash will return False and do nothing
        result = account.token_delete(token_hash1)
        self.assertEqual(False, result)
        self.assertEqual([token_hash2], account.extra.get("tokens"))

        # Deleting all script hashes will also remove the "tokens" key from extra
        result = account.token_delete(token_hash2)
        self.assertEqual(True, result)
        self.assertIsNone(account.extra.get("tokens"))

        # Trying to add a non NEP-17 contract will return False
        result = account.token_add(token_hash3, snapshot)
        self.assertEqual(False, result)
        self.assertIsNone(account.extra.get("tokens"))
