import unittest

from neo3.wallet import Account, private_key_to_nep2, private_key_from_nep2


class AccountCreationTestCase(unittest.TestCase):

    def test_account_from_nep2(self):
        nep2 = '6PYWFgCbuow5AwyfUXWyn1Cjc4NFFvrGq97nKoEXgvFiysHzstgt3ZT25G'
        account = Account.from_nep2(nep2, "password")
        print(account.address)
        assert account.get_key() == nep2


    def test_create_nep2(self):
        private_key = b'\x01' * 32
        password = "password"
        nep2 = private_key_to_nep2(private_key, password)
        print(nep2)
        decrypted_key = private_key_from_nep2(nep2, password)
        assert private_key == decrypted_key

    def test_account_from_json(self):
        json = {
            'address': 'NYnoVTT6WYgDkqgLfJedtrCVXg9QP9ehWf',
            'label': None,
            'isdefault': False,
            'lock': False,
            'key': '6PYN3LouHarFmMdQF1CdRXDcYPziErnhx9jwhTvHoQqvxTSrKqbY8wemjb',
            'contract': {
                'script': 'DCEDcq1kV285mzXGuZf0D4PASSmXtaNAolxhcGbm5nSoKYVBdHR2qg==',
                'parameters': [
                    {
                        'name': 'signature',
                        'type': 'Signature'
                    }
                ],
                'deployed': False
            },
            'extra': None
        }
        account = Account.from_json(json)

        # if os.path.isfile(filepath):
        #     with open(filepath, mode='rb') as file:
        #         import json
        #         wallet = file.read()
        #         self._load_from_json(json.loads(wallet))

        self.assertEqual(json['address'], account.address)
        result = account.to_json()
        self.assertEqual(result, json)
