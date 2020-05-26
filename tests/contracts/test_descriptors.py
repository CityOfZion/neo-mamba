import unittest
from neo3 import contracts
from neo3.core import cryptography, types


class ContractPermissionDescriptorTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        private_key = b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
        cls.keypair = cryptography.KeyPair(private_key)

    def test_wildcard(self):
        cpd = contracts.ContractPermissionDescriptor()
        self.assertTrue(cpd.is_wildcard)
        self.assertDictEqual({'contract': '*'}, cpd.to_json())
        cpd_from_json = contracts.ContractPermissionDescriptor.from_json(cpd.to_json())
        self.assertEqual(cpd.contract_hash, cpd_from_json.contract_hash)
        self.assertEqual(cpd.group, cpd_from_json.group)

    def test_group(self):
        cpd = contracts.ContractPermissionDescriptor(contract_hash=types.UInt160.zero())
        self.assertTrue(cpd.is_hash)
        self.assertFalse(cpd.is_group)
        self.assertFalse(cpd.is_wildcard)
        self.assertDictEqual({'contract': '0000000000000000000000000000000000000000'}, cpd.to_json())
        cpd_from_json = contracts.ContractPermissionDescriptor.from_json(cpd.to_json())
        self.assertEqual(cpd.contract_hash, cpd_from_json.contract_hash)
        self.assertEqual(cpd.group, cpd_from_json.group)

    def test_contract_hash(self):
        cpd = contracts.ContractPermissionDescriptor(group=self.keypair.public_key)
        self.assertFalse(cpd.is_hash)
        self.assertTrue(cpd.is_group)
        self.assertFalse(cpd.is_wildcard)
        self.assertDictEqual({'contract': '033d523f36a732974c0f7dbdfafb5206ecd087211366a274190f05b86d357f4bad'},
                             cpd.to_json())
        cpd_from_json = contracts.ContractPermissionDescriptor.from_json(cpd.to_json())

        self.assertEqual(cpd.contract_hash, cpd_from_json.contract_hash)
        self.assertEqual(cpd.group, cpd_from_json.group)

    def test_exceptions(self):
        # test construction with too many arguments given
        with self.assertRaises(ValueError) as context:
            cpd = contracts.ContractPermissionDescriptor(
                contract_hash=types.UInt160.zero(),
                group=self.keypair.public_key)
        self.assertIn("Maximum 1 argument", str(context.exception))

        # test from_json with invalid json
        with self.assertRaises(ValueError) as context:
            contracts.ContractPermissionDescriptor.from_json({'contract':None})
        self.assertEqual("Invalid JSON - Cannot deduce permission type from None", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.ContractPermissionDescriptor.from_json({'contract': 'abc'})
        self.assertEqual("Invalid JSON - Cannot deduce permission type from: abc", str(context.exception))

