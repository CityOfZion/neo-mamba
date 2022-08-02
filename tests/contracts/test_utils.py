import unittest
from neo3.contracts import get_contract_hash, NEF
from neo3.core import types


class TestContractUtils(unittest.TestCase):
    def test_get_contract_hash(self):
        nef = NEF("test", b'\x01\x02\x03')
        actual = get_contract_hash(types.UInt160.zero(), nef.checksum, "test")
        expected = types.UInt160.from_string("0x576c9c6f22eea8fd823155b00141a4327bac8263")
        self.assertEqual(expected, actual)

        actual = get_contract_hash(types.UInt160.from_string("0xa400ff00ff00ff00ff00ff00ff00ff00ff00ff01"), nef.checksum, "test")
        expected = types.UInt160.from_string("0x55f776130883b2d486dec295ca74533663d0f8ea")
        self.assertEqual(expected, actual)
