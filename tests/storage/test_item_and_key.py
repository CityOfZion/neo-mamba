import unittest
from neo3 import storage
from neo3.core import types


class StorageKeyTest(unittest.TestCase):
    def test_eq(self):
        contract = types.UInt160.zero()
        key_val = b'\0x01\x02\x03'
        sk = storage.StorageKey(contract, key_val)
        sk2 = storage.StorageKey(contract, key_val)
        self.assertFalse(sk == object())
        self.assertTrue(sk == sk2)

    def test_len(self):
        contract = types.UInt160.zero()
        key_val = b'\x01\x02\x03'
        sk = storage.StorageKey(contract, key_val)

        group_size = 16
        group_remainder_size = 1
        # len(key_val) is smaller than group_size
        # thus we get (see implementation of write_bytes_with_grouping) to understand the logic
        expected_len = len(contract) + group_size + group_remainder_size
        self.assertEqual(expected_len, len(sk))

    def test_serialization(self):
        contract = types.UInt160.zero()
        key_val = b'\x01\x02\x03'
        key_val_padding = bytearray(16 - len(key_val))
        key_val_group_remainder = b'\x03'
        sk = storage.StorageKey(contract, key_val)

        # test serialize
        expected_value = contract.to_array() + key_val + key_val_padding + key_val_group_remainder
        self.assertEqual(expected_value, sk.to_array())
        # test deserialize
        self.assertEqual(sk, storage.StorageKey.deserialize_from_bytes(expected_value))

    def test_various(self):
        contract = types.UInt160.zero()
        key_val = b'\x01\x02\x03'
        sk = storage.StorageKey(contract, key_val)
        # test __repr__ in absence of __str__
        self.assertIn("<StorageKey at ", str(sk))
        self.assertIn(r"[0000000000000000000000000000000000000000] b'\x01\x02\x03'", str(sk))

        # test __hash__
        self.assertEqual(2161234436, hash(sk))


class StorageItemTest(unittest.TestCase):
    def test_eq(self):
        si = storage.StorageItem(b'\x01')
        si2 = storage.StorageItem(b'\x01')
        self.assertFalse(si == object())
        self.assertTrue(si == si2)

    def test_len(self):
        si = storage.StorageItem(b'\x01')
        self.assertEqual(2, len(si))

    def test_serialization(self):
        si_data = b'\x01\x02\x03'
        si = storage.StorageItem(si_data)
        length_indicator = b'\x03'
        self.assertEqual(length_indicator+si_data, si.to_array())

        self.assertEqual(si, storage.StorageItem.deserialize_from_bytes(length_indicator+si_data))

    def test_clone_from_replica(self):
        si_data = b'\x01\x02\x03'
        si = storage.StorageItem(si_data)
        clone = si.clone()
        self.assertEqual(si, clone)
        self.assertNotEqual(id(si), id(clone))

        si2 = storage.StorageItem(bytearray())
        si2.from_replica(si)
        self.assertEqual(si, si2)
