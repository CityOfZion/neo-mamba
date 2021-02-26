import unittest
from neo3 import storage


class StorageKeyTest(unittest.TestCase):
    def test_eq(self):
        contract = 1
        key_val = b'\0x01\x02\x03'
        sk = storage.StorageKey(contract, key_val)
        sk2 = storage.StorageKey(contract, key_val)
        self.assertFalse(sk == object())
        self.assertTrue(sk == sk2)

    def test_len(self):
        contract = 1
        key_val = b'\x01\x02\x03'
        sk = storage.StorageKey(contract, key_val)

        # contract id is serialized to int32
        expected_len = 4 + len(key_val)
        self.assertEqual(expected_len, len(sk))

    def test_serialization(self):
        contract = 1
        key_val = b'\x01\x02\x03'
        sk = storage.StorageKey(contract, key_val)

        # test serialize
        expected_value = b'\x01\x00\x00\x00' + key_val
        self.assertEqual(expected_value, sk.to_array())
        # test deserialize
        self.assertEqual(sk, storage.StorageKey.deserialize_from_bytes(expected_value))

    def test_addition(self):
        sk = storage.StorageKey(1, b'\x01')
        new_sk = sk + b'\x02'
        self.assertNotEqual(id(sk), id(new_sk))
        self.assertNotEqual(sk.key, new_sk.key)
        self.assertEqual(new_sk.key, b'\x01\x02')

        with self.assertRaises(TypeError) as context:
            sk + 1
        self.assertEqual("unsupported operand type(s) for +: 'StorageKey' and 'int'", str(context.exception))

    def test_various(self):
        contract = 1
        key_val = b'\x01\x02\x03'
        sk = storage.StorageKey(contract, key_val)
        # test __repr__ in absence of __str__
        self.assertIn("<StorageKey at ", str(sk))
        self.assertIn(r"[1] b'\x01\x02\x03'", str(sk))

        # test __hash__
        self.assertEqual(2161234437, hash(sk))


class StorageItemTest(unittest.TestCase):
    def test_eq(self):
        si = storage.StorageItem(b'\x01')
        si2 = storage.StorageItem(b'\x01')
        self.assertFalse(si == object())
        self.assertTrue(si == si2)

    def test_len(self):
        si = storage.StorageItem(b'\x01')
        self.assertEqual(3, len(si))

    def test_serialization(self):
        si_data = b'\x01\x02\x03'
        si = storage.StorageItem(si_data, False)
        length_indicator = b'\x03'
        bool_false = b'\x00'
        self.assertEqual(length_indicator + si_data + bool_false, si.to_array())

        self.assertEqual(si, storage.StorageItem.deserialize_from_bytes(length_indicator + si_data + bool_false))

    def test_clone_from_replica(self):
        si_data = b'\x01\x02\x03'
        si = storage.StorageItem(si_data)
        clone = si.clone()
        self.assertEqual(si, clone)
        self.assertNotEqual(id(si), id(clone))

        si2 = storage.StorageItem(bytearray())
        si2.from_replica(si)
        self.assertEqual(si, si2)
