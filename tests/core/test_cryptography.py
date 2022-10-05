import unittest
import binascii
import hashlib
from neo3crypto import mmh3_hash_bytes, mmh3_hash
from neo3.core import types
from neo3.core import cryptography as crypto


class MerkleTreeTestCase(unittest.TestCase):
    def test_compute_root_single_hash(self):
        data = binascii.unhexlify(b"aa" * 32)
        hash1 = types.UInt256(data=data)
        root = crypto.MerkleTree.compute_root([hash1])

        self.assertEqual(data, root.to_array())

    def test_compute_root_multiple_hashes(self):
        expected_hash = hashlib.sha256(
            hashlib.sha256(binascii.unhexlify(b"aa" * 32 + b"bb" * 32)).digest()
        ).digest()

        hash1 = types.UInt256(data=binascii.unhexlify(b"aa" * 32))
        hash2 = types.UInt256(data=binascii.unhexlify(b"bb" * 32))
        hashes = [hash1, hash2]
        root = crypto.MerkleTree.compute_root(hashes)

        self.assertEqual(expected_hash, root.to_array())

    def test_computer_root_no_input(self):
        self.assertEqual(types.UInt256.zero(), crypto.MerkleTree.compute_root([]))

    def test_build_no_leaves(self):
        with self.assertRaises(ValueError) as context:
            crypto.MerkleTree._build([])
        self.assertIn("Leaves must have length", str(context.exception))

    def test_to_hash_array(self):
        hash1 = types.UInt256(data=binascii.unhexlify(b"aa" * 32))
        hash2 = types.UInt256(data=binascii.unhexlify(b"bb" * 32))
        hash3 = types.UInt256(data=binascii.unhexlify(b"cc" * 32))
        hash4 = types.UInt256(data=binascii.unhexlify(b"dd" * 32))
        hash5 = types.UInt256(data=binascii.unhexlify(b"ee" * 32))
        hashes = [hash1, hash2, hash3, hash4, hash5]

        m = crypto.MerkleTree(hashes)
        hash_array = m.to_hash_array()

        # sort the array
        hash_array = sorted(hash_array)

        for i, h in enumerate(hashes):
            self.assertEqual(h, hash_array[i])

    def test_merkle_node_methods(self):
        hash1 = types.UInt256(data=binascii.unhexlify(b"aa" * 32))
        hash2 = types.UInt256(data=binascii.unhexlify(b"bb" * 32))
        hashes = [hash1, hash2]
        m = crypto.MerkleTree(hashes)

        self.assertEqual(True, m.root.is_root())
        self.assertEqual(False, m.root.is_leaf())
        self.assertEqual(False, m.root.left_child.is_root())
        self.assertEqual(True, m.root.left_child.is_leaf())


class BloomFilterTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_seed_building(self):
        filter = crypto.BloomFilter(m=7, k=10, ntweak=123456)
        # these values have been captured by creating a BloomFilter in C# and reading the seed values through debugging
        expected_seeds = [
            123456,
            4222003669,
            4148916586,
            4075829503,
            4002742420,
            3929655337,
            3856568254,
            3783481171,
            3710394088,
            3637307005,
        ]
        self.assertEqual(expected_seeds, filter.seeds)

    def test_add_and_check(self):
        # modelled after https://github.com/neo-project/neo/blob/982e69090f27c1415872536ce39aea22f0873467/neo.UnitTests/Cryptography/UT_BloomFilter.cs#L12
        elements = b"\x00\x01\x02\x03\x04"
        filter = crypto.BloomFilter(m=7, k=10, ntweak=123456)
        filter.add(elements)
        self.assertTrue(filter.check(elements))
        self.assertFalse(filter.check(elements + b"\x05\x06\x07\x08\x09"))

    def test_init_with_elements(self):
        elements = b"\x00\x01\x02\x03\x04"
        m = 7
        k = 10
        filter = crypto.BloomFilter(m=m, k=k, ntweak=123456, elements=elements)
        self.assertEqual(m, len(filter.bits))
        self.assertEqual(k, len(filter.seeds))

    def test_get_bits(self):
        """
        byte[] elements = { 0, 1, 2, 3, 4};
        BloomFilter bf = new BloomFilter(7, 10, 123456, elements);
        byte[] buffer = new byte[(bf.M/8)+1];
        Console.WriteLine($"\\x{BitConverter.ToString(buffer).Replace("-", "\\x")}");
        """
        elements = b"\x00\x01\x02\x03\x04"
        filter = crypto.BloomFilter(m=7, k=10, ntweak=123456, elements=elements)
        self.assertEqual(b"\x00", filter.get_bits())


class Murmur128test(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_neo_cases(self):
        # https://github.com/Liaojinghui/neo/blob/30f33d075502acd792f804ffcf84cce689255306/tests/neo.UnitTests/Cryptography/UT_Murmur128.cs
        self.assertEqual(
            bytes.fromhex("0bc59d0ad25fde2982ed65af61227a0e"),
            mmh3_hash_bytes("hello", 123),
        )
        self.assertEqual(
            bytes.fromhex("3d3810fed480472bd214a14023bb407f"),
            mmh3_hash_bytes("world", 123),
        )
        self.assertEqual(
            bytes.fromhex("e0a0632d4f51302c55e3b3e48d28795d"),
            mmh3_hash_bytes("hello world", 123),
        )


class MurMur32test(unittest.TestCase):
    def test_one(self):
        x: int = mmh3_hash(b"\x01\x02\x03\x04\x05\x06", 123, signed=False)
        self.assertEqual(
            bytes.fromhex("3cdc1e41"), x.to_bytes(4, "little", signed=False)
        )
