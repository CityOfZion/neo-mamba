import unittest
from neo3 import storage


class ComparatorTestCase(unittest.TestCase):
    def test_forward(self):
        comperator = storage.NEOByteCompare("forward")
        self.assertEqual(-1, comperator.compare(b'\x00', b'\x01'))
        self.assertEqual(0, comperator.compare(b'\x01', b'\x01'))
        self.assertEqual(1, comperator.compare(b'\x02', b'\x01'))
        self.assertEqual(-1, comperator.compare(b'\x01', b'\x02'))
        self.assertEqual(1, comperator.compare(b'\x01\x01', b'\x01'))
        self.assertEqual(1, comperator.compare(b'\xff', b'\x01'))
        self.assertEqual(-1, comperator.compare(b'\xf9', b'\xfb'))
        self.assertEqual(1, comperator.compare(b'\xf9\xff\xff\xff\x09', b'\x01\x00\x00\x00\x01'))
        self.assertEqual(1, comperator.compare(b'\x01\x00\x00\x00\x01\x02', b'\x01\x00\x00\x00\x01'))

