import unittest
from neo3.contracts import contract, nef, manifest
from neo3.core import types


class ContractStateTestCase(unittest.TestCase):
    def test_equals(self):
        manifest_ = manifest.ContractManifest()
        nef_ = nef.NEF()
        state = contract.ContractState(1, nef_, manifest_, 0, types.UInt160.zero())
        clone = contract.ContractState(1, nef_, manifest_, 0, types.UInt160.zero())
        self.assertEqual(state, clone)

        nef2 = nef.NEF()
        state2 = contract.ContractState(
            2, nef2, manifest_, 0, types.UInt160(b"\x01" * 20)
        )
        self.assertNotEqual(state, state2)
        self.assertNotEqual(state, None)
        self.assertNotEqual(state, object())
