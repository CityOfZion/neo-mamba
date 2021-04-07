import unittest
from neo3 import contracts
from neo3.core import types


class ContractStateTestCase(unittest.TestCase):
    def test_contractstate_clone(self):
        manifest = contracts.ContractManifest()
        nef = contracts.NEF()
        state = contracts.ContractState(1, nef, manifest, 0, types.UInt160.zero())
        clone = state.clone()
        self.assertNotEqual(id(state), id(clone))
        self.assertNotEqual(id(state.manifest), id(clone.manifest))

    def test_equals(self):
        manifest = contracts.ContractManifest()
        nef = contracts.NEF()
        state = contracts.ContractState(1, nef, manifest, 0, types.UInt160.zero())
        clone = state.clone()
        self.assertEqual(state, clone)

        nef2 = contracts.NEF()
        state2 = contracts.ContractState(2, nef2, manifest, 0, types.UInt160(b'\x01' * 20))
        self.assertNotEqual(state, state2)
        self.assertNotEqual(state, None)
        self.assertNotEqual(state, object())
