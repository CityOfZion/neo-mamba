import unittest
from neo3 import storage, contracts


class ContractStateTestCase(unittest.TestCase):
    def test_contractstate_clone(self):
        manifest = contracts.ContractManifest()
        state = storage.ContractState(b'\x01', manifest)
        clone = state.clone()
        self.assertNotEqual(id(state), id(clone))
        self.assertNotEqual(id(state.manifest), id(clone.manifest))

    def test_equals(self):
        manifest = contracts.ContractManifest()
        state = storage.ContractState(b'\x01', manifest)
        clone = state.clone()
        self.assertEqual(state, clone)

        state2 = storage.ContractState(b'\x02', manifest)
        self.assertNotEqual(state, state2)
        self.assertNotEqual(state, None)
        self.assertNotEqual(state, object())