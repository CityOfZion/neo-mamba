# The class is still called DesignationContract
import unittest
from neo3 import settings, contracts, blockchain
from neo3.core import types, cryptography
from neo3.network import payloads
from tests.contracts.interop.utils import test_engine


class TestDesignationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # this triggers deployment of the native contracts
        blockchain.Blockchain()

        settings.network.standby_committee = ['02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765']
        settings.network.validators_count = 1

    @classmethod
    def tearDownClass(cls) -> None:
        settings.reset_settings_to_default()

    def test_assign_and_get_role(self):
        engine = test_engine(has_snapshot=True, has_container=True)
        # set signers list to our committee to pass check_committee() validation
        engine.script_container.signers = [payloads.Signer(
            types.UInt160.from_string("2006cf497676f551841a150550dc3f561c1b6c67"),
            payloads.WitnessScope.GLOBAL
        )]
        public_key1 = cryptography.KeyPair(b'\x01' * 32).public_key
        public_key2 = cryptography.KeyPair(b'\x02' * 32).public_key
        public_key3 = cryptography.KeyPair(b'\x03' * 32).public_key
        c = contracts.DesignationContract()
        c.designate_as_role(engine, contracts.DesignateRole.STATE_VALIDATOR, [public_key1, public_key2])
        c.designate_as_role(engine, contracts.DesignateRole.ORACLE, [public_key3])

        index = engine.snapshot.persisting_block.index + 1
        state_nodes = c.get_designated_by_role(engine.snapshot, contracts.DesignateRole.STATE_VALIDATOR, index)
        self.assertEqual(2, len(state_nodes))
        self.assertIn(public_key1, state_nodes)
        self.assertIn(public_key2, state_nodes)

        oracle_nodes = c.get_designated_by_role(engine.snapshot, contracts.DesignateRole.ORACLE, index)
        self.assertEqual(1, len(oracle_nodes))
        self.assertEqual(public_key3, oracle_nodes[0])
