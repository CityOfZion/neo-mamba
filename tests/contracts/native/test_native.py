import unittest
import binascii
from neo3 import settings, contracts, blockchain
from neo3.core import cryptography, to_script_hash


class TestNativeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        settings.network.standby_committee = ['02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765']
        settings.network.validators_count = 1
        cls.validator_public_key = cryptography.ECPoint.deserialize_from_bytes(
            binascii.unhexlify(settings.network.standby_committee[0])
        )
        cls.validator_account = to_script_hash(
            contracts.Contract.create_multisig_redeemscript(1, [cls.validator_public_key]))

        blockchain.Blockchain()

    @classmethod
    def tearDownClass(cls) -> None:
        settings.reset_settings_to_default()

    def test_requesting_contract_by_name(self):
        self.assertIsNone(contracts.NativeContract.get_contract_by_name("bogus_contract"))
        self.assertIsInstance(contracts.NativeContract.get_contract_by_name("PolicyContract"), contracts.PolicyContract)

    def test_various(self):
        native = contracts.NativeContract()
        known_contracts = native.registered_contracts
        self.assertIn(contracts.GasToken(), known_contracts)
        self.assertIn(contracts.NeoToken(), known_contracts)
        self.assertIn(contracts.PolicyContract(), known_contracts)