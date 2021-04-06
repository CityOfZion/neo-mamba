import unittest
from neo3 import vm, contracts, storage
from neo3.core import types
from tests.contracts.interop.utils import test_engine, test_block, test_tx


def test_name_service(operation: str, has_return_value=False, args=None):
    # engine = contracts.ApplicationEngine(contracts.TriggerType.APPLICATION, tx, b.currentSnapshot, 0, test_mode=True)
    engine = test_engine(has_snapshot=True)
    # or we won't pass the native deploy call
    block = test_block(1)
    # engine.snapshot = snapshot
    engine.snapshot.persisting_block = block

    # now call the actual contract
    sb = vm.ScriptBuilder()
    if args is None:
        sb.emit_dynamic_call(contracts.NameService().hash, operation)
    else:
        sb.emit_dynamic_call_with_args(contracts.NameService().hash, operation, args)

    script = vm.Script(sb.to_array())
    engine.load_script(script)
    return engine


class NameServiceTestCase(unittest.TestCase):
    def test_root(self):
        # root regex fail
        engine = test_name_service("addRoot", False, ["te_st"])
        self.assertEqual(vm.VMState.FAULT, engine.execute())

        # checkwitness fail
        engine = test_name_service("addRoot", False, ["test"])
        engine.script_container = test_tx()
        self.assertEqual(vm.VMState.FAULT, engine.execute())

        # ok
        # first make sure to pass check witness
        engine = test_name_service("addRoot", False, ["test"])
        tx = test_tx(signers=[contracts.NeoToken().get_committee_address(engine.snapshot)])
        engine.script_container = tx
        self.assertEqual(vm.VMState.HALT, engine.execute())

        # fail, duplicate
        engine2 = test_name_service("addRoot", False, ["test"])
        engine2.snapshot = engine.snapshot
        tx = test_tx(signers=[contracts.NeoToken().get_committee_address(engine.snapshot)])
        engine2.script_container = tx
        self.assertEqual(vm.VMState.FAULT, engine2.execute())

    def test_price(self):
        # negative price
        engine = test_name_service("setPrice", False, [-1])
        self.assertEqual(vm.VMState.FAULT, engine.execute())

        # free price
        engine = test_name_service("setPrice", False, [0])
        self.assertEqual(vm.VMState.FAULT, engine.execute())

        # too high price
        engine = test_name_service("setPrice", False, [10000_00000001])
        self.assertEqual(vm.VMState.FAULT, engine.execute())

        # checkwitness fail
        engine = test_name_service("setPrice", False, [1])
        engine.script_container = test_tx()
        self.assertEqual(vm.VMState.FAULT, engine.execute())

        # ok
        engine = test_name_service("setPrice", False, [55])
        tx = test_tx(signers=[contracts.NeoToken().get_committee_address(engine.snapshot)])
        engine.script_container = tx
        self.assertEqual(vm.VMState.HALT, engine.execute())
        self.assertEqual(55, contracts.NameService().get_price(engine.snapshot))

    def test_is_available(self):
        nameservice = contracts.NameService()

        engine = test_engine(has_snapshot=True)
        tx = test_tx(signers=[contracts.NeoToken().get_committee_address(engine.snapshot)])
        engine.script_container = tx

        snapshot = engine.snapshot
        with self.assertRaises(ValueError) as context:
            nameservice.is_available(snapshot, "te_st")
        self.assertEqual("Regex failure - name is not valid", str(context.exception))

        with self.assertRaises(ValueError) as context:
            nameservice.is_available(snapshot, "sub.neo.org")
        self.assertEqual("Invalid format", str(context.exception))

        with self.assertRaises(ValueError) as context:
            nameservice.is_available(snapshot, "neo.org")
        self.assertEqual("'org' is not a registered root", str(context.exception))

        # store "com" as a registered root, thus leaving "org" available
        nameservice.add_root(engine, "org")
        self.assertTrue(nameservice.is_available(snapshot, "neo.org"))

    def test_register(self):
        nameservice = contracts.NameService()

        engine = test_engine(has_snapshot=True)
        tx = test_tx(signers=[contracts.NeoToken().get_committee_address(engine.snapshot)])
        engine.script_container = tx

        nameservice.add_root(engine, "org")

        # not signed
        with self.assertRaises(ValueError) as context:
            nameservice.register(engine, "coz.org", types.UInt160.zero())
        self.assertEqual("CheckWitness failed", str(context.exception))

        self.assertTrue(nameservice.register(engine, "coz.org", tx.sender))

        # already registered
        with self.assertRaises(ValueError) as context:
            nameservice.register(engine, "coz.org", tx.sender)
        self.assertEqual("Registration failure - 'coz.org' is not available", str(context.exception))
