import unittest
from neo3 import settings, storage, vm, contracts, blockchain
from neo3.core import syscall_name_to_int, types, to_script_hash
from tests.contracts.interop.utils import test_engine, test_block, TestIVerifiable

# this triggers deployment of the native contracts
blockchain.Blockchain()


def contract_hash(sender: types.UInt160, checksum: int, name: str) -> types.UInt160:
    sb = vm.ScriptBuilder()
    sb.emit(vm.OpCode.ABORT)
    sb.emit_push(sender.to_array())
    sb.emit_push(checksum)
    sb.emit_push(name)
    return to_script_hash(sb.to_array())


def test_native_contract(contract_hash: types.UInt160, operation: str, args=None):
    engine = test_engine(has_snapshot=True)
    block = test_block(0)
    # or we won't pass the native deploy call
    engine.snapshot.persisting_block = block

    sb = vm.ScriptBuilder()
    sb.emit_dynamic_call(contract_hash, operation)

    script = vm.Script(sb.to_array())
    engine.load_script(script)

    # storing the current script in a contract otherwise "System.Contract.Call" will fail its checks
    nef = contracts.NEF(script=sb.to_array())
    manifest = contracts.ContractManifest("test_contract")
    next_id = contracts.ManagementContract().get_next_available_id(engine.snapshot)
    contract = contracts.ContractState(next_id + 1, nef, manifest, 0, to_script_hash(nef.script))
    engine.snapshot.contracts.put(contract)

    return engine


class TestPolicyContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        settings.network.standby_committee = ['02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765']
        settings.network.validators_count = 1

    @classmethod
    def tearDownClass(cls) -> None:
        settings.reset_settings_to_default()

    def test_basics(self):
        policy = contracts.PolicyContract()
        self.assertEqual(-7, policy.id)
        self.assertEqual("PolicyContract", contracts.PolicyContract().service_name())

    def test_policy_default_get_fee_per_byte(self):
        engine = test_native_contract(contracts.PolicyContract().hash, "getFeePerByte")
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertEqual(vm.IntegerStackItem(1000), item)

    def test_policy_block_account_and_is_blocked(self):
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        # set or we won't pass the native deploy call
        engine.snapshot.persisting_block = block

        sb = vm.ScriptBuilder()

        # set or we won't pass the check_comittee() in the policy contract function implementations
        engine.script_container = TestIVerifiable()
        validator = settings.standby_committee[0]
        script_hash = to_script_hash(contracts.Contract.create_multisig_redeemscript(1, [validator]))
        engine.script_container.script_hashes = [script_hash]

        # first we setup the stack for calling `blockAccount`
        # push data to create a vm.Array holding 20 bytes for the UInt160 Account parameter of the _block_account function.
        sb.emit_push(b'\x11' * 20)
        sb.emit(vm.OpCode.PUSH1)
        sb.emit(vm.OpCode.PACK)
        sb.emit_push(15)  # call flags
        sb.emit_push("blockAccount")
        sb.emit_push(contracts.PolicyContract().hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))

        # next we call `isBlocked`
        sb.emit_push(b'\x11' * 20)
        sb.emit(vm.OpCode.PUSH1)
        sb.emit(vm.OpCode.PACK)
        sb.emit_push(15)  # call flags
        sb.emit_push("isBlocked")
        sb.emit_push(contracts.PolicyContract().hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))

        script = vm.Script(sb.to_array())
        engine.load_script(script)

        # storing the current script in a contract otherwise "System.Contract.Call" will fail its checks
        nef = contracts.NEF(script=sb.to_array())
        manifest = contracts.ContractManifest("test_contract")
        sender = engine.script_container.script_hashes[0]
        contract = contracts.ContractState(1, nef, manifest, 0, contract_hash(sender, nef.checksum, manifest.name))
        engine.snapshot.contracts.put(contract)

        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(2, len(engine.result_stack))
        get_is_blocked_result = engine.result_stack.pop()
        set_blocked_account_result = engine.result_stack.pop()
        self.assertTrue(set_blocked_account_result.to_boolean())
        self.assertTrue(get_is_blocked_result.to_boolean())

    def test_policy_unblock_account(self):
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        engine.snapshot.persisting_block = block

        # we must add a script_container with valid signature to pass the check_comittee() validation check
        # in the function itself
        engine.script_container = TestIVerifiable()
        validator = settings.standby_committee[0]
        script_hash = to_script_hash(contracts.Contract.create_multisig_redeemscript(1, [validator]))
        engine.script_container.script_hashes = [script_hash]

        policy = contracts.PolicyContract()
        account_not_found = types.UInt160(data=b'\x11' * 20)
        account = types.UInt160.zero()
        self.assertTrue(policy._block_account(engine, account))
        self.assertFalse(policy._unblock_account(engine, account_not_found))
        self.assertTrue(policy._unblock_account(engine, account))
        storage_key = policy.key_blocked_account + account
        storage_item = engine.snapshot.storages.try_get(storage_key)
        self.assertIsNone(storage_item)

    def test_policy_setters_fail_without_signatures(self):
        # cover set functions where check_committee fails
        policy = contracts.PolicyContract()
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        engine.snapshot.persisting_block = block
        engine.script_container = TestIVerifiable()

        with self.assertRaises(ValueError) as context:
            policy._set_fee_per_byte(engine, 0)
        self.assertEqual("Check committee failed", str(context.exception))

        self.assertFalse(policy._block_account(engine, None))
        self.assertFalse(policy._unblock_account(engine, None))
