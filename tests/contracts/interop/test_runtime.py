import unittest
import hashlib
from typing import List

from neo3 import vm, contracts, storage
from neo3.core.serialization import BinaryReader, BinaryWriter
from neo3.network import payloads
from neo3.contracts import syscall_name_to_int
from neo3.core import to_script_hash, types, cryptography, serialization, msgrouter
from tests.contracts.interop.utils import test_engine, test_block, test_tx, TestIVerifiable, contract_hash


class TestIVerifiable(payloads.IVerifiable):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.script_hashes = [types.UInt160.zero()]

    def serialize(self, writer: BinaryWriter) -> None:
        pass

    def deserialize(self, reader: BinaryReader) -> None:
        pass

    def __len__(self):
        pass

    def serialize_unsigned(self, writer: serialization.BinaryWriter) -> None:
        pass

    def deserialize_unsigned(self, reader: serialization.BinaryReader) -> None:
        pass

    def get_script_hashes_for_verifying(self, snapshot: storage.Snapshot) -> List[types.UInt160]:
        return self.script_hashes


class RuntimeInteropTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_getplatform(self):
        engine = test_engine()
        engine.invoke_syscall_by_name("System.Runtime.Platform")
        item = engine.pop()
        self.assertIsInstance(item, vm.ByteStringStackItem)
        self.assertEqual(vm.ByteStringStackItem(b'NEO'), item)

    def test_gettrigger(self):
        engine = test_engine()
        engine.invoke_syscall_by_name("System.Runtime.GetTrigger")
        item = engine.pop()
        self.assertIsInstance(item, vm.IntegerStackItem)
        self.assertEqual(vm.IntegerStackItem(contracts.TriggerType.APPLICATION.value), item)

    def test_gettime(self):
        engine = test_engine(has_container=False, has_snapshot=True)
        b = test_block()
        engine.snapshot.persisting_block = b
        engine.invoke_syscall_by_name("System.Runtime.GetTime")
        item = engine.pop()
        self.assertIsInstance(item, vm.IntegerStackItem)
        self.assertEqual(vm.IntegerStackItem(b.timestamp), item)

    def test_getscriptcontainer(self):
        # first test against an invalid script container (IVerifiable, but not IOperable)
        engine = test_engine()
        container = payloads.Header._serializable_init()
        engine.script_container = container

        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Runtime.GetScriptContainer")
        self.assertEqual("script container is not a valid IInteroperable type", str(context.exception))

        tx = test_tx(1)
        engine = test_engine()
        engine.script_container = tx

        sb = vm.ScriptBuilder()
        sb.emit_syscall(syscall_name_to_int("System.Runtime.GetScriptContainer"))
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()

        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack._items))
        item = engine.result_stack.pop()
        self.assertIsInstance(item, vm.ArrayStackItem)
        # we now have a Block that has been serialized, let's check the hash
        self.assertEqual(vm.ByteStringStackItem(tx.hash().to_array()), item[0])

    def test_getexecutingscripthash(self):
        engine = test_engine()
        sb = vm.ScriptBuilder()
        sb.emit(vm.OpCode.PUSH1)
        sb.emit(vm.OpCode.PUSH2)
        sb.emit(vm.OpCode.PUSH3)
        sb.emit_syscall(syscall_name_to_int("System.Runtime.GetExecutingScriptHash"))
        data = sb.to_array()

        engine.load_script(vm.Script(data))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(4, len(engine.result_stack._items))
        item = engine.result_stack.pop()
        self.assertEqual(to_script_hash(data).to_array(), item.to_array())

    def test_getcallingscripthash(self):
        """
        Testing this requires 2 contracts

        1) caller_contract: uses a System.Contract.Call to call callee_contract. This will set the calling script hash on the ExecutionContext of the callee_contract
        2) callee_contract: uses a System.Runtime.GetCallingScriptHash to return the calling script
        """
        sb = vm.ScriptBuilder()
        sb.emit_syscall(syscall_name_to_int("System.Runtime.GetCallingScriptHash"))
        callee_contract_script = sb.to_array()
        callee_nef = contracts.NEF(script=callee_contract_script)
        callee_contract_name = "callee_contract"
        callee_manifest = contracts.ContractManifest(callee_contract_name)
        callee_manifest.abi.methods = [
            contracts.ContractMethodDescriptor("test_func", 0, [], contracts.ContractParameterType.ANY, True)
        ]
        callee_contract_hash = contract_hash(types.UInt160.zero(), callee_nef.checksum, callee_contract_name)
        callee_contract = contracts.ContractState(1, callee_nef, callee_manifest, 0, callee_contract_hash)

        # create caller_contract script
        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call(callee_contract.hash, "test_func")
        caller_script = sb.to_array()
        caller_nef = contracts.NEF(script=caller_script)
        caller_contract_name = "caller_contract"
        caller_manifest = contracts.ContractManifest(caller_contract_name)
        caller_contract_hash = contract_hash(types.UInt160.zero(), caller_nef.checksum, caller_contract_name)
        caller_contract = contracts.ContractState(2, caller_nef, caller_manifest, 0, caller_contract_hash)

        engine = test_engine(has_snapshot=True, default_script=False)
        engine.snapshot.contracts.put(callee_contract)
        engine.snapshot.contracts.put(caller_contract)
        engine.load_script(vm.Script(caller_script))
        engine.execute()

        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertEqual(to_script_hash(caller_nef.script).to_array(), item.to_array())

    def test_getentryscripthash(self):
        # entry script hash is set on a engine.load_script
        sb = vm.ScriptBuilder()
        sb.emit_syscall(syscall_name_to_int("System.Runtime.GetEntryScriptHash"))
        raw_script = sb.to_array()

        engine = test_engine(default_script=False)
        ctx = engine.load_script(vm.Script(raw_script))
        engine.execute()

        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertEqual(to_script_hash(raw_script).to_array(), item.to_array())

    def test_checkwitness_helper(self):
        engine = test_engine()
        tx = test_tx()
        engine.script_container = tx

        bad_hash = types.UInt160.zero()
        self.assertFalse(engine.checkwitness(bad_hash))

        # if scope is GLOBAL then checkwitness should always return true
        good_hash = tx.sender
        tx.signers[0].scope = payloads.WitnessScope.GLOBAL
        self.assertTrue(engine.checkwitness(good_hash))

    def test_checkwitness_helper_custom_contracts(self):
        engine = test_engine(has_snapshot=True, default_script=False)
        tx = test_tx()
        engine.script_container = tx

        sb = vm.ScriptBuilder()
        sb.emit(vm.OpCode.RET)
        caller_script = sb.to_array()
        engine.load_script(vm.Script(caller_script))

        # test for CUSTOM_CONTRACTS in scope
        tx.signers[0].scope = payloads.WitnessScope.CUSTOM_CONTRACTS
        tx.signers[0].allowed_contracts = [to_script_hash(caller_script)]

        self.assertTrue(engine.checkwitness(tx.sender))

        # now check it fails if the hash is not in the allowed_contracts_list
        tx.signers[0].allowed_contracts = [types.UInt160.zero()]
        self.assertFalse(engine.checkwitness(tx.sender))

    @unittest.SkipTest
    def test_checkwitness_custom_groups(self):
        """
        We need to setup 2 contracts
        1) caller_contract: uses a System.Contract.Call to call callee_contract. This will set the calling script hash on the ExecutionContext of the callee_contract
        2) callee_contract: uses a System.Runtime.CheckWitness
        """
        engine = test_engine(has_snapshot=True, default_script=False)
        tx = test_tx()
        engine.script_container = tx

        '''
        Create the callee contract, which does a checkwitness on its caller.
        Checkwitness shall only pass if the caller == "caller_contract" as defined by CustomGroup
        '''
        sb = vm.ScriptBuilder()
        sb.emit_syscall(syscall_name_to_int("System.Runtime.GetCallingScriptHash"))  # get script hash of "caller_contract"
        sb.emit_syscall(syscall_name_to_int("System.Runtime.CheckWitness"))
        callee_contract_script = sb.to_array()
        callee_nef = contracts.NEF(script=callee_contract_script)
        callee_contract_name = "callee_contract"
        callee_manifest = contracts.ContractManifest(callee_contract_name)
        callee_manifest.abi.methods = [
            contracts.ContractMethodDescriptor("test_func", 0, [], contracts.ContractParameterType.ANY, True)
        ]
        callee_contract_hash = contract_hash(tx.sender, callee_nef.checksum, callee_contract_name)
        callee_contract = contracts.ContractState(1, callee_nef, callee_manifest, 0, callee_contract_hash)

        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call(callee_contract.hash, "test_func")
        caller_script = sb.to_array()
        caller_nef = contracts.NEF(script=caller_script)
        caller_contract_name = "caller_contract"
        caller_manifest = contracts.ContractManifest(caller_contract_name)

        keypair = cryptography.KeyPair(private_key=b'\x01' * 32)
        signature = cryptography.sign(caller_script, keypair.private_key)
        caller_manifest.groups = [contracts.ContractGroup(
            public_key=keypair.public_key,
            signature=signature
        )]

        caller_contract_hash = contract_hash(tx.sender, caller_nef.checksum, caller_contract_name)
        caller_contract = contracts.ContractState(2, caller_nef, caller_manifest, 0, caller_contract_hash)
        engine.snapshot.contracts.put(caller_contract)
        engine.snapshot.contracts.put(callee_contract)
        engine.load_script(vm.Script(caller_script))

        tx.signers[0].scope = payloads.WitnessScope.CUSTOM_GROUPS
        tx.signers[0].allowed_groups = [keypair.public_key]

        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertTrue(item.to_boolean())

        # now try again but make sure it fails if the public key is not listed in the allowed groups
        engine = test_engine(has_snapshot=True, default_script=False)
        tx = test_tx()
        engine.script_container = tx

        engine.snapshot.contracts.put(caller_contract)
        engine.snapshot.contracts.put(callee_contract)
        engine.load_script(vm.Script(caller_script))

        tx.signers[0].scope = payloads.WitnessScope.CUSTOM_GROUPS
        keypair = cryptography.KeyPair(private_key=b'\x02' * 32)
        tx.signers[0].allowed_groups = [keypair.public_key]

        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertFalse(item.to_boolean())

    def test_checkwitness_called_by_entry(self):
        """
        We need to setup 2 contracts
        1) caller_contract: uses a System.Contract.Call to call callee_contract. This will set the calling script hash on the ExecutionContext of the callee_contract
        2) callee_contract: uses a System.Runtime.CheckWitness
        """
        engine = test_engine(has_snapshot=True, has_container=False, default_script=False)
        tx = test_tx()
        tx.signers[0].scope = payloads.WitnessScope.CALLED_BY_ENTRY
        engine.script_container = tx

        sb = vm.ScriptBuilder()
        sb.emit_push(tx.sender.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Runtime.CheckWitness"))
        callee_contract_script = sb.to_array()
        callee_nef = contracts.NEF(script=callee_contract_script)
        callee_manifest = contracts.ContractManifest()
        callee_manifest.abi.methods = [
            contracts.ContractMethodDescriptor("test_func", 0, [], contracts.ContractParameterType.ANY, True)
        ]
        callee_contract = contracts.ContractState(1, callee_nef, callee_manifest, 0, to_script_hash(callee_contract_script))

        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call(callee_contract.hash, "test_func")
        caller_script = sb.to_array()
        caller_nef = contracts.NEF(script=caller_script)
        caller_manifest = contracts.ContractManifest()
        caller_contract = contracts.ContractState(2, caller_nef, caller_manifest, 0, to_script_hash(caller_script))

        engine.snapshot.contracts.put(callee_contract)
        engine.snapshot.contracts.put(caller_contract)
        engine.load_script(vm.Script(caller_script))
        engine.execute()

        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertTrue(item.to_boolean())

    def test_checkwitness_helper_other_verifiable(self):
        engine = test_engine(has_snapshot=True, has_container=False, default_script=True)
        engine.script_container = TestIVerifiable()
        self.assertFalse(engine.checkwitness(types.UInt160(b'\x01' * 20)))

        # our test verifiable has 1 verifiable with a UInt160.zero() hash
        self.assertTrue(engine.checkwitness(types.UInt160.zero()))

    def test_checkwitness_with_public_key(self):
        kp = cryptography.KeyPair(b'\x01' * 32)
        redeemscript = contracts.Contract.create_signature_redeemscript(
            kp.public_key
        )
        intermediate_data = hashlib.sha256(redeemscript).digest()
        data = hashlib.new('ripemd160', intermediate_data).digest()
        hash_ = types.UInt160(data=data)

        engine = test_engine(has_snapshot=True, has_container=False, default_script=True)
        engine.script_container = TestIVerifiable()
        engine.script_container.script_hashes = [hash_]

        engine.push(vm.ByteStringStackItem(kp.public_key.to_array()))
        engine.invoke_syscall_by_name("System.Runtime.CheckWitness")

        self.assertEqual(1 , len(engine.current_context.evaluation_stack))
        item = engine.pop()
        self.assertTrue(item.to_boolean())

    def test_checkwitness_invalid_data(self):
        engine = test_engine()
        engine.push(vm.ByteStringStackItem(b''))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Runtime.CheckWitness")
        self.assertEqual("Supplied CheckWitness data is not a valid hash", str(context.exception))

    def test_gasleft(self):
        engine = test_engine()
        engine.is_test_mode = True

        sb = vm.ScriptBuilder()
        sb.emit_syscall(syscall_name_to_int("System.Runtime.GasLeft"))
        data = sb.to_array()

        # test with test mode
        engine.load_script(vm.Script(data))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack._items))
        item = engine.result_stack.pop()
        self.assertEqual(vm.IntegerStackItem(-1), item)

        """
        using (var engine = ApplicationEngine.Create(TriggerType.Application, null, null, gas:500))
        using (var script = new ScriptBuilder())
        {
            script.EmitSysCall(ApplicationEngine.System_Runtime_GasLeft);
            engine.LoadScript(script.ToArray());
            Assert.AreEqual(VMState.HALT, engine.Execute());
            Assert.AreEqual(engine.ResultStack.Count, 1);
            Console.WriteLine(engine.ResultStack.Pop().GetInteger());
        }
        """
        # test with actual consumption
        engine = test_engine()
        engine.is_test_mode = False
        engine.gas_amount = 500
        # we can re-use the script
        engine.load_script(vm.Script(data))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack._items))
        item = engine.result_stack.pop()
        self.assertEqual(vm.IntegerStackItem(20), item)

    def test_get_invocation_counter_ok(self):
        """
        We need to setup 2 contracts
        1) caller_contract: uses a System.Contract.Call to call callee_contract. This will increase the invocation counter of the callee contract
        2) callee_contract: uses a System.Runtime.GetInvocationCounter
        """
        engine = test_engine(has_snapshot=True, has_container=False, default_script=False)

        sb = vm.ScriptBuilder()
        sb.emit_syscall(syscall_name_to_int("System.Runtime.GetInvocationCounter"))
        callee_contract_script = sb.to_array()
        callee_nef = contracts.NEF(script=callee_contract_script)
        callee_manifest = contracts.ContractManifest("contract1")
        callee_manifest.abi.methods = [
            contracts.ContractMethodDescriptor("test_func", 0, [], contracts.ContractParameterType.ANY, True)
        ]
        callee_contract = contracts.ContractState(1, callee_nef, callee_manifest, 0, contract_hash(types.UInt160.zero(), callee_nef.checksum, callee_manifest.name))

        sb = vm.ScriptBuilder()
        sb.emit_dynamic_call(callee_contract.hash, "test_func")
        caller_script = sb.to_array()
        caller_nef = contracts.NEF(script=caller_script)
        caller_manifest = contracts.ContractManifest("contract2")
        caller_contract = contracts.ContractState(2, caller_nef, caller_manifest, 0, contract_hash(types.UInt160.zero(), caller_nef.checksum, caller_manifest.name))

        engine.snapshot.contracts.put(callee_contract)
        engine.snapshot.contracts.put(caller_contract)
        engine.load_script(vm.Script(caller_script))
        engine.execute()

        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertEqual(1, int(item))

    def test_runtime_log(self):
        message = ''

        def runtime_log(script_container: payloads.IVerifiable, msg: str):
            nonlocal message
            message = msg

        msgrouter.interop_log += runtime_log

        engine = test_engine()
        engine.push(vm.ByteStringStackItem('hello world'))
        engine.invoke_syscall_by_name("System.Runtime.Log")
        self.assertEqual('hello world', message)

        # try with too long message
        engine = test_engine()
        engine.push(vm.ByteStringStackItem(b'a' * (engine.MAX_NOTIFICATION_SIZE + 1)))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Runtime.Log")
        self.assertEqual("Log message length (1025) exceeds maximum allowed (1024)", str(context.exception))

    def test_runtime_getnotifications(self):
        engine = test_engine()

        target_hash = types.UInt160.zero()
        state = vm.ArrayStackItem(engine.reference_counter)
        notif1 = (object(), target_hash, b'notif1', state)
        notif2 = (object(), types.UInt160(b'\x01' * 20), b'notif2', state)
        notif3 = (object(), target_hash, b'notif3', state)

        engine.notifications = [notif1, notif2, notif3]
        engine.push(vm.ByteStringStackItem(target_hash.to_array()))
        engine.invoke_syscall_by_name("System.Runtime.GetNotifications")

        self.assertEqual(1, len(engine.current_context.evaluation_stack))
        notification_items = engine.pop()
        item1 = notification_items[0]
        item2 = notification_items[1]
        self.assertEqual(item1[0].to_array(), types.UInt160.zero().to_array())
        self.assertEqual(item1[1].to_array(), b'notif1')
        self.assertEqual(item2[0].to_array(), types.UInt160.zero().to_array())
        self.assertEqual(item2[1].to_array(), b'notif3')

    def test_runtime_getnotifications_limit_exceeded(self):
        engine = test_engine()
        target_hash = types.UInt160.zero()
        state = vm.ArrayStackItem(engine.reference_counter)

        # we can't adjust the limit, so we need to exceed it
        for i in range(0, engine.MAX_STACK_SIZE + 1):
            engine.notifications.append((object(), target_hash, b'notif' + str(i).encode(), state))
        engine.push(vm.ByteStringStackItem(target_hash.to_array()))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Runtime.GetNotifications")

        self.assertEqual("Notification count exceeds limits", str(context.exception))

    def test_runtime_notify(self):

        message = ''

        def runtime_notify(script_hash: types.UInt160, msg: str, state: vm.ArrayStackItem):
            nonlocal message
            message = msg

        msgrouter.interop_notify += runtime_notify

        engine = test_engine()
        engine.push(vm.ArrayStackItem(engine.reference_counter))  # state
        expected_message = 'my_notification_message'
        engine.push(vm.ByteStringStackItem(expected_message.encode()))  # event message
        engine.invoke_syscall_by_name("System.Runtime.Notify")

        self.assertEqual(message, expected_message)
        self.assertEqual(1, len(engine.notifications))
        item = engine.notifications[0]
        self.assertIsNone(item[0])  # == engine.script_container
        self.assertEqual(engine.current_scripthash, item[1])
        self.assertEqual(expected_message, item[2].decode())

    def test_runtime_notify_exceed_size(self):
        engine = test_engine()
        engine.push(vm.ArrayStackItem(engine.reference_counter))  # state
        engine.push(vm.ByteStringStackItem(b'\x01' * (engine.MAX_EVENT_SIZE + 1)))  # event messasge
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Runtime.Notify")
        self.assertEqual("Notify event name length (33) exceeds maximum allowed (32)", str(context.exception))
