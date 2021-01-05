import unittest
import json
from neo3 import vm, contracts, storage
from neo3.network import payloads
from neo3.contracts import syscall_name_to_int
from neo3.contracts.interop.contract import contract_call_internal
from neo3.core import to_script_hash, types, cryptography
from .utils import test_engine, test_block
from copy import deepcopy

"""
We compile the following smart contract for testing using neo3-boa

def main() -> str:
   return "hello world"
"""

raw_hello_world_nef = b'NEF3neo3-boa by COZ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e\x0c\x0bhello world@\xe3\xb9\x00\x17'

raw_hello_world_manifest = {
    "groups": [],
    "features": {
        "storage": False,
        "payable": False
    },
    "abi": {
        "hash": "0x20caf3711a574b0be8c5746d85db2ee1e85aed3b",
        "methods": [],
        "events": []
    },
    "permissions": [
        {
            "contract": "*",
            "methods": "*"
        }
    ],
    "trusts": [],
    "safemethods": [],
    "supportedstandards": [],
    "extra": None
}

hello_world_nef = contracts.NEF.deserialize_from_bytes(raw_hello_world_nef)
hello_world_manifest = contracts.manifest.ContractManifest.from_json(raw_hello_world_manifest)

raw_bye_world_nef = b'NEF3neo3-boa by COZ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x0c\tbye world@\x9f\xff\x95\xd0'
raw_bye_world_manifest = {
    "groups": [],
    "features": {
        "storage": False,
        "payable": False
    },
    "abi": {
        "hash": "0xbf15664f6d3ecb0ff82ebe001257263b50a314c4",
        "methods": [],
        "events": []
    },
    "permissions": [
        {
            "contract": "*",
            "methods": "*"
        }
    ],
    "trusts": [],
    "safemethods": [],
    "supportedstandards": [],
    "extra": None
}
bye_world_nef = contracts.NEF.deserialize_from_bytes(raw_bye_world_nef)
bye_world_manifest = contracts.ContractManifest.from_json(raw_bye_world_manifest)


"""
Contract3 code - compiled with neo3-boa

from boa3.builtin import public

def main() -> int:
    return 1

@public
def test_func() -> int:
    return 2

@public
def test_func2(value: int) -> int:
    return 1 + value
"""
raw_contract3_nef = b'NEF3neo3-boa by COZ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x11@\x12@W\x00\x01\x11x\x9e@P\x9c\xb5\xb0'
raw_contract3_manifest = {
    "groups": [],
    "features": {
        "storage": False,
        "payable": False
    },
    "abi": {
        "hash": "0xad8c3929e008a0a981dcb5e3c3a0928becdc2a41",
        "methods": [
            {
                "name": "test_func",
                "offset": 2,
                "parameters": [],
                "returntype": "Integer"
            },
            {
                "name": "test_func2",
                "offset": 4,
                "parameters": [
                    {
                        "name": "value",
                        "type": "Integer"
                    }
                ],
                "returntype": "Integer"
            }
        ],
        "events": []
    },
    "permissions": [
        {
            "contract": "*",
            "methods": "*"
        }
    ],
    "trusts": [],
    "safemethods": [],
    "supportedstandards": [],
    "extra": None
}

contract3_nef = contracts.NEF.deserialize_from_bytes(raw_contract3_nef)
contract3_manifest = contracts.ContractManifest.from_json(raw_contract3_manifest)


class RuntimeInteropTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_validate_sample_contract(self):
        engine = test_engine()
        engine.load_script(vm.Script(hello_world_nef.script))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack._items))
        item = engine.result_stack.pop()
        self.assertIsInstance(item, vm.ByteStringStackItem)
        self.assertEqual(vm.ByteStringStackItem(b'hello world'), item)

    def test_contract_create_invalid_manifest_or_script(self):
        # script len 0
        engine = test_engine(has_snapshot=True)
        invalid_script = b''
        engine.push(vm.ByteStringStackItem(str(hello_world_manifest).encode()))
        engine.push(vm.ByteStringStackItem(invalid_script))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Contract.Create")
        self.assertEqual("Invalid script or manifest length", str(context.exception))

        # script too long
        invalid_script = b'\x00' * (engine.MAX_CONTRACT_LENGTH + 1)
        engine.push(vm.ByteStringStackItem(str(hello_world_manifest).encode()))
        engine.push(vm.ByteStringStackItem(invalid_script))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Contract.Create")
        self.assertEqual("Invalid script or manifest length", str(context.exception))

        # manifest len 0
        invalid_manifest = b''
        engine.push(vm.ByteStringStackItem(invalid_manifest))
        engine.push(vm.ByteStringStackItem(hello_world_nef.script))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Contract.Create")
        self.assertEqual("Invalid script or manifest length", str(context.exception))

        # manifest too long
        invalid_manifest = b'\x00' * (contracts.ContractManifest.MAX_LENGTH + 1)
        engine.push(vm.ByteStringStackItem(invalid_manifest))
        engine.push(vm.ByteStringStackItem(hello_world_nef.script))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Contract.Create")
        self.assertEqual("Invalid script or manifest length", str(context.exception))

    def test_contract_create_ok(self):
        engine = test_engine(has_snapshot=True)
        sb = vm.ScriptBuilder()
        sb.emit_push(str(hello_world_manifest).encode())
        sb.emit_push(hello_world_nef.script)
        sb.emit_syscall(syscall_name_to_int("System.Contract.Create"))
        engine.load_script(vm.Script(sb.to_array()))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack._items))
        item = engine.result_stack.pop()
        # returns a serialized contract state
        self.assertEqual(hello_world_nef.script, item[0].to_array())
        self.assertEqual(hello_world_manifest, contracts.ContractManifest.from_json(json.loads(item[1].to_array())))
        self.assertEqual(contracts.ContractFeatures.HAS_STORAGE in hello_world_manifest.features, item[2])
        self.assertEqual(contracts.ContractFeatures.PAYABLE in hello_world_manifest.features, item[3])
        return engine

    def test_contract_create_already_exits(self):
        engine = test_engine(has_snapshot=True)

        # store store the contract ourselves
        contract = storage.ContractState(hello_world_nef.script, hello_world_manifest)
        engine.snapshot.contracts.put(contract)
        # now try to create a contract
        engine.push(vm.ByteStringStackItem(str(hello_world_manifest).encode()))
        engine.push(vm.ByteStringStackItem(hello_world_nef.script))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Contract.Create")
        self.assertEqual("Contract already exists", str(context.exception))

    def test_contract_create_manifest_mismatch(self):
        engine = test_engine(has_snapshot=True)
        manifest_copy = deepcopy(hello_world_manifest)
        # invalidate the associated contract hash
        manifest_copy.abi.contract_hash = types.UInt160.zero()
        engine.push(vm.ByteStringStackItem(str(manifest_copy).encode()))
        engine.push(vm.ByteStringStackItem(hello_world_nef.script))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Contract.Create")
        self.assertEqual("Error: manifest does not match with script", str(context.exception))

    def test_contract_destroy_not_found(self):
        # contract destroy must be called by the contract itself, the function uses the engine.current_script hash for
        # locating the contract to delete. We set the engine to have a default script, which does not match a contract
        # that exists in storage
        engine = test_engine(has_snapshot=True, default_script=True)
        # we also place at least 1 contract in storage and validate it doesn't get removed
        contract = storage.ContractState(hello_world_nef.script, hello_world_manifest)
        engine.snapshot.contracts.put(contract)

        # now call the destroy function
        engine.invoke_syscall_by_name("System.Contract.Destroy")
        # and assert nothing changed to our contracts storage
        self.assertIsNotNone(engine.snapshot.contracts.try_get(contract.script_hash()))

    def test_contract_destroy_ok(self):
        engine = test_engine(has_snapshot=True, default_script=False)
        # for this test we modify our contract to also have storage, to validate it gets cleared properly
        contract = storage.ContractState(hello_world_nef.script, deepcopy(hello_world_manifest))
        contract.manifest.features |= contracts.ContractFeatures.HAS_STORAGE
        engine.snapshot.contracts.put(contract)

        storage_key = storage.StorageKey(contract.script_hash(), b'firstkey')
        storage_item = storage.StorageItem(b'firstitem')
        engine.snapshot.storages.put(storage_key, storage_item)

        # setup the engine by loading the contract script such that we can call destroy on _that_ contract
        engine.load_script(vm.Script(contract.script))
        engine.invoke_syscall_by_name("System.Contract.Destroy")
        self.assertIsNone(engine.snapshot.contracts.try_get(contract.script_hash()))
        self.assertIsNone(engine.snapshot.storages.try_get(storage_key))

    def test_contract_update_ok(self):
        engine = test_engine(has_snapshot=True, default_script=False)
        # the real world setup should be
        # 1) deploy a smart contract with an update function that internally calls "System.Contract.Update"
        # 2) perform a contract call to the old contract and supply a new script + manifest as arguments
        #
        # here we will bypass deploying a contract with an update function and directly call "System.Contract.Update" on
        # the engine. We start by persisting the contract we want to update
        contract = storage.ContractState(hello_world_nef.script, hello_world_manifest)
        engine.snapshot.contracts.put(contract)

        # we load the old contract as script to properly setup "engine.current_scripthash"
        engine.load_script(vm.Script(contract.script))
        # next we push the necessary items on the stack before calling the update function
        engine.push(vm.ByteStringStackItem(str(bye_world_manifest).encode()))
        engine.push(vm.ByteStringStackItem(bye_world_nef.script))
        engine.invoke_syscall_by_name("System.Contract.Update")

        # test that we cannot find the old contract anymore
        self.assertIsNone(engine.snapshot.contracts.try_get(contract.script_hash()))
        new_contract = storage.ContractState(bye_world_nef.script, bye_world_manifest)
        # make sure the new contract is still there (and that we not just cleared the whole storage)
        self.assertIsNotNone(engine.snapshot.contracts.try_get(new_contract.script_hash()))

    def test_contract_update_exceptions1(self):
        # asking to update a contract that is not already deployed
        engine = test_engine(has_snapshot=True, default_script=True)
        fake_manifest = b'\x01' * 10
        fake_nef = b'\x01' * 10
        engine.push(vm.ByteStringStackItem(fake_manifest))
        engine.push(vm.ByteStringStackItem(fake_nef))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Contract.Update")
        self.assertEqual("Can't find contract to update", str(context.exception))

    def test_contract_update_exceptions2(self):
        # asking to update with an invalid new script
        engine = test_engine(has_snapshot=True, default_script=False)

        contract = storage.ContractState(hello_world_nef.script, hello_world_manifest)
        engine.snapshot.contracts.put(contract)

        # we load the stored as script to properly setup "engine.current_scripthash"
        engine.load_script(vm.Script(contract.script))
        # next we push the necessary items on the stack before calling the update function
        fake_manifest = b''
        fake_nef = b''
        engine.push(vm.ByteStringStackItem(fake_manifest))
        engine.push(vm.ByteStringStackItem(fake_nef))

        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Contract.Update")
        self.assertEqual("Invalid script length: 0", str(context.exception))

    def test_contract_update_exceptions3(self):
        # asking to update without making changes to the script
        engine = test_engine(has_snapshot=True, default_script=False)

        contract = storage.ContractState(hello_world_nef.script, hello_world_manifest)
        engine.snapshot.contracts.put(contract)

        # we load the stored as script to properly setup "engine.current_scripthash"
        engine.load_script(vm.Script(contract.script))
        # next we push the necessary items on the stack before calling the update function
        fake_manifest = b''
        engine.push(vm.ByteStringStackItem(fake_manifest))
        # same script as already exists in storage
        engine.push(vm.ByteStringStackItem(contract.script))

        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Contract.Update")
        self.assertEqual("Nothing to update", str(context.exception))

    def test_contract_update_exceptions4(self):
        # asking to update with a new script but with an invalid (0 length) manifest
        engine = test_engine(has_snapshot=True, default_script=False)

        contract_old = storage.ContractState(hello_world_nef.script, hello_world_manifest)
        engine.snapshot.contracts.put(contract_old)

        # we load the stored as script to properly setup "engine.current_scripthash"
        engine.load_script(vm.Script(contract_old.script))
        # next we push the necessary items on the stack before calling the update function
        bad_manifest = b''
        engine.push(vm.ByteStringStackItem(bad_manifest))
        engine.push(vm.ByteStringStackItem(bye_world_nef.script))

        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Contract.Update")
        self.assertEqual("Invalid manifest length: 0", str(context.exception))

    def test_contract_update_exceptions5(self):
        # asking to update with a new script but with an invalid manifest (from a different contract)
        engine = test_engine(has_snapshot=True, default_script=False)

        contract_old = storage.ContractState(hello_world_nef.script, hello_world_manifest)
        engine.snapshot.contracts.put(contract_old)

        # we load the stored as script to properly setup "engine.current_scripthash"
        engine.load_script(vm.Script(contract_old.script))
        # next we push the necessary items on the stack before calling the update function
        bad_manifest = contract_old.manifest
        engine.push(vm.ByteStringStackItem(str(bad_manifest).encode()))
        engine.push(vm.ByteStringStackItem(bye_world_nef.script))

        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Contract.Update")
        self.assertEqual("Error: manifest does not match with script", str(context.exception))

    def test_contract_update_exceptions6(self):
        # asking to update with a new script but with an invalid manifest (new manifest does not support storage,
        # while the old contract has existing storage)
        engine = test_engine(has_snapshot=True, default_script=False)

        contract_old = storage.ContractState(hello_world_nef.script, deepcopy(hello_world_manifest))
        contract_old.manifest.features |= contracts.ContractFeatures.HAS_STORAGE
        engine.snapshot.contracts.put(contract_old)

        storage_key = storage.StorageKey(contract_old.script_hash(), b'firstkey')
        storage_item = storage.StorageItem(b'firstitem')
        engine.snapshot.storages.put(storage_key, storage_item)

        # we load the stored as script to properly setup "engine.current_scripthash"
        engine.load_script(vm.Script(contract_old.script))
        # next we push the necessary items on the stack before calling the update funcztion
        # we take the matching manifest and change it to have no storage
        bad_manifest = deepcopy(bye_world_manifest)
        bad_manifest.features &= ~contracts.ContractFeatures.HAS_STORAGE
        engine.push(vm.ByteStringStackItem(str(bad_manifest).encode()))
        engine.push(vm.ByteStringStackItem(bye_world_nef.script))

        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Contract.Update")
        self.assertEqual("Error: New contract does not support storage while old contract has existing storage", str(context.exception))

    def test_contract_call(self):
        engine = test_engine(has_snapshot=True, default_script=False)
        # current executing contract
        contract = storage.ContractState(hello_world_nef.script, hello_world_manifest)
        engine.snapshot.contracts.put(contract)
        # target contract
        target_contract = storage.ContractState(contract3_nef.script, contract3_manifest)
        engine.snapshot.contracts.put(target_contract)
        engine.load_script(vm.Script(contract.script))
        array = vm.ArrayStackItem(engine.reference_counter)
        array.append(vm.IntegerStackItem(3))
        engine.push(array)  # args
        engine.push(vm.ByteStringStackItem("test_func2"))  # method
        engine.push(vm.ByteStringStackItem(target_contract.script_hash().to_array()))
        engine.invoke_syscall_by_name("System.Contract.Call")
        engine.execute()

        self.assertEqual(2, len(engine.result_stack))
        main_contract_return_value = engine.result_stack.pop()
        syscall_called_contract_return_value = engine.result_stack.pop()
        self.assertEqual("hello world", main_contract_return_value.to_array().decode())
        self.assertEqual(4, int(syscall_called_contract_return_value))

    def test_contract_call_exceptions(self):
        engine = test_engine(has_snapshot=True, default_script=False)
        engine.load_script(vm.Script(hello_world_nef.script))
        with self.assertRaises(ValueError) as context:
            contract_call_internal(engine, types.UInt160.zero(), "_invalid_method", vm.ArrayStackItem(engine.reference_counter), contracts.native.CallFlags)
        self.assertEqual("[System.Contract.Call] Method not allowed to start with _", str(context.exception))

        # can't find contract
        with self.assertRaises(ValueError) as context:
            contract_call_internal(engine, types.UInt160.zero(), "valid_method", vm.ArrayStackItem(engine.reference_counter), contracts.native.CallFlags)
        self.assertEqual("[System.Contract.Call] Can't find target contract", str(context.exception))

        target_contract = storage.ContractState(contract3_nef.script, contract3_manifest)
        engine.snapshot.contracts.put(target_contract)

        # modify the manifest of the current executing contract to only allow to call 1 specific method on other contracts
        new_current_manifest = deepcopy(hello_world_manifest)
        new_current_manifest.permissions = [contracts.ContractPermission(
            contracts.ContractPermissionDescriptor(),  # allow to call any contract
            contracts.WildcardContainer(['method_aaaa'])  # allowing to call the listed method only
        )]
        new_current_contract = storage.ContractState(hello_world_nef.script, new_current_manifest)
        engine.snapshot.contracts.put(new_current_contract)
        with self.assertRaises(ValueError) as context:
            contract_call_internal(engine, target_contract.script_hash(), "invalid_method", vm.ArrayStackItem(engine.reference_counter), contracts.native.CallFlags)
        self.assertEqual("[System.Contract.Call] Not allowed to call target method 'invalid_method' according to manifest", str(context.exception))

        # restore current contract to its original form and try to call a non-existing contract
        current_contract = storage.ContractState(hello_world_nef.script, hello_world_manifest)
        engine.snapshot.contracts.delete(new_current_contract.script_hash())
        engine.snapshot.contracts.put(current_contract)

        with self.assertRaises(ValueError) as context:
            contract_call_internal(engine, target_contract.script_hash(), "invalid_method", vm.ArrayStackItem(engine.reference_counter), contracts.native.CallFlags)
        self.assertEqual("[System.Contract.Call] requested target method 'invalid_method' does not exist on target contract", str(context.exception))

        # call the target method with invalid number of arguments
        array = vm.ArrayStackItem(engine.reference_counter)
        array.append([vm.NullStackItem(), vm.NullStackItem()])
        with self.assertRaises(ValueError) as context:
            contract_call_internal(engine, target_contract.script_hash(), "test_func", array, contracts.native.CallFlags)
        self.assertEqual("[System.Contract.Call] Invalid number of contract arguments. Expected 0 actual 2", str(context.exception))

    def test_contract_call_ex(self):
        # code is the same as "test_contract_call" except for the interop
        engine = test_engine(has_snapshot=True, default_script=False)
        # current executing contract
        contract = storage.ContractState(hello_world_nef.script, hello_world_manifest)
        engine.snapshot.contracts.put(contract)
        # target contract
        target_contract = storage.ContractState(contract3_nef.script, contract3_manifest)
        engine.snapshot.contracts.put(target_contract)
        engine.load_script(vm.Script(contract.script))
        engine.push(vm.IntegerStackItem(15))  # call flags
        array = vm.ArrayStackItem(engine.reference_counter)
        array.append(vm.IntegerStackItem(3))
        engine.push(array)  # args
        engine.push(vm.ByteStringStackItem("test_func2"))  # method
        engine.push(vm.ByteStringStackItem(target_contract.script_hash().to_array()))
        engine.invoke_syscall_by_name("System.Contract.CallEx")
        engine.execute()

        self.assertEqual(2, len(engine.result_stack))
        main_contract_return_value = engine.result_stack.pop()
        syscall_called_contract_return_value = engine.result_stack.pop()
        self.assertEqual("hello world", main_contract_return_value.to_array().decode())
        self.assertEqual(4, int(syscall_called_contract_return_value))

    def test_contract_call_ex_fail(self):
        engine = test_engine()
        array = vm.ArrayStackItem(engine.reference_counter)
        engine.push(vm.IntegerStackItem(123))  # invalid value for CallFlags
        engine.push(array)  # args
        engine.push(vm.ByteStringStackItem("test_func2"))  # method
        engine.push(vm.ByteStringStackItem(b'\x00')) # call flags

        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Contract.CallEx")
        self.assertIn("Failed to convert parameter stack item", str(context.exception))

    def test_contract_is_standard_ok(self):
        keypair = cryptography.KeyPair(b'\x01' * 32)
        sig_contract = contracts.Contract.create_signature_contract(keypair.public_key)

        engine = test_engine(has_snapshot=True)
        contract = storage.ContractState(sig_contract.script, contracts.ContractManifest(sig_contract.script_hash))
        engine.snapshot.contracts.put(contract)
        engine.push(vm.ByteStringStackItem(contract.script_hash().to_array()))
        engine.invoke_syscall_by_name("System.Contract.IsStandard")
        engine.execute()
        self.assertEqual(True, engine.result_stack.pop().to_boolean())

    def test_contract_is_standard_fail(self):
        # can't find contract
        engine = test_engine(has_snapshot=True)
        engine.push(vm.ByteStringStackItem(types.UInt160.zero().to_array()))
        engine.invoke_syscall_by_name("System.Contract.IsStandard")
        engine.execute()
        self.assertEqual(False, engine.result_stack.pop().to_boolean())

    def test_contract_is_standard_fail2(self):
        # can find contract, but is not a signature contract
        engine = test_engine(has_snapshot=True)

        # create a non-standard contract
        script = b'\x01\x02\x03'
        script_hash = to_script_hash(script)
        manifest = contracts.ContractManifest(script_hash)
        contract = storage.ContractState(script, manifest)
        engine.snapshot.contracts.put(contract)

        # push function argument and call
        engine.push(vm.ByteStringStackItem(script_hash.to_array()))
        engine.invoke_syscall_by_name("System.Contract.IsStandard")
        engine.execute()
        self.assertEqual(False, engine.result_stack.pop().to_boolean())

    def test_contract_is_standard_fail3(self):
        # test on witnesses of a transaction
        engine = test_engine(has_container=True, has_snapshot=True)
        witness = payloads.Witness(invocation_script=b'\x01', verification_script=b'\x02')
        engine.script_container.witnesses = [witness]
        engine.push(vm.ByteStringStackItem(witness.script_hash().to_array()))
        engine.invoke_syscall_by_name("System.Contract.IsStandard")
        engine.execute()
        self.assertEqual(False, engine.result_stack.pop().to_boolean())

    def test_contract_call_flags(self):
        engine = test_engine()
        engine.invoke_syscall_by_name("System.Contract.GetCallFlags")
        self.assertEqual(1, len(engine.current_context.evaluation_stack))
        self.assertEqual(contracts.CallFlags.ALL, contracts.CallFlags(int(engine.pop())))

    def test_contract_create_standard_account(self):
        keypair = cryptography.KeyPair(b'\x01' * 32)
        engine = test_engine()
        engine.push(vm.ByteStringStackItem(keypair.public_key.to_array()))
        engine.invoke_syscall_by_name("System.Contract.CreateStandardAccount")
        engine.execute()
        self.assertEqual(1, len(engine.result_stack))
        signature_redeem_script = contracts.Contract.create_signature_redeemscript(keypair.public_key)
        result_item = types.UInt160(engine.result_stack.pop().to_array())
        self.assertEqual(to_script_hash(signature_redeem_script), result_item)

