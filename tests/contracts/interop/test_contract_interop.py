import unittest
from neo3 import vm, contracts, storage
from neo3.network import payloads
from neo3.core import to_script_hash, types, cryptography
from tests.contracts.interop.utils import test_engine, test_tx
from copy import deepcopy

"""
We compile the following smart contract for testing using neo3-boa

@public
def main() -> str:
   return "hello world"
"""

raw_hello_world_nef = b'NEF3neo3-boa by COZ-0.7.0.0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0e\x0c\x0bhello world@_h.\xd7'
raw_hello_world_manifest = {
    "name": "hello_world",
    "groups": [],
    "features": {},
    "abi": {
        "methods": [
            {
                "name": "main",
                "offset": 0,
                "parameters": [],
                "returntype": "String",
                "safe": False
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
    "supportedstandards": [],
    "extra": None
}

hello_world_nef = contracts.NEF.deserialize_from_bytes(raw_hello_world_nef)
hello_world_manifest = contracts.manifest.ContractManifest.from_json(raw_hello_world_manifest)

raw_bye_world_nef = b'NEF3neo3-boa by COZ-0.7.0.0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x0c\tbye world@NLE\xa8'
raw_bye_world_manifest = {
    "name": "bye_world",
    "groups": [],
    "features": {},
    "abi": {
        "methods": [
            {
                "name": "main",
                "offset": 0,
                "parameters": [],
                "returntype": "String",
                "safe": False
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
raw_contract3_nef = b'NEF3neo3-boa by COZ-0.7.0.0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0b\x11@\x12@W\x00\x01\x11x\x9e@\xaa,\x0bW'
raw_contract3_manifest = {
    "name": "contract3",
    "groups": [],
    "features": {},
    "abi": {
        "methods": [
            {
                "name": "test_func",
                "offset": 2,
                "parameters": [],
                "returntype": "Integer",
                "safe": False
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
                "returntype": "Integer",
                "safe": False
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

    @unittest.SkipTest
    def test_contract_create_invalid_manifest_or_script(self):
        # script len 0
        engine = test_engine(has_snapshot=True)
        engine.script_container = test_tx(1)
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

    def test_contract_call(self):
        engine = test_engine(has_snapshot=True, default_script=False)
        # current executing contract
        fake_hash = types.UInt160.deserialize_from_bytes(b'\x01' * 20)
        contract = contracts.ContractState(0, hello_world_nef, hello_world_manifest, 0, fake_hash)
        engine.snapshot.contracts.put(contract)
        # target contract
        fake_hash2 = types.UInt160.deserialize_from_bytes(b'\x02' * 20)
        target_contract = contracts.ContractState(1, contract3_nef, contract3_manifest, 0, fake_hash2)
        engine.snapshot.contracts.put(target_contract)
        engine.load_script(vm.Script(contract.script))
        array = vm.ArrayStackItem(engine.reference_counter)
        array.append(vm.IntegerStackItem(3))
        engine.push(array)  # args
        engine.push(vm.IntegerStackItem(15))  # callflags
        engine.push(vm.ByteStringStackItem("test_func2"))  # method
        engine.push(vm.ByteStringStackItem(target_contract.hash.to_array()))
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

        # can't find contract
        with self.assertRaises(ValueError) as context:
            engine._contract_call_internal(types.UInt160.zero(), "valid_method", contracts.CallFlags.ALL, False, vm.ArrayStackItem(engine.reference_counter))
        self.assertEqual("[System.Contract.Call] Can't find target contract", str(context.exception))

        fake_contract_hash = types.UInt160(b'\x01' * 20)
        target_contract = contracts.ContractState(0, contract3_nef, contract3_manifest, 0, fake_contract_hash)
        engine.snapshot.contracts.put(target_contract)

        # modify the manifest of the current executing contract to only allow to call 1 specific method on other contracts
        new_current_manifest = deepcopy(hello_world_manifest)
        new_current_manifest.permissions = [contracts.ContractPermission(
            contracts.ContractPermissionDescriptor(),  # allow to call any contract
            contracts.WildcardContainer(['method_aaaa'])  # allowing to call the listed method only
        )]
        fake_contract_hash2 = types.UInt160(b'\x02' * 20)
        new_current_contract = contracts.ContractState(1, hello_world_nef, new_current_manifest, 0, fake_contract_hash2)
        engine.snapshot.contracts.put(new_current_contract)
        with self.assertRaises(ValueError) as context:
            engine._contract_call_internal(target_contract.hash, "invalid_method", contracts.CallFlags.ALL, False, vm.ArrayStackItem(engine.reference_counter))
        self.assertEqual("[System.Contract.Call] Method 'invalid_method' with 0 arguments does not exist on target contract", str(context.exception))

        # restore current contract to its original form and try to call a non-existing contract
        current_contract = contracts.ContractState(1, hello_world_nef, hello_world_manifest, 1, fake_contract_hash2)
        engine.snapshot.contracts.delete(new_current_contract.hash)
        engine.snapshot.contracts.put(current_contract)

        with self.assertRaises(ValueError) as context:
            engine._contract_call_internal(target_contract.hash, "invalid_method", contracts.CallFlags.ALL, False, vm.ArrayStackItem(engine.reference_counter))
        self.assertEqual("[System.Contract.Call] Method 'invalid_method' with 0 arguments does not exist on target contract", str(context.exception))

        # call the target method with invalid number of arguments
        array = vm.ArrayStackItem(engine.reference_counter)
        array.append([vm.NullStackItem(), vm.NullStackItem()])
        with self.assertRaises(ValueError) as context:
            engine._contract_call_internal(target_contract.hash, "test_func", contracts.CallFlags.ALL, False, array)
        self.assertEqual("[System.Contract.Call] Method 'test_func' with 2 arguments does not exist on target contract", str(context.exception))

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
