import unittest
from neo3 import vm, contracts, storage, settings
from neo3.core import to_script_hash
from neo3.contracts import interop
from tests.contracts.interop.utils import syscall_name_to_int, test_engine

"""
In the early days, when all these tests were written, contract hashes were determined by hashing the contract script.
This means that ApplicationEngine.calling_script_hash equaled a hash of the script we loaded via load_script(). 
That knowledge was used initially for creating all the tests below. 
 
The contract hash computation changed with:
- https://github.com/neo-project/neo/pull/2244
- https://github.com/neo-project/neo/pull/2240

Because of this change some tricks are used internally by NEO for updating the `calling_script_hash` to the correct contract hash. 
These tricks only happen when calling contracts via `System.Contract.Call` or via the OpCode.CALLT. 
Using these make the tests far more complex, so instead we keep the old logic. \

In summary this means; 
ContractState objects are created where the ContractHash is still based on the old method of hashing
the contract script. Technically this is incorrect, but makes testing much easier.
"""


class StorageInteropTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    @classmethod
    def setUpClass(cls) -> None:
        # blockchain.Blockchain()
        pass

    def setUp(self) -> None:
        self.RET = b'\x40'
        self.manifest = contracts.ContractManifest("contract_name")
        self.nef = contracts.NEF(script=self.RET)
        self.contract_hash = to_script_hash(self.nef.script)
        self.contract = contracts.ContractState(1, self.nef, self.manifest, 0, self.contract_hash)
        self.contract.manifest.abi.methods = [
            contracts.ContractMethodDescriptor("test_func", 0, [], contracts.ContractParameterType.ANY, True)
        ]

    def test_get_context(self):
        engine = test_engine(has_snapshot=True)
        engine.snapshot.contracts.put(self.contract)
        ctx = engine.invoke_syscall_by_name("System.Storage.GetContext")
        self.assertIsInstance(ctx, storage.StorageContext)
        self.assertEqual(self.contract.id, ctx.id)
        self.assertFalse(ctx.is_read_only)

        # repeat for read only
        ctx = engine.invoke_syscall_by_name("System.Storage.GetReadOnlyContext")
        self.assertIsInstance(ctx, storage.StorageContext)
        self.assertEqual(self.contract.id, ctx.id)
        self.assertTrue(ctx.is_read_only)

    def test_as_readonly(self):
        engine = test_engine(has_snapshot=True)
        engine.snapshot.contracts.put(self.contract)
        ctx = engine.invoke_syscall_by_name("System.Storage.GetContext")
        self.assertFalse(ctx.is_read_only)
        engine.push(vm.StackItem.from_interface(ctx))
        ctx = engine.invoke_syscall_by_name("System.Storage.AsReadOnly")
        self.assertTrue(ctx.is_read_only)

    def test_storage_get_key_not_found(self):
        engine = test_engine(has_snapshot=True, has_container=True)
        script = vm.ScriptBuilder()
        # key parameter for the `Storage.Get` syscall
        script.emit(vm.OpCode.PUSH2)
        script.emit_syscall(syscall_name_to_int("System.Storage.GetContext"))
        # at this point our stack looks like follows
        # * storage context
        # * key
        script.emit_syscall(syscall_name_to_int("System.Storage.Get"))
        engine.load_script(vm.Script(script.to_array()))

        # we have to store our contract or some sanity checks will fail (like getting a StorageContext
        nef = contracts.NEF(script=script.to_array())
        contract = contracts.ContractState(1, nef, self.manifest, 0, to_script_hash(nef.script))
        engine.snapshot.contracts.put(contract)

        storage_key = storage.StorageKey(contract.id, b'\x01')
        storage_item = storage.StorageItem(b'\x11')
        engine.snapshot.storages.put(storage_key, storage_item)

        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertIsInstance(item, vm.NullStackItem)

    def test_storage_get_ok(self):
        engine = test_engine(has_snapshot=True)
        engine.snapshot.contracts.put(self.contract)

        storage_key = storage.StorageKey(self.contract.id, b'\x01')
        storage_item = storage.StorageItem(b'\x11')
        engine.snapshot.storages.put(storage_key, storage_item)

        ctx = engine.invoke_syscall_by_name("System.Storage.GetContext")
        engine.push(vm.ByteStringStackItem(storage_key.key))
        engine.push(vm.StackItem.from_interface(ctx))
        returned_value = engine.invoke_syscall_by_name("System.Storage.Get")

        self.assertEqual(storage_item.value, returned_value)

    def test_storage_get_ok2(self):
        # this is basically the same as `test_storage_get_ok`
        # but performed by executing a script
        # it exists to validate that the `Optional[bytes]` return value is converted properly
        engine = test_engine(has_snapshot=True)
        script = vm.ScriptBuilder()
        script.emit(vm.OpCode.PUSH1)
        script.emit_syscall(syscall_name_to_int("System.Storage.GetContext"))
        script.emit_syscall(syscall_name_to_int("System.Storage.Get"))
        engine.load_script(vm.Script(script.to_array()))

        nef = contracts.NEF(script=script.to_array())
        contract_hash = to_script_hash(nef.script)
        contract = contracts.ContractState(1, nef, self.manifest, 0, contract_hash)
        engine.snapshot.contracts.put(contract)

        storage_key = storage.StorageKey(contract.id, b'\x01')
        storage_item = storage.StorageItem(b'\x11')
        engine.snapshot.storages.put(storage_key, storage_item)

        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertEqual(storage_item.value, item.to_array())

    def test_storage_find(self):
        # settings.storage.default_provider = 'leveldb'
        engine = test_engine(has_snapshot=True)
        engine.snapshot.contracts.put(self.contract)

        storage_key1 = storage.StorageKey(self.contract.id, b'\x01')
        storage_item1 = storage.StorageItem(b'\x11')
        engine.snapshot.storages.put(storage_key1, storage_item1)
        storage_key2 = storage.StorageKey(self.contract.id, b'\x02')
        storage_item2 = storage.StorageItem(b'\x22')
        engine.snapshot.storages.put(storage_key2, storage_item2)

        ctx = engine.invoke_syscall_by_name("System.Storage.GetContext")
        engine.push(vm.IntegerStackItem(contracts.FindOptions.NONE))
        engine.push(vm.ByteStringStackItem(storage_key1.key))
        engine.push(vm.StackItem.from_interface(ctx))

        it = engine.invoke_syscall_by_name("System.Storage.Find")
        self.assertIsInstance(it, interop.StorageIterator)

        with self.assertRaises(ValueError) as context:
            it.value()
        self.assertEqual("Cannot call 'value' without having advanced the iterator at least once", str(context.exception))

        self.assertTrue(it.next())

        struct = it.value()  # 0 key, 1 value
        self.assertEqual(storage_item1.value, struct[1].to_array())

    def test_storage_put_helper_parameter_validation(self):
        with self.assertRaises(ValueError) as context:
            key = (b'\x01' * contracts.interop.MAX_STORAGE_KEY_SIZE) + b'\x01'
            contracts.interop.storage_put(None, None, key, b'')
        self.assertEqual(f"Storage key length exceeds maximum of {contracts.interop.MAX_STORAGE_KEY_SIZE}", str(context.exception))

        with self.assertRaises(ValueError) as context:
            value = (b'\x01' * contracts.interop.MAX_STORAGE_VALUE_SIZE) + b'\x01'
            contracts.interop.storage_put(None, None, b'', value)
        self.assertEqual(f"Storage value length exceeds maximum of {contracts.interop.MAX_STORAGE_VALUE_SIZE}", str(context.exception))

        with self.assertRaises(ValueError) as context:
            ctx = storage.StorageContext(None, is_read_only=True)
            contracts.interop.storage_put(None, ctx, b'', b'')
        self.assertEqual("Cannot persist to read-only storage context", str(context.exception))

    def test_storage_put_new(self):
        # see `test_storage_get_key_not_found()` for a description on why the storage is setup with a script as is

        # setup
        engine = test_engine(has_snapshot=True)
        script = vm.ScriptBuilder()
        script.emit(vm.OpCode.PUSH2)  # storage put value
        script.emit(vm.OpCode.PUSH1)  # storage put key
        script.emit_syscall(syscall_name_to_int("System.Storage.GetContext"))
        script.emit_syscall(syscall_name_to_int("System.Storage.Put"))
        engine.load_script(vm.Script(script.to_array()))

        nef = contracts.NEF(script=script.to_array())
        manifest = contracts.ContractManifest(f"contractname1")
        manifest.abi.methods = [
            contracts.ContractMethodDescriptor("test_func", 0, [], contracts.ContractParameterType.ANY, True)
        ]
        hash_ = to_script_hash(nef.script)

        contract = contracts.ContractState(1, nef, manifest, 0, hash_)
        engine.snapshot.contracts.put(contract)

        engine.execute()

        self.assertEqual(vm.VMState.HALT, engine.state)
        storage_key = storage.StorageKey(1, b'\x01')
        item = engine.snapshot.storages.try_get(storage_key)
        self.assertIsNotNone(item)
        self.assertEqual(b'\x02', item.value)

    def test_storage_put_overwrite(self):
        # test with new data being shorter than the old data
        engine = test_engine(has_snapshot=True)
        key = b'\x01'
        storage_key = storage.StorageKey(1, key)
        storage_item = storage.StorageItem(b'\x11\x22\x33')
        engine.snapshot.storages.put(storage_key, storage_item)

        ctx = storage.StorageContext(1, is_read_only=False)
        new_item_value = b'\x11\x22'
        contracts.interop.storage_put(engine, ctx, key, new_item_value)

        item = engine.snapshot.storages.get(storage_key)
        self.assertIsNotNone(item)
        self.assertEqual(new_item_value, item.value)

        # now test with data being longer than before
        longer_item_value = b'\x11\x22\x33\x44'
        contracts.interop.storage_put(engine, ctx, key, longer_item_value)

        item = engine.snapshot.storages.get(storage_key)
        self.assertIsNotNone(item)
        self.assertEqual(longer_item_value, item.value)

    def test_storage_delete_readonly_context(self):
        engine = test_engine(has_snapshot=True)

        engine.snapshot.contracts.put(self.contract)

        storage_key = storage.StorageKey(self.contract.id, b'\x01')
        storage_item = storage.StorageItem(b'\x11')
        engine.snapshot.storages.put(storage_key, storage_item)

        ctx = engine.invoke_syscall_by_name("System.Storage.GetReadOnlyContext")
        engine.push(vm.ByteStringStackItem(storage_key.key))
        engine.push(vm.StackItem.from_interface(ctx))

        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Storage.Delete")
        self.assertEqual("Cannot delete from read-only storage context", str(context.exception))

    def test_delete_ok(self):
        engine = test_engine(has_snapshot=True)
        engine.snapshot.contracts.put(self.contract)

        storage_key = storage.StorageKey(self.contract.id, b'\x01')
        storage_item = storage.StorageItem(b'\x11')
        engine.snapshot.storages.put(storage_key, storage_item)

        ctx = engine.invoke_syscall_by_name("System.Storage.GetContext")
        engine.push(vm.ByteStringStackItem(storage_key.key))
        engine.push(vm.StackItem.from_interface(ctx))

        engine.invoke_syscall_by_name("System.Storage.Delete")

        self.assertIsNone(engine.snapshot.storages.try_get(storage_key))
