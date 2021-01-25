import unittest
from neo3 import vm, contracts, storage
from neo3.core import types
from neo3.contracts import interop
from .utils import syscall_name_to_int
from .utils import test_engine


class StorageInteropTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def setUp(self) -> None:
        self.RET = b'\x40'
        self.manifest = contracts.ContractManifest()
        self.contract = storage.ContractState(script=self.RET, _manifest=self.manifest)

    def test_get_context(self):
        engine = test_engine(has_snapshot=True)
        engine.snapshot.contracts.put(self.contract)
        ctx = engine.invoke_syscall_by_name("System.Storage.GetContext")
        self.assertIsInstance(ctx, storage.StorageContext)
        self.assertEqual(self.contract.script_hash(), ctx.script_hash)
        self.assertFalse(ctx.is_read_only)

        # repeat for read only
        ctx = engine.invoke_syscall_by_name("System.Storage.GetReadOnlyContext")
        self.assertIsInstance(ctx, storage.StorageContext)
        self.assertEqual(self.contract.script_hash(), ctx.script_hash)
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
        engine = test_engine(has_snapshot=True)
        script = vm.ScriptBuilder()
        # key parameter for the `Get` syscall
        script.emit(vm.OpCode.PUSH2)
        script.emit_syscall(syscall_name_to_int("System.Storage.GetContext"))
        # at this point our stack looks like follows
        # * storage context
        # * key
        script.emit_syscall(syscall_name_to_int("System.Storage.Get"))
        engine.load_script(vm.Script(script.to_array()))

        # we set the script parameter of the ContractState to our script
        # which ensures that `engine.current_scripthash` matches the script we manually build above
        # this basically means the engine thinks it is running a smart contract that we can find in our storage
        # which in turns enables us to call the `System.Storage.GetContext` syscall
        contract = storage.ContractState(script=script.to_array(), _manifest=self.manifest)
        engine.snapshot.contracts.put(contract)

        storage_key = storage.StorageKey(contract.script_hash(), b'\x01')
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

        storage_key = storage.StorageKey(self.contract.script_hash(), b'\x01')
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

        contract = storage.ContractState(script=script.to_array(), _manifest=self.manifest)
        engine.snapshot.contracts.put(contract)

        storage_key = storage.StorageKey(contract.script_hash(), b'\x01')
        storage_item = storage.StorageItem(b'\x11')
        engine.snapshot.storages.put(storage_key, storage_item)

        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertEqual(storage_item.value, item.to_array())

    def test_storage_find(self):
        engine = test_engine(has_snapshot=True)
        engine.snapshot.contracts.put(self.contract)

        storage_key1 = storage.StorageKey(self.contract.script_hash(), b'\x01')
        storage_item1 = storage.StorageItem(b'\x11', is_constant=False)
        engine.snapshot.storages.put(storage_key1, storage_item1)
        storage_key2 = storage.StorageKey(self.contract.script_hash(), b'\x02')
        storage_item2 = storage.StorageItem(b'\x22', is_constant=False)
        engine.snapshot.storages.put(storage_key2, storage_item2)

        ctx = engine.invoke_syscall_by_name("System.Storage.GetContext")
        engine.push(vm.ByteStringStackItem(storage_key1.key))
        engine.push(vm.StackItem.from_interface(ctx))

        it = engine.invoke_syscall_by_name("System.Storage.Find")
        self.assertIsInstance(it, interop.StorageIterator)
        it.next()
        self.assertEqual(storage_key1.key, it.key().to_array())
        self.assertEqual(storage_item1.value, it.value().to_array())

        it.next()
        with self.assertRaises(ValueError) as context:
            it.key()
        self.assertEqual("Cannot call 'key' without having advanced the iterator at least once", str(context.exception))
        with self.assertRaises(ValueError) as context:
            it.value()
        self.assertEqual("Cannot call 'value' without having advanced the iterator at least once", str(context.exception))

    def test_storage_put_helper_parameter_validation(self):
        with self.assertRaises(ValueError) as context:
            key = (b'\x01' * contracts.interop.MAX_STORAGE_KEY_SIZE) + b'\x01'
            contracts.interop._storage_put_internal(None, None, key, b'', None)
        self.assertEqual(f"Storage key length exceeds maximum of {contracts.interop.MAX_STORAGE_KEY_SIZE}", str(context.exception))

        with self.assertRaises(ValueError) as context:
            value = (b'\x01' * contracts.interop.MAX_STORAGE_VALUE_SIZE) + b'\x01'
            contracts.interop._storage_put_internal(None, None, b'', value, None)
        self.assertEqual(f"Storage value length exceeds maximum of {contracts.interop.MAX_STORAGE_VALUE_SIZE}", str(context.exception))

        with self.assertRaises(ValueError) as context:
            ctx = storage.StorageContext(None, is_read_only=True)
            contracts.interop._storage_put_internal(None, ctx, b'', b'', None)
        self.assertEqual("Cannot persist to read-only storage context", str(context.exception))

        # finaly make sure it fails if we try to modify an item that is marked constant
        engine = test_engine(has_snapshot=True)
        key = storage.StorageKey(types.UInt160.zero(), b'\x01')
        item = storage.StorageItem(b'', is_constant=True)
        engine.snapshot.storages.put(key, item)

        with self.assertRaises(ValueError) as context:
            ctx = storage.StorageContext(types.UInt160.zero(), is_read_only=False)
            contracts.interop._storage_put_internal(engine, ctx, b'\x01', b'', storage.StorageFlags.NONE)
        self.assertEqual("StorageItem is marked as constant", str(context.exception))

    def test_storage_put_new(self):
        # see `test_storage_get_key_not_found()` for a description on why the storage is setup with a script as is

        for i in range(2):
            # setup
            engine = test_engine(has_snapshot=True)
            script = vm.ScriptBuilder()
            if i == 0:
                script.emit(vm.OpCode.PUSH2)  # storage put value
                script.emit(vm.OpCode.PUSH1)  # storage put key
                script.emit_syscall(syscall_name_to_int("System.Storage.GetContext"))
                script.emit_syscall(syscall_name_to_int("System.Storage.Put"))
            else:
                script.emit(vm.OpCode.PUSH0)  # storage put call flags
                script.emit(vm.OpCode.PUSH2)  # storage put value
                script.emit(vm.OpCode.PUSH1)  # storage put key
                script.emit_syscall(syscall_name_to_int("System.Storage.GetContext"))
                script.emit_syscall(syscall_name_to_int("System.Storage.PutEx"))
            engine.load_script(vm.Script(script.to_array()))

            contract = storage.ContractState(script=script.to_array(), _manifest=self.manifest)
            engine.snapshot.contracts.put(contract)

            engine.execute()

            self.assertEqual(vm.VMState.HALT, engine.state)
            storage_key = storage.StorageKey(contract.script_hash(), b'\x01')
            item = engine.snapshot.storages.try_get(storage_key)
            self.assertIsNotNone(item)
            self.assertEqual(b'\x02', item.value)

    def test_storage_put_overwrite(self):
        # test with new data being shorter than the old data
        engine = test_engine(has_snapshot=True)
        key = b'\x01'
        storage_key = storage.StorageKey(types.UInt160.zero(), key)
        storage_item = storage.StorageItem(b'\x11\x22\x33', is_constant=False)
        engine.snapshot.storages.put(storage_key, storage_item)

        ctx = storage.StorageContext(types.UInt160.zero(), is_read_only=False)
        new_item_value = b'\x11\x22'
        contracts.interop._storage_put_internal(engine, ctx, key, new_item_value, storage.StorageFlags.NONE)

        item = engine.snapshot.storages.get(storage_key)
        self.assertIsNotNone(item)
        self.assertEqual(new_item_value, item.value)

        # now test with data being longer than before
        longer_item_value = b'\x11\x22\x33\x44'
        contracts.interop._storage_put_internal(engine, ctx, key, longer_item_value, storage.StorageFlags.NONE)

        item = engine.snapshot.storages.get(storage_key)
        self.assertIsNotNone(item)
        self.assertEqual(longer_item_value, item.value)

    def test_storage_delete_readonly_context(self):
        engine = test_engine(has_snapshot=True)

        engine.snapshot.contracts.put(self.contract)

        storage_key = storage.StorageKey(self.contract.script_hash(), b'\x01')
        storage_item = storage.StorageItem(b'\x11')
        engine.snapshot.storages.put(storage_key, storage_item)

        ctx = engine.invoke_syscall_by_name("System.Storage.GetReadOnlyContext")
        engine.push(vm.ByteStringStackItem(storage_key.key))
        engine.push(vm.StackItem.from_interface(ctx))

        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Storage.Delete")
        self.assertEqual("Cannot delete from read-only storage context", str(context.exception))

    def test_storage_delete_constant_item(self):
        engine = test_engine(has_snapshot=True)
        engine.snapshot.contracts.put(self.contract)

        storage_key = storage.StorageKey(self.contract.script_hash(), b'\x01')
        storage_item = storage.StorageItem(b'\x11', is_constant=True)
        engine.snapshot.storages.put(storage_key, storage_item)

        ctx = engine.invoke_syscall_by_name("System.Storage.GetContext")
        engine.push(vm.ByteStringStackItem(storage_key.key))
        engine.push(vm.StackItem.from_interface(ctx))

        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Storage.Delete")
        self.assertEqual("Cannot delete a storage item that is marked constant", str(context.exception))

    def test_delete_ok(self):
        engine = test_engine(has_snapshot=True)
        engine.snapshot.contracts.put(self.contract)

        storage_key = storage.StorageKey(self.contract.script_hash(), b'\x01')
        storage_item = storage.StorageItem(b'\x11', is_constant=False)
        engine.snapshot.storages.put(storage_key, storage_item)

        ctx = engine.invoke_syscall_by_name("System.Storage.GetContext")
        engine.push(vm.ByteStringStackItem(storage_key.key))
        engine.push(vm.StackItem.from_interface(ctx))

        engine.invoke_syscall_by_name("System.Storage.Delete")

        self.assertIsNone(engine.snapshot.storages.try_get(storage_key))
