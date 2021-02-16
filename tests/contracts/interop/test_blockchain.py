import unittest
from neo3 import vm
from .utils import test_engine, test_block


class BlockchainInteropTestCase(unittest.TestCase):
    def test_get_height(self):
        engine = test_engine(has_container=True, has_snapshot=True)
        engine.invoke_syscall_by_name("System.Blockchain.GetHeight")
        item = engine.current_context.evaluation_stack.pop()
        # unlike the C# test case, our chain starts at -1 because our chain is created without the genesis block
        # this was done such that you can sync without having to know the validators to create the genesis block
        # this is useful for purposes where we're less concerned with security (e.g. a statistics app)
        self.assertEqual(vm.BigInteger(-1), item.to_biginteger())

    def test_get_block(self):
        engine = test_engine(has_container=True, has_snapshot=True)
        # test with height
        engine.push(vm.ByteStringStackItem(b'\x01'))
        engine.invoke_syscall_by_name("System.Blockchain.GetBlock")
        self.assertIsInstance(engine.pop(), vm.NullStackItem)

        # test with invalid height (-1)
        engine.push(vm.ByteStringStackItem(b'\xFF'))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Blockchain.GetBlock")
        self.assertEqual("Invalid height", str(context.exception))

        # test with invalid data > 32 bytes
        engine.push(vm.ByteStringStackItem(b'\xFF' * 33))
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Blockchain.GetBlock")
        self.assertEqual("Invalid data", str(context.exception))

        # test with serialized block hash (UInt256). This fake hash won't return a block
        engine.push(vm.ByteStringStackItem(b'\x01' * 32))
        engine.invoke_syscall_by_name("System.Blockchain.GetBlock")
        self.assertIsInstance(engine.pop(), vm.NullStackItem)

        # now find an existing block
        # first add a block and update the snapshot
        # normally this would be done while persisting in Blockchain
        testblock = test_block()
        engine.snapshot.best_block_height = testblock.index
        engine.snapshot.blocks.put(testblock)
        engine.push(vm.ByteStringStackItem(testblock.hash().to_array()))
        engine.invoke_syscall_by_name("System.Blockchain.GetBlock")
        # # validate the right content was pushed onto the stack
        item = engine.pop()
        self.assertIsInstance(item, vm.ArrayStackItem)
        self.assertEqual(len(item), 8)
        self.assertEqual(item[0].to_array(), testblock.hash().to_array())
        self.assertEqual(item[1].to_biginteger(), vm.BigInteger(testblock.version))
        self.assertEqual(item[2].to_array(), testblock.prev_hash.to_array())
        self.assertEqual(item[3].to_array(), testblock.merkle_root.to_array())
        self.assertEqual(item[4].to_biginteger(), vm.BigInteger(testblock.timestamp))
        self.assertEqual(item[5].to_biginteger(), vm.BigInteger(testblock.index))
        self.assertEqual(item[6].to_array(), testblock.next_consensus.to_array())
        self.assertEqual(item[7].to_biginteger(), vm.BigInteger(len(testblock.transactions)))

    def test_get_transaction_from_block(self):
        # this test for the first part is identical to the GetBlock test above
        engine = test_engine(has_container=True, has_snapshot=True)

        # test with serialized block hash (UInt256). This fake hash won't return a block
        engine.push(vm.IntegerStackItem(0))  # index
        engine.push(vm.ByteStringStackItem(b'\x01' * 32))
        engine.invoke_syscall_by_name("System.Blockchain.GetTransactionFromBlock")
        self.assertIsInstance(engine.pop(), vm.NullStackItem)

        # now find an existing block, but with an invalid transaction index (
        # first add a block and update the snapshot
        # normally this would be done while persisting in Blockchain
        testblock = test_block()
        engine.snapshot.best_block_height = testblock.index
        engine.snapshot.blocks.put(testblock)
        engine.push(vm.IntegerStackItem(-1))  # index
        engine.push(vm.ByteStringStackItem(testblock.hash().to_array()))  # hash
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Blockchain.GetTransactionFromBlock")
        self.assertEqual("Transaction index out of range: -1", str(context.exception))

        # now let's try again but this time with an invalid index (out of bounds)
        engine.push(vm.IntegerStackItem(len(testblock.transactions) + 1))  # index
        engine.push(vm.ByteStringStackItem(testblock.hash().to_array()))  # hash
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("System.Blockchain.GetTransactionFromBlock")
        self.assertEqual("Transaction index out of range: 2", str(context.exception))

        # Finally, we try with a valid index (we have only 1 transaction, so 0)
        engine.push(vm.IntegerStackItem(vm.BigInteger(0)))  # index
        engine.push(vm.ByteStringStackItem(testblock.hash().to_array()))  # hash
        engine.invoke_syscall_by_name("System.Blockchain.GetTransactionFromBlock")

        # and test the TX items pushed to the stack
        item = engine.pop()
        testblock_tx = testblock.transactions[0]
        self.assertIsInstance(item, vm.ArrayStackItem)
        self.assertEqual(len(item), 8)
        self.assertEqual(item[0].to_array(), testblock_tx.hash().to_array())
        self.assertEqual(item[1].to_biginteger(), vm.BigInteger(testblock_tx.version))
        self.assertEqual(item[2].to_biginteger(), vm.BigInteger(testblock_tx.nonce))
        self.assertEqual(item[3].to_array(), testblock_tx.sender.to_array())
        self.assertEqual(item[4].to_biginteger(), vm.BigInteger(testblock_tx.system_fee))
        self.assertEqual(item[5].to_biginteger(), vm.BigInteger(testblock_tx.network_fee))
        self.assertEqual(item[6].to_biginteger(), vm.BigInteger(testblock_tx.valid_until_block))
        self.assertEqual(item[7].to_array(), testblock_tx.script)

    def test_get_transaction(self):
        engine = test_engine(has_container=True, has_snapshot=True)
        bad_tx_hash_bytes = b'\x01' * 32
        engine.push(vm.ByteStringStackItem(bad_tx_hash_bytes))
        engine.invoke_syscall_by_name("System.Blockchain.GetTransaction")
        self.assertIsInstance(engine.pop(), vm.NullStackItem)

        # now get a valid tx
        testblock = test_block()
        engine.snapshot.best_block_height = testblock.index
        testblock_tx = testblock.transactions[0]
        engine.snapshot.transactions.put(testblock_tx)
        engine.push(vm.ByteStringStackItem(testblock_tx.hash().to_array()))
        engine.invoke_syscall_by_name("System.Blockchain.GetTransaction")

        # and test the TX item pushed to the stack. We're not going to check all items in the array as we've already
        # done that in test_get_transaction_from_block() so we already know that the "to_stack_item()" conversion works
        item = engine.pop()
        self.assertIsInstance(item, vm.ArrayStackItem)
        self.assertEqual(len(item), 8)
        self.assertEqual(item[0].to_array(), testblock_tx.hash().to_array())

    def test_get_transaction_height(self):
        engine = test_engine(has_container=True, has_snapshot=True)
        bad_tx_hash_bytes = b'\x01' * 32
        engine.push(vm.ByteStringStackItem(bad_tx_hash_bytes))
        engine.invoke_syscall_by_name("System.Blockchain.GetTransactionHeight")
        item = engine.pop()
        self.assertIsInstance(item, vm.IntegerStackItem)
        self.assertEqual(vm.BigInteger(-1), item.to_biginteger())

        # now get a valid tx
        testblock = test_block()
        engine.snapshot.best_block_height = testblock.index
        testblock_tx = testblock.transactions[0]
        engine.snapshot.transactions.put(testblock_tx)
        engine.push(vm.ByteStringStackItem(testblock_tx.hash().to_array()))
        engine.invoke_syscall_by_name("System.Blockchain.GetTransactionHeight")
        item = engine.pop()
        self.assertIsInstance(item, vm.IntegerStackItem)
        self.assertEqual(str(vm.BigInteger(1)), str(item.to_biginteger()))
