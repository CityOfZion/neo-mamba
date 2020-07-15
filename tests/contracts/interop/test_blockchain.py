import unittest
from neo3 import vm, contracts
from neo3.contracts import interop
from .utils import test_engine, test_block


class BlockchainInteropTestCase(unittest.TestCase):
    def test_getheight(self):
        engine = test_engine(has_container=True, has_snapshot=True)
        self.assertTrue(interop.InteropService.invoke_with_name(engine, "System.Blockchain.GetHeight"))
        item = engine.current_context.evaluation_stack.pop()
        # unlike the C# test case, our chain starts at -1 because our chain is created without the genesis block
        # this was done such that you can sync without having to know the validators to create the genesis block
        # this is useful for purposes where we're less concerned with security (e.g. a statistics app)
        self.assertEqual(vm.BigInteger(-1), item.to_biginteger())

    def test_get_block(self):
        engine = test_engine(has_container=True, has_snapshot=True)
        # test with height
        engine.push(vm.ByteStringStackItem(b'\x01'))
        self.assertTrue(interop.InteropService.invoke_with_name(engine, "System.Blockchain.GetBlock"))
        self.assertIsInstance(engine.try_pop_item(), vm.NullStackItem)

        # test with serialized block hash (UInt256). This fake hash won't return a block
        engine.push(vm.ByteStringStackItem(b'\x01' * 32))
        self.assertTrue(interop.InteropService.invoke_with_name(engine, "System.Blockchain.GetBlock"))
        self.assertIsInstance(engine.try_pop_item(), vm.NullStackItem)

        # try with serialized block data that is too short
        engine.push(vm.ByteStringStackItem(b'\x01' * 8))
        self.assertFalse(interop.InteropService.invoke_with_name(engine, "System.Blockchain.GetBlock"))

        # now find an existing block
        # first add a block and update the snapshot
        # normally this would be done while persisting in Blockchain
        testblock = test_block()
        engine.snapshot.block_height = testblock.index
        engine.snapshot.blocks.put(testblock)
        engine.push(vm.ByteStringStackItem(testblock.hash().to_array()))
        self.assertTrue(interop.InteropService.invoke_with_name(engine, "System.Blockchain.GetBlock"))

        # validate the right content was pushed onto the stack
        item = engine.try_pop_item()
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

        # test with height
        engine.push(vm.ByteStringStackItem(b'\x01'))
        self.assertTrue(interop.InteropService.invoke_with_name(engine, "System.Blockchain.GetTransactionFromBlock"))
        self.assertIsInstance(engine.try_pop_item(), vm.NullStackItem)

        # test with serialized block hash (UInt256). This fake hash won't return a block
        engine.push(vm.ByteStringStackItem(b'\x01' * 32))
        self.assertTrue(interop.InteropService.invoke_with_name(engine, "System.Blockchain.GetTransactionFromBlock"))
        self.assertIsInstance(engine.try_pop_item(), vm.NullStackItem)

        # try with serialized block data that is too short
        engine.push(vm.ByteStringStackItem(b'\x01' * 8))
        self.assertFalse(interop.InteropService.invoke_with_name(engine, "System.Blockchain.GetTransactionFromBlock"))

        # now find an existing block
        # first add a block and update the snapshot
        # normally this would be done while persisting in Blockchain
        testblock = test_block()
        engine.snapshot.block_height = testblock.index
        engine.snapshot.blocks.put(testblock)
        engine.push(vm.ByteStringStackItem(testblock.hash().to_array()))
        # we fail because we've not put enough data on the stack to indicate the transaction index
        self.assertFalse(interop.InteropService.invoke_with_name(engine, "System.Blockchain.GetTransactionFromBlock"))

        # now let's try again but this time with an invalid index (negative)
        engine.push(vm.IntegerStackItem(vm.BigInteger(-1)))  # index
        engine.push(vm.ByteStringStackItem(testblock.hash().to_array()))  # hash
        self.assertFalse(interop.InteropService.invoke_with_name(engine, "System.Blockchain.GetTransactionFromBlock"))

        # now let's try again but this time with an invalid index (out of bounds)
        engine.push(vm.IntegerStackItem(vm.BigInteger(len(testblock.transactions) + 1)))  # index
        engine.push(vm.ByteStringStackItem(testblock.hash().to_array()))  # hash
        self.assertFalse(interop.InteropService.invoke_with_name(engine, "System.Blockchain.GetTransactionFromBlock"))

        # Finally, we try with a valid index (we have only 1 transaction, so 0)
        engine.push(vm.IntegerStackItem(vm.BigInteger(0)))  # index
        engine.push(vm.ByteStringStackItem(testblock.hash().to_array()))  # hash
        self.assertTrue(interop.InteropService.invoke_with_name(engine, "System.Blockchain.GetTransactionFromBlock"))

        # and test the TX items pushed to the stack
        item = engine.try_pop_item()
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


    def test_get_transaction_height(self):
        pass

    def test_get_contract(self):
        pass