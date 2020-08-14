import abc
import unittest
from neo3.core import types
from neo3.network import payloads
from neo3 import storage
from neo3.contracts import manifest
from contextlib import suppress
from copy import deepcopy


class AbstractBlockStorageTest(abc.ABC, unittest.TestCase):
    """
    A helper class to easily test backend specific code
    """

    @abc.abstractmethod
    def db_factory(self):
        """ Implement to return an instance of your DB """

    def test_rawview_bestblockheight(self):

        raw_view = self.db.get_rawview()
        self.assertEqual(-1, raw_view.block_height)

        raw_view.blocks.put(self.block1)
        self.assertEqual(1, raw_view.block_height)

        with self.assertRaises(AttributeError):
            raw_view.block_height = 2
        self.assertEqual(1, raw_view.block_height)

    def setUp(self) -> None:
        self.db = self.db_factory()
        signer = payloads.Signer(account=types.UInt160.from_string("d7678dd97c000be3f33e9362e673101bac4ca654"),
                                 scope=payloads.WitnessScope.FEE_ONLY)
        tx = payloads.Transaction(version=0,
                                  nonce=123,
                                  system_fee=456,
                                  network_fee=789,
                                  valid_until_block=1,
                                  attributes=[],
                                  signers=[signer],
                                  script=b'\x01',
                                  witnesses=[])

        self.block1 = payloads.Block(version=0,
                                   prev_hash=types.UInt256.from_string("f782c7fbb2eef6afe629b96c0d53fb525eda64ce5345057caf975ac3c2b9ae0a"),
                                   timestamp=123,
                                   index=1,
                                   next_consensus=types.UInt160.from_string("d7678dd97c000be3f33e9362e673101bac4ca654"),
                                   witness=payloads.Witness(invocation_script=b'', verification_script=b'\x55'),
                                   consensus_data=payloads.ConsensusData(primary_index=1, nonce=123),
                                   transactions=[tx])
        self.block1.rebuild_merkle_root()
        self.block1_hash = self.block1.hash()

        self.block2 = deepcopy(self.block1)
        self.block2.index = 2
        self.block2_hash = self.block2.hash()

    def test_raw(self):
        raw_view = self.db.get_rawview()

        # we should not find anything in an empty db
        target_block_hash = types.UInt256.zero()
        with self.assertRaises(KeyError):
            raw_view.blocks.get(target_block_hash)
        self.assertIsNone(raw_view.blocks.try_get(target_block_hash))

        with self.assertRaises(KeyError):
            raw_view.blocks.get_by_height(1)
        self.assertIsNone(raw_view.blocks.try_get_by_height(1))

        # fill the db
        raw_view.blocks.put(self.block1)
        # and test it is immediately added
        block_from_db = raw_view.blocks.try_get(self.block1_hash)
        self.assertIsNotNone(block_from_db)
        self.assertEqual(self.block1, block_from_db)

        # test again but get via height
        block_from_db = raw_view.blocks.try_get_by_height(self.block1.index)
        self.assertIsNotNone(block_from_db)
        self.assertEqual(self.block1, block_from_db)

        # test getting all blocks
        raw_view.blocks.put(self.block2)
        blocks = list(raw_view.blocks.all())
        self.assertEqual(2, len(blocks))
        self.assertIn(self.block1, blocks)
        self.assertIn(self.block2, blocks)

        # finally try removing a block
        raw_view.blocks.delete(self.block1_hash)
        self.assertIsNone(raw_view.blocks.try_get(self.block1_hash))

    def test_snapshot_basic_add_delete_get(self):
        # test basic add, delete, get and separation
        raw_view = self.db.get_rawview()
        snapshot_view = self.db.get_snapshotview()

        # we should not find anything in an empty db
        target_block_hash = types.UInt256.zero()
        with self.assertRaises(KeyError):
            snapshot_view.blocks.get(target_block_hash)
        self.assertIsNone(snapshot_view.blocks.try_get(target_block_hash))

        # same as previous but by height
        with self.assertRaises(KeyError):
            snapshot_view.blocks.get_by_height(1)
        self.assertIsNone(snapshot_view.blocks.try_get_by_height(1))

        # add item
        snapshot_view.blocks.put(self.block1)
        # real backend should not be affected until a commit is called
        self.assertIsNone(raw_view.blocks.try_get(self.block1_hash))
        self.assertIsNone(raw_view.blocks.try_get_by_height(self.block1.index))

        # persist to backend
        snapshot_view.commit()
        block_from_db = raw_view.blocks.try_get(self.block1_hash)
        # and validate
        self.assertIsNotNone(block_from_db)
        self.assertEqual(self.block1, block_from_db)

        # same but by height to validate the height -> hash -> block mapping
        block_from_db = raw_view.blocks.try_get_by_height(self.block1.index)
        self.assertIsNotNone(block_from_db)
        self.assertEqual(self.block1, block_from_db)

        # finally, try deleting
        # get a clean view with no cache
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.blocks.delete(self.block1_hash)

        # real backend should still have it, snapshot not
        self.assertIsNotNone(raw_view.blocks.try_get(self.block1_hash))
        self.assertIsNone(snapshot_view.blocks.try_get(self.block1_hash))

        # persist and validate real backend also doesn't have it anymore
        snapshot_view.commit()
        self.assertIsNone(raw_view.blocks.try_get(self.block1_hash))

    def test_snapshot_add_duplicates(self):
        snapshot_view = self.db.get_snapshotview()

        # test double adding while already in cache
        snapshot_view.blocks.put(self.block1)
        with self.assertRaises(ValueError):
            snapshot_view.blocks.put(self.block1)

        # test double adding when not in cache, but in real backend
        snapshot_view.commit()
        # get a clean one with an empty cache
        snapshot_view = self.db.get_snapshotview()
        with self.assertRaises(ValueError):
            snapshot_view.blocks.put(self.block1)

    def test_snapshot_add_while_cache_marked_deleted(self):
        # an item can exist in the real backend, and be marked in cache to be deleted
        # it should then be possible to delete it from cache without exceptions

        # fill real backend
        raw_view = self.db.get_rawview()
        raw_view.blocks.put(self.block1)

        # ensure item is marked as deleted in cache
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.blocks.delete(self.block1_hash)

        # now test by adding add the item again
        success = False
        with suppress(ValueError):
            snapshot_view.blocks.put(self.block1)
            success = True
        self.assertTrue(success)

    def test_snapshot_get_various(self):
        snapshot_view = self.db.get_snapshotview()

        # get non existing item
        with self.assertRaises(KeyError):
            snapshot_view.blocks.get(self.block1_hash)

        with self.assertRaises(KeyError):
            snapshot_view.blocks.get_by_height(self.block1.index)

        # test read only
        raw_view = self.db.get_rawview()
        raw_view.blocks.put(self.block1)
        block = snapshot_view.blocks.get(self.block1_hash, read_only=True)
        block.index = 123

        block_again = snapshot_view.blocks.get(self.block1_hash, read_only=True)
        # We validate the hash of the original with the hash of the block we retrieved.
        # The modification of the index attribute above changes the hash, if it persisted
        # the following test fails
        self.assertEqual(self.block1_hash, block_again.hash())

        # same as above but test read_only for get_by_height()
        block = snapshot_view.blocks.get_by_height(self.block1.index, read_only=True)
        block.index = 123
        block_again = snapshot_view.blocks.get(self.block1_hash, read_only=True)
        self.assertEqual(self.block1_hash, block_again.hash())

    def test_snapshot_clone_put(self):
        raw_view = self.db.get_rawview()
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.blocks.put(self.block1)

        clone_view = snapshot_view.clone()
        # validate it has the same block
        self.assertEqual(self.block1, clone_view.blocks.try_get(self.block1_hash))

        # put some in the clone
        clone_view.blocks.put(self.block2)

        # validate it is not visible anywhere but in the clone
        self.assertIsNone(raw_view.blocks.try_get(self.block2_hash))
        self.assertIsNone(snapshot_view.blocks.try_get(self.block2_hash))
        self.assertEqual(self.block2, clone_view.blocks.try_get(self.block2_hash))

        # commit changes of the clone back into the snapshot
        # should affect only the snapshot, not the real backend
        clone_view.commit()
        self.assertIsNone(raw_view.blocks.try_get(self.block2_hash))
        self.assertEqual(self.block2, snapshot_view.blocks.try_get(self.block2_hash))

        # finally commit to real db
        snapshot_view.commit()
        self.assertEqual(self.block2, raw_view.blocks.try_get(self.block2_hash))

    def test_snapshot_clone_delete(self):
        raw_view = self.db.get_rawview()
        raw_view.blocks.put(self.block1)
        snapshot_view = self.db.get_snapshotview()

        # perform a get to fill the cache
        snapshot_view.blocks.get(self.block1_hash)

        clone_view = snapshot_view.clone()
        # now test deleting an item
        clone_view.blocks.delete(self.block1_hash)
        # test it's gone in the clone, but nowhere else
        self.assertIsNone(clone_view.blocks.try_get(self.block1_hash))
        self.assertIsNone(clone_view.blocks.try_get_by_height(self.block1.index))
        self.assertIsNotNone(snapshot_view.blocks.try_get(self.block1_hash))
        self.assertIsNotNone(snapshot_view.blocks.try_get_by_height(self.block1.index))
        self.assertIsNotNone(raw_view.blocks.try_get(self.block1_hash))
        self.assertIsNotNone(raw_view.blocks.try_get_by_height(self.block1.index))

        # commit the clone into the snapshot
        clone_view.commit()
        # and validate it is also gone in the snapshot but not the real db
        self.assertIsNone(snapshot_view.blocks.try_get(self.block1_hash))
        self.assertIsNotNone(raw_view.blocks.try_get(self.block1_hash))

        # finally persist to real db
        snapshot_view.commit()
        self.assertIsNone(raw_view.blocks.try_get(self.block1_hash))

    def test_snapshot_clone_update(self):
        # we currently have no way of testing for changes, as any attribute changes on the Block object
        # will change the hash and
        pass

    def test_all(self):
        raw_view = self.db.get_rawview()
        raw_view.blocks.put(self.block1)
        raw_view.blocks.put(self.block2)

        snapshot_view = self.db.get_snapshotview()

        # get() a block to fill the cache so we can test sorting and readonly behaviour
        # block2's hash comes before block1 when sorting. So we cache that first as the all() function internals
        # collect the results from the backend (=block1) before results from the cache (=block2).
        # Therefore if block2 is found in the first position of the all() results, we can
        # conclude that the sort() happened correctly.
        snapshot_view.blocks.get(self.block2_hash)
        blocks = list(snapshot_view.blocks.all())
        self.assertEqual(2, len(blocks))
        self.assertEqual(self.block2, blocks[0])
        self.assertEqual(self.block1, blocks[1])

        # ensure all() results are readonly
        blocks[0].transactions.append(payloads.Transaction._serializable_init())
        blocks[1].transactions.append(payloads.Transaction._serializable_init())

        block1_from_snap = snapshot_view.blocks.get(self.block1_hash, read_only=True)
        block2_from_snap = snapshot_view.blocks.get(self.block2_hash, read_only=True)
        self.assertNotEqual(3, len(block1_from_snap.transactions))
        self.assertNotEqual(3, len(block2_from_snap.transactions))

        # test clone all()
        block3 = deepcopy(self.block1)
        block3.index = 3

        clone_view = snapshot_view.clone()
        clone_view.blocks.put(block3)
        blocks = list(clone_view.blocks.all())
        self.assertEqual(3, len(blocks))
        self.assertEqual(2, len(list(snapshot_view.blocks.all())))
        self.assertEqual(self.block2, blocks[0])
        self.assertEqual(block3, blocks[1])
        self.assertEqual(self.block1, blocks[2])

    def test_snapshot_bestblockheight(self):
        snapshot_view = self.db.get_snapshotview()
        self.assertEqual(-1, snapshot_view.block_height)

        snapshot_view.block_height = 2
        self.assertEqual(2, snapshot_view.block_height)

        # nothing yet in raw view
        raw_view = self.db.get_rawview()
        self.assertEqual(-1, raw_view.block_height)

        clone_view = snapshot_view.clone()
        self.assertEqual(2, clone_view.block_height)

        clone_view.block_height = 3
        self.assertEqual(3, clone_view.block_height)
        self.assertEqual(2, snapshot_view.block_height)
        self.assertEqual(-1, raw_view.block_height)

        clone_view.commit()
        self.assertEqual(3, snapshot_view.block_height)
        self.assertEqual(-1, raw_view.block_height)

        snapshot_view.commit()
        self.assertEqual(3, raw_view.block_height)

    def test_snapshot_bestblockheight_2(self):
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.blocks.put(self.block1)
        snapshot_view.commit()

        raw_view = self.db.get_rawview()
        self.assertEqual(self.block1.index, raw_view.block_height)


class AbstractContractStorageTest(abc.ABC, unittest.TestCase):
    """
    A helper class to easily test backend specific code
    """

    @abc.abstractmethod
    def db_factory(self):
        """ Implement to return an instance of your DB """

    def setUp(self) -> None:
        self.db = self.db_factory()
        self.contract1 = storage.ContractState(b'\x01\x02', manifest.ContractManifest())
        self.contract1_hash = self.contract1.script_hash()
        self.contract2 = storage.ContractState(b'\x03\x04', manifest.ContractManifest())
        self.contract2_hash = self.contract2.script_hash()
        self.contract3 = storage.ContractState(b'\x05\x06', manifest.ContractManifest())
        self.contract3_hash = self.contract2.script_hash()

    def test_raw(self):
        raw_view = self.db.get_rawview()

        # we should not find anything in an empty db
        target_contract_hash = types.UInt160.zero()
        with self.assertRaises(KeyError):
            raw_view.contracts.get(target_contract_hash)
        self.assertIsNone(raw_view.contracts.try_get(target_contract_hash))

        # fill the db
        raw_view.contracts.put(self.contract1)
        # and test it is immediately added
        contract_from_db = raw_view.contracts.try_get(self.contract1_hash)
        self.assertIsNotNone(contract_from_db)
        self.assertEqual(self.contract1, contract_from_db)

        # test getting all contracts
        raw_view.contracts.put(self.contract2)
        contracts = list(raw_view.contracts.all())
        self.assertEqual(2, len(contracts))
        self.assertIn(self.contract1, contracts)
        self.assertIn(self.contract2, contracts)

        # finally try removing the contract
        raw_view.contracts.delete(self.contract1_hash)
        self.assertIsNone(raw_view.contracts.try_get(self.contract1_hash))

    def test_snapshot_basic_add_delete_get(self):
        # test basic add, delete, get and separation
        raw_view = self.db.get_rawview()
        snapshot_view = self.db.get_snapshotview()

        # we should not find anything in an empty db
        target_contract_hash = types.UInt160.zero()
        with self.assertRaises(KeyError) as context:
            snapshot_view.contracts.get(target_contract_hash)
        self.assertIsNone(snapshot_view.contracts.try_get(target_contract_hash))

        # add item
        snapshot_view.contracts.put(self.contract1)
        # real backend should not be affected until a commit is called
        self.assertIsNone(raw_view.contracts.try_get(self.contract1_hash))

        # persist to backend
        snapshot_view.commit()
        contract_from_db = raw_view.contracts.try_get(self.contract1_hash)
        # and validate
        self.assertIsNotNone(contract_from_db)
        self.assertEqual(self.contract1, contract_from_db)

        # finally, try deleting
        # get a clean view with no cache
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.contracts.delete(self.contract1_hash)

        # real backend should still have it, snapshot not
        self.assertIsNotNone(raw_view.contracts.try_get(self.contract1_hash))
        self.assertIsNone(snapshot_view.contracts.try_get(self.contract1_hash))

        # persist and validate real backend also doesn't have it anymore
        snapshot_view.commit()
        self.assertIsNone(raw_view.contracts.try_get(self.contract1_hash))

    def test_snapshot_add_duplicates(self):
        snapshot_view = self.db.get_snapshotview()

        # test double adding while already in cache
        snapshot_view.contracts.put(self.contract1)
        with self.assertRaises(ValueError):
            snapshot_view.contracts.put(self.contract1)

        # test double adding when not in cache, but in real backend
        snapshot_view.commit()
        # get a clean one with an empty cache
        snapshot_view = self.db.get_snapshotview()
        with self.assertRaises(ValueError):
            snapshot_view.contracts.put(self.contract1)

    def test_snapshot_add_while_cache_marked_deleted(self):
        # an item can exist in the real backend, and be marked in cache to be deleted
        # it should then be possible to delete it from cache without exceptions

        # fill real backend
        raw_view = self.db.get_rawview()
        raw_view.contracts.put(self.contract1)

        # ensure item is marked as deleted in cache
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.contracts.delete(self.contract1_hash)

        # now test by adding add the item again
        success = False
        with suppress(ValueError):
            snapshot_view.contracts.put(self.contract1)
            success = True
        self.assertTrue(success)

    def test_snapshot_delete_various(self):
        snapshot_view = self.db.get_snapshotview()

        # delete non existing item with empty cache should throw no errors
        ok = False
        with suppress(Exception):
            snapshot_view.contracts.delete(self.contract1_hash)
            ok = True
        self.assertTrue(ok)

        # delete an item that was only added to the cache
        snapshot_view.contracts.put(self.contract1)
        snapshot_view.contracts.delete(self.contract1_hash)
        # we test if the cache is empty by looking at the count of items in the cache
        self.assertEqual(0, len(snapshot_view.contracts._dictionary))

        # finally we get an existing item, which puts it into CHANGED state
        # then DELETE it and verify it is marked as deleted

        # start by filling the real backend
        raw_view = self.db.get_rawview()
        raw_view.contracts.put(self.contract1)

        # get the item so it creates a cache entry
        contract_from_db = snapshot_view.contracts.get(self.contract1_hash)
        self.assertIsNotNone(contract_from_db)
        # now delete it
        snapshot_view.contracts.delete(self.contract1_hash)
        # and validate the item in cache is marked as DELETED
        self.assertEqual(1, len(snapshot_view.contracts._dictionary))
        trackable = snapshot_view.contracts._dictionary.get(self.contract1_hash, None)  # type: storage.Trackable
        self.assertIsNotNone(trackable)
        self.assertEqual(storage.TrackState.DELETED, trackable.state)

    def test_snapshot_get_various(self):
        snapshot_view = self.db.get_snapshotview()

        # get non existing item
        with self.assertRaises(KeyError):
            snapshot_view.contracts.get(self.contract1_hash)

        # test read only
        raw_view = self.db.get_rawview()
        raw_view.contracts.put(self.contract1)
        contract = snapshot_view.contracts.get(self.contract1_hash, read_only=True)
        contract.script = b'\x11\x22'

        contract_again = snapshot_view.contracts.get(self.contract1_hash, read_only=True)
        # We validate the hash of the original with the hash of the contract we retrieved.
        # The modification of the script attribute above changes the hash, if it persisted
        # the following test fails
        self.assertEqual(self.contract1_hash, contract_again.script_hash())

    def test_snapshot_clone_put(self):
        raw_view = self.db.get_rawview()
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.contracts.put(self.contract1)

        clone_view = snapshot_view.clone()
        # validate it has the same tx
        self.assertEqual(self.contract1, clone_view.contracts.try_get(self.contract1_hash))

        # put some in the clone
        clone_view.contracts.put(self.contract2)

        # validate it is not visible anywhere but in the clone
        self.assertIsNone(raw_view.contracts.try_get(self.contract2_hash))
        self.assertIsNone(snapshot_view.contracts.try_get(self.contract2_hash))
        self.assertEqual(self.contract2, clone_view.contracts.try_get(self.contract2_hash))

        # commit changes of the clone back into the snapshot
        # should affect only the snapshot, not the real backend
        clone_view.commit()
        self.assertIsNone(raw_view.contracts.try_get(self.contract2_hash))
        self.assertEqual(self.contract2, snapshot_view.contracts.try_get(self.contract2_hash))

        # finally commit to real db
        snapshot_view.commit()
        self.assertEqual(self.contract2, raw_view.contracts.try_get(self.contract2_hash))

    def test_snapshot_clone_delete(self):
        raw_view = self.db.get_rawview()
        raw_view.contracts.put(self.contract1)
        snapshot_view = self.db.get_snapshotview()

        # perform a get to fill the cache
        snapshot_view.contracts.get(self.contract1_hash)

        clone_view = snapshot_view.clone()
        # now test deleting an item
        clone_view.contracts.delete(self.contract1_hash)
        # test it's gone in the clone, but nowhere else
        self.assertIsNone(clone_view.contracts.try_get(self.contract1_hash))
        self.assertIsNotNone(snapshot_view.contracts.try_get(self.contract1_hash))
        self.assertIsNotNone(raw_view.contracts.try_get(self.contract1_hash))

        # commit the clone into the snapshot
        clone_view.commit()
        # and validate it is also gone in the snapshot but not the real db
        self.assertIsNone(snapshot_view.contracts.try_get(self.contract1_hash))
        self.assertIsNotNone(raw_view.contracts.try_get(self.contract1_hash))

        # finally persist to real db
        snapshot_view.commit()
        self.assertIsNone(raw_view.contracts.try_get(self.contract1_hash))

    def test_snapshot_clone_update(self):
        raw_view = self.db.get_rawview()
        raw_view.contracts.put(self.contract1)
        snapshot_view = self.db.get_snapshotview()

        # perform a get to fill the cache
        snapshot_view.contracts.get(self.contract1_hash)

        clone_view = snapshot_view.clone()
        contract_from_clone = clone_view.contracts.get(self.contract1_hash)  # type: storage.ContractState
        # modify one of the attributes
        contract_from_clone.manifest.extra = True

        # validate the snapshot and real backend are not affected
        contract_from_snapshot = snapshot_view.contracts.get(self.contract1_hash)
        contract_from_real_db = raw_view.contracts.get(self.contract1_hash)
        self.assertNotEqual(True, contract_from_snapshot.manifest.extra)
        self.assertNotEqual(True, contract_from_real_db.manifest.extra)

        # commit clone
        clone_view.commit()
        # now snapshot should be updated, but real db not
        contract_from_snapshot = snapshot_view.contracts.get(self.contract1_hash)
        contract_from_real_db = raw_view.contracts.get(self.contract1_hash)
        self.assertEqual(True, contract_from_snapshot.manifest.extra)
        self.assertNotEqual(True, contract_from_real_db.manifest.extra)

        # finally persist to real db
        snapshot_view.commit()
        contract_from_real_db = raw_view.contracts.get(self.contract1_hash)
        self.assertEqual(True, contract_from_real_db.manifest.extra)

    def test_all(self):
        raw_view = self.db.get_rawview()
        raw_view.contracts.put(self.contract1)
        raw_view.contracts.put(self.contract2)

        snapshot_view = self.db.get_snapshotview()
        # get contract 2 to add a cache entry, so we can confirm correct sorting
        snapshot_view.contracts.get(self.contract2_hash, read_only=True)

        contracts = list(snapshot_view.contracts.all())
        self.assertEqual(2, len(contracts))
        self.assertEqual(self.contract1, contracts[0])
        self.assertEqual(self.contract2, contracts[1])

        # Ensure results are readonly. We modify the manifest, because that's the attribute which does not affect the
        # key the contract is stored under (a.k.a does not affect the contract script hash)
        mani = manifest.ContractManifest()
        mani._attr_for_test = 111
        contracts[0].manifest = mani
        contracts[1].manifest = mani

        mani1_from_snapshot = snapshot_view.contracts.get(self.contract1_hash, read_only=True)
        mani2_from_snapshot = snapshot_view.contracts.get(self.contract2_hash, read_only=True)
        # validate the manifest is unchanged
        self.assertIsNone(mani1_from_snapshot.manifest.extra)
        self.assertIsNone(mani2_from_snapshot.manifest.extra)

        # find something that's only in a clone
        clone_view = snapshot_view.clone()
        clone_view.contracts.put(self.contract3)

        contracts = list(clone_view.contracts.all())
        self.assertEqual(3, len(contracts))
        self.assertEqual(2, len(list(snapshot_view.contracts.all())))
        self.assertEqual(self.contract1, contracts[0])
        self.assertEqual(self.contract2, contracts[1])
        self.assertEqual(self.contract3, contracts[2])


class AbstractStorageStorageTest(abc.ABC, unittest.TestCase):
    """
    A helper class to easily test backend specific code
    """

    @abc.abstractmethod
    def db_factory(self):
        """ Implement to return an instance of your DB """

    def setUp(self) -> None:
        self.db = self.db_factory()
        self.contract1_hash = types.UInt160.from_string("d7678dd97c000be3f33e9362e673101bac4ca654")

        self.storagekey1 = storage.StorageKey(self.contract1_hash, b'\x01\x02')
        self.storageitem1 = storage.StorageItem(b'\x01\x01')

        self.contract2_hash = types.UInt160.from_string("AAAA8dd97c000be3f33e9362e673101bac4cFFFF")

        self.storagekey2 = storage.StorageKey(self.contract2_hash, b'\x03\x04')
        self.storageitem2 = storage.StorageItem(b'\x02\x02')

        self.storagekey3 = storage.StorageKey(self.contract2_hash, b'\x03\x05')
        self.storageitem3 = storage.StorageItem(b'\x03\x03')

        self.storagekey4 = storage.StorageKey(self.contract2_hash, b'\x04\x04')
        self.storageitem4 = storage.StorageItem(b'\x04\x04')

    def test_raw(self):
        raw_view = self.db.get_rawview()

        # we should not find any key in an empty db
        target_key = storage.StorageKey(types.UInt160.zero(), b'\x00')
        with self.assertRaises(KeyError):
            raw_view.storages.get(target_key)
        self.assertIsNone(raw_view.storages.try_get(target_key))

        # fill the db
        raw_view.storages.put(self.storagekey1, self.storageitem1)
        # and test it is immediately added
        item_from_db = raw_view.storages.try_get(self.storagekey1)
        self.assertIsNotNone(item_from_db)
        self.assertEqual(self.storageitem1, item_from_db)

        # test getting all storages
        raw_view.storages.put(self.storagekey2, self.storageitem2)
        storage_pairs = dict(raw_view.storages.all())
        self.assertEqual(2, len(storage_pairs))
        self.assertIn(self.storagekey1, storage_pairs)
        self.assertIn(self.storagekey2, storage_pairs)
        self.assertIn(self.storageitem1, storage_pairs.values())
        self.assertIn(self.storageitem2, storage_pairs.values())

        # test finding keys
        raw_view.storages.put(self.storagekey3, self.storageitem3)

        storage_pairs = dict(raw_view.storages.find(self.contract2_hash, b'\03'))
        self.assertEqual(2, len(storage_pairs))
        self.assertNotIn(self.storagekey1, storage_pairs)
        self.assertIn(self.storagekey2, storage_pairs)
        self.assertIn(self.storagekey3, storage_pairs)
        self.assertNotIn(self.storageitem1, storage_pairs.values())
        self.assertIn(self.storageitem2, storage_pairs.values())
        self.assertIn(self.storageitem3, storage_pairs.values())

        # finally try removing the tx
        raw_view.storages.delete(self.storagekey1)
        self.assertIsNone(raw_view.storages.try_get(self.storagekey1))

    def test_snapshot_basic_add_delete_get(self):
        # test basic add, delete, get and separation
        raw_view = self.db.get_rawview()
        snapshot_view = self.db.get_snapshotview()

        # we should not find any key in an empty db
        target_key = storage.StorageKey(types.UInt160.zero(), b'\x00')
        with self.assertRaises(KeyError):
            raw_view.storages.get(target_key)
        self.assertIsNone(raw_view.storages.try_get(target_key))

        # add item
        snapshot_view.storages.put(self.storagekey1, self.storageitem1)
        # real backend should not be affected until a commit is called
        self.assertIsNone(raw_view.storages.try_get(self.storagekey1))

        # persist to backend
        snapshot_view.commit()
        storage_from_db = raw_view.storages.try_get(self.storagekey1)
        # and validate
        self.assertIsNotNone(storage_from_db)
        self.assertEqual(self.storageitem1, storage_from_db)

        # finally, try deleting
        # get a clean view with no cache
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.storages.delete(self.storagekey1)

        # real backend should still have it, snapshot not
        self.assertIsNotNone(raw_view.storages.try_get(self.storagekey1))
        self.assertIsNone(snapshot_view.storages.try_get(self.storagekey1))

        # persist and validate real backend also doesn't have it anymore
        snapshot_view.commit()
        self.assertIsNone(raw_view.storages.try_get(self.storagekey1))

    def test_snapshot_with_context_manager(self):
        # partially repeat test_snapshot_basic_add_delete_get()
        raw_view = self.db.get_rawview()
        with self.db.get_snapshotview() as snapshot_view:
            # we should not find any key in an empty db
            target_key = storage.StorageKey(types.UInt160.zero(), b'\x00')
            with self.assertRaises(KeyError):
                raw_view.storages.get(target_key)
            self.assertIsNone(raw_view.storages.try_get(target_key))

            # add item
            snapshot_view.storages.put(self.storagekey1, self.storageitem1)
            # real backend should not be affected until a commit is called
            self.assertIsNone(raw_view.storages.try_get(self.storagekey1))

            # persist to backend
            snapshot_view.commit()
            storage_from_db = raw_view.storages.try_get(self.storagekey1)
            # and validate
            self.assertIsNotNone(storage_from_db)
            self.assertEqual(self.storageitem1, storage_from_db)

    def test_snapshot_add_duplicates(self):
        snapshot_view = self.db.get_snapshotview()

        # test double adding while already in cache
        snapshot_view.storages.put(self.storagekey1, self.storageitem1)
        with self.assertRaises(ValueError):
            snapshot_view.storages.put(self.storagekey1, self.storageitem1)

        # test double adding when not in cache, but in real backend
        snapshot_view.commit()
        # get a clean one with an empty cache
        snapshot_view = self.db.get_snapshotview()
        with self.assertRaises(ValueError):
            snapshot_view.storages.put(self.storagekey1, self.storageitem1)

    def test_snapshot_add_while_cache_marked_deleted(self):
        # an item can exist in the real backend, and be marked in cache to be deleted
        # it should then be possible to delete it from cache without exceptions

        # fill real backend
        raw_view = self.db.get_rawview()
        raw_view.storages.put(self.storagekey1, self.storageitem1)

        # ensure item is marked as deleted in cache
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.storages.delete(self.storagekey1)

        # now test by adding add the item again
        success = False
        with suppress(ValueError):
            snapshot_view.storages.put(self.storagekey1, self.storageitem1)
            success = True
        self.assertTrue(success)

    def test_snapshot_delete_various(self):
        snapshot_view = self.db.get_snapshotview()

        # delete non existing item with empty cache should throw no errors
        ok = False
        with suppress(Exception):
            snapshot_view.storages.delete(self.storagekey1)
            ok = True
        self.assertTrue(ok)

        # delete an item that was only added to the cache
        snapshot_view.storages.put(self.storagekey1, self.storageitem1)
        snapshot_view.storages.delete(self.storagekey1)
        # we test if the cache is empty by looking at the count of items in the cache
        self.assertEqual(0, len(snapshot_view.storages._dictionary))

        # finally we get an existing item, which puts it into CHANGED state
        # then DELETE it and verify it is marked as deleted

        # start by filling the real backend
        raw_view = self.db.get_rawview()
        raw_view.storages.put(self.storagekey1, self.storageitem1)

        # get the item so it creates a cache entry
        value_from_db = snapshot_view.storages.get(self.storagekey1)
        self.assertIsNotNone(value_from_db)
        # now delete it
        snapshot_view.storages.delete(self.storagekey1)
        # and validate the item in cache is marked as DELETED
        self.assertEqual(1, len(snapshot_view.storages._dictionary))
        trackable = snapshot_view.storages._dictionary.get(self.storagekey1, None)  # type: storage.Trackable
        self.assertIsNotNone(trackable)
        self.assertEqual(storage.TrackState.DELETED, trackable.state)

    def test_snapshot_get_various(self):
        snapshot_view = self.db.get_snapshotview()

        # get non existing item
        with self.assertRaises(KeyError):
            snapshot_view.storages.get(self.storagekey1)

        # test read only
        raw_view = self.db.get_rawview()
        raw_view.storages.put(self.storagekey1, self.storageitem1)
        storageitem = snapshot_view.storages.get(self.storagekey1, read_only=True)
        storageitem.value = b'\x55\x55'

        storageitem_again = snapshot_view.storages.get(self.storagekey1, read_only=True)
        self.assertEqual(self.storageitem1, storageitem_again)

    def test_snapshot_clone_put(self):
        raw_view = self.db.get_rawview()
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.storages.put(self.storagekey1, self.storageitem1)

        clone_view = snapshot_view.clone()
        # validate it has the same tx
        self.assertEqual(self.storageitem1, clone_view.storages.try_get(self.storagekey1))

        # put some in the clone
        clone_view.storages.put(self.storagekey2, self.storageitem2)

        # validate it is not visible anywhere but in the clone
        self.assertIsNone(raw_view.storages.try_get(self.storagekey2))
        self.assertIsNone(snapshot_view.storages.try_get(self.storagekey2))
        self.assertEqual(self.storageitem2, clone_view.storages.try_get(self.storagekey2))

        # commit changes of the clone back into the snapshot
        # should affect only the snapshot, not the real backend
        clone_view.commit()
        self.assertIsNone(raw_view.storages.try_get(self.storagekey2))
        self.assertEqual(self.storageitem2, snapshot_view.storages.try_get(self.storagekey2))

        # finally commit to real db
        snapshot_view.commit()
        self.assertEqual(self.storageitem2, raw_view.storages.try_get(self.storagekey2))

    def test_snapshot_clone_delete(self):
        raw_view = self.db.get_rawview()
        raw_view.storages.put(self.storagekey1, self.storageitem1)
        snapshot_view = self.db.get_snapshotview()

        # perform a get to fill the cache
        snapshot_view.storages.get(self.storagekey1)

        clone_view = snapshot_view.clone()
        # now test deleting an item
        clone_view.storages.delete(self.storagekey1)
        # test it's gone in the clone, but nowhere else
        self.assertIsNone(clone_view.storages.try_get(self.storagekey1))
        self.assertIsNotNone(snapshot_view.storages.try_get(self.storagekey1))
        self.assertIsNotNone(raw_view.storages.try_get(self.storagekey1))

        # commit the clone into the snapshot
        clone_view.commit()
        # and validate it is also gone in the snapshot but not the real db
        self.assertIsNone(snapshot_view.storages.try_get(self.storagekey1))
        self.assertIsNotNone(raw_view.storages.try_get(self.storagekey1))

        # finally persist to real db
        snapshot_view.commit()
        self.assertIsNone(raw_view.storages.try_get(self.storagekey1))

    def test_snapshot_clone_update(self):
        raw_view = self.db.get_rawview()
        raw_view.storages.put(self.storagekey1, self.storageitem1)
        snapshot_view = self.db.get_snapshotview()

        # perform a get to fill the cache
        snapshot_view.storages.get(self.storagekey1)

        clone_view = snapshot_view.clone()
        value_from_clone = clone_view.storages.get(self.storagekey1) # type: storage.StorageItem
        value_from_clone.value = b'\x55\x55'

        # validate the snapshot and real backend are not affected
        value_from_snapshot = snapshot_view.storages.get(self.storagekey1)
        value_from_real_db = raw_view.storages.get(self.storagekey1)
        self.assertNotEqual(b'\x55\x55', value_from_snapshot.value)
        self.assertNotEqual(b'\x55\x55', value_from_real_db.value)

        # commit clone
        clone_view.commit()
        # now snapshot should be updated, but real db not
        value_from_snapshot = snapshot_view.storages.get(self.storagekey1)
        value_from_real_db = raw_view.storages.get(self.storagekey1)
        self.assertEqual(b'\x55\x55', value_from_snapshot.value)
        self.assertNotEqual(b'\x55\x55', value_from_real_db.value)

        # finally persist to real db
        snapshot_view.commit()
        value_from_real_db = raw_view.storages.get(self.storagekey1)
        self.assertEqual(b'\x55\x55', value_from_real_db.value)

    def test_all(self):
        raw_view = self.db.get_rawview()
        raw_view.storages.put(self.storagekey1, self.storageitem1)
        raw_view.storages.put(self.storagekey2, self.storageitem2)
        raw_view.storages.put(self.storagekey3, self.storageitem3)

        snapshot_view = self.db.get_snapshotview()
        # get a key to fill the cache so we can test sorting and readonly behaviour
        # key3 should come after key 2
        snapshot_view.storages.get(self.storagekey3, read_only=True)

        all_pairs = dict(snapshot_view.storages.all(self.contract2_hash))
        self.assertEqual(2, len(all_pairs))
        self.assertNotIn(self.storagekey1, all_pairs)
        self.assertEqual(self.storagekey2, list(all_pairs.keys())[0])
        self.assertEqual(self.storagekey3, list(all_pairs.keys())[1])
        self.assertNotIn(self.storageitem1, all_pairs.values())
        self.assertEqual(self.storageitem2, list(all_pairs.values())[0])
        self.assertEqual(self.storageitem3, list(all_pairs.values())[1])

        # test results are readonly by modifying the results and requesting it again from the snapshot.
        storage_item2 = list(all_pairs.values())[0]
        storage_item3 = list(all_pairs.values())[1]
        storage_item2.value = b'\x55\x55'
        storage_item3.value = b'\x55\x55'
        item2_from_snap = snapshot_view.storages.get(self.storagekey2, read_only=True)
        item3_from_snap = snapshot_view.storages.get(self.storagekey3, read_only=True)
        self.assertNotEqual(b'\x55\x55', item2_from_snap.value)
        self.assertNotEqual(b'\x55\x55', item3_from_snap.value)


        clone_view = snapshot_view.clone()
        clone_view.storages.put(self.storagekey4, self.storageitem4)

        all_pairs = dict(clone_view.storages.all(self.contract2_hash))
        self.assertEqual(3, len(all_pairs))
        self.assertEqual(2, len(list(snapshot_view.storages.all(self.contract2_hash))))
        self.assertNotIn(self.storagekey1, all_pairs)
        self.assertEqual(self.storagekey2, list(all_pairs.keys())[0])
        self.assertEqual(self.storagekey3, list(all_pairs.keys())[1])
        self.assertEqual(self.storagekey4, list(all_pairs.keys())[2])
        self.assertNotIn(self.storageitem1, all_pairs.values())
        self.assertEqual(self.storageitem2, list(all_pairs.values())[0])
        self.assertEqual(self.storageitem3, list(all_pairs.values())[1])
        self.assertEqual(self.storageitem4, list(all_pairs.values())[2])

    def test_find(self):
        raw_view = self.db.get_rawview()
        raw_view.storages.put(self.storagekey1, self.storageitem1)
        raw_view.storages.put(self.storagekey2, self.storageitem2)
        raw_view.storages.put(self.storagekey3, self.storageitem3)
        raw_view.storages.put(self.storagekey4, self.storageitem4)

        snapshot_view = self.db.get_snapshotview()

        # get a key to fill the cache so we can test sorting and readonly behaviour
        # key3 should come after key 2
        snapshot_view.storages.get(self.storagekey3, read_only=True)


        # key2,3 and 4 are of the same smart contract
        # only key2 and key3 start with \x03
        all_pairs = list(snapshot_view.storages.find(self.contract2_hash, b'\x03'))
        keys = list(map(lambda i: i[0], all_pairs))
        items = list(map(lambda i: i[1], all_pairs))
        self.assertEqual(2, len(all_pairs))
        self.assertNotIn(self.storagekey1, keys)
        self.assertEqual(self.storagekey2, keys[0])
        self.assertEqual(self.storagekey3, keys[1])
        self.assertNotIn(self.storagekey4, keys)

        self.assertNotIn(self.storageitem1, items)
        self.assertEqual(self.storageitem2, items[0])
        self.assertEqual(self.storageitem3, items[1])
        self.assertNotIn(self.storageitem4, items)

        # test for read only results
        items[0].value = b'\x55\x55'
        item_from_snap = snapshot_view.storages.get(self.storagekey3, read_only=True)
        self.assertNotEqual(b'\x55\x55', item_from_snap.value)

        keys[0].key = b'\x77\x77'

        # create a storage key that should match the above modification
        modified_key = storage.StorageKey(self.contract2_hash, b'\x77\x77')
        # and we should not find it
        self.assertIsNone(snapshot_view.storages.try_get(modified_key, read_only=True))

        # test find in clone
        clone_key = storage.StorageKey(self.contract2_hash, b'\x03\x88')
        clone_item = storage.StorageItem(b'\x99\x99')
        clone_view = snapshot_view.clone()
        clone_view.storages.put(clone_key, clone_item)
        all_pairs = list(clone_view.storages.find(self.contract2_hash, b'\x03'))
        self.assertEqual(3, len(all_pairs))


    def test_find_extra(self):
        """
        This test used to fail on Neo 2.x and was reported here: https://github.com/neo-project/neo/issues/946

        They changed the logic to be deterministic, so we simulate the same

        public class Test : DataCache<StorageKey, StorageItem>
        {
            static StorageItem si = new StorageItem { IsConstant = false, Value = new byte[] { 0x1 } };
            static StorageKey key1 = new StorageKey { ScriptHash = UInt160.Zero, Key = new byte[] { 1 } };
            static StorageKey key2 = new StorageKey { ScriptHash = UInt160.Zero, Key = new byte[] { 2 } };
            static StorageKey key3 = new StorageKey { ScriptHash = UInt160.Zero, Key = new byte[] { 3 } };

            static Dictionary<StorageKey, StorageItem> innerDictionary = new Dictionary<StorageKey, StorageItem>() {
                { key1, si },
                { key2, si },
                { key3, si }
            };

            public override void DeleteInternal(StorageKey key)
            {
                throw new NotImplementedException();
            }

            protected override void AddInternal(StorageKey key, StorageItem value)
            {
                throw new NotImplementedException();
            }

            protected override IEnumerable<KeyValuePair<StorageKey, StorageItem>> FindInternal(byte[] key_prefix)
            {
                foreach (var pair in innerDictionary)
                {
                    yield return new KeyValuePair<StorageKey, StorageItem>(pair.Key, pair.Value);
                }
            }

            protected override StorageItem GetInternal(StorageKey key)
            {
                return innerDictionary[key];
            }

            protected override StorageItem TryGetInternal(StorageKey key)
            {
                return innerDictionary[key];
            }

            protected override void UpdateInternal(StorageKey key, StorageItem value)
            {
                throw new NotImplementedException();
            }
        }

        public static void Main(string[] args)
        {
            DataCache<StorageKey, StorageItem> test = new Test();
            StorageKey key1 = new StorageKey { ScriptHash = UInt160.Zero, Key = new byte[] { 1 } };

            test.TryGet(key1);
            foreach (KeyValuePair<StorageKey, StorageItem> pair in test.Find())
            {
                Console.WriteLine($"{BitConverter.ToString(pair.Key.Key)}");
            }
        }


        """
        key1 = storage.StorageKey(types.UInt160.zero(), b'key1')
        key2 = storage.StorageKey(types.UInt160.zero(), b'key2')
        key3 = storage.StorageKey(types.UInt160.zero(), b'key3')
        value1 = storage.StorageItem(b'value1')

        snapshot_view = self.db.get_snapshotview()
        snapshot_view.storages.put(key1, value1)
        snapshot_view.storages.put(key2, value1)
        snapshot_view.storages.put(key3, value1)
        results = list(snapshot_view.storages.all())
        self.assertEqual(key1, results[0][0])
        self.assertEqual(key2, results[1][0])
        self.assertEqual(key3, results[2][0])

        # NEO-cli sorts keys based on the serialized TKey value, we make 1 special case where we change the contract
        key1 = storage.StorageKey(types.UInt160.from_string("0000000000000000000000000000000000000001"), key=b'key1')
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.storages.put(key1, value1)
        snapshot_view.storages.put(key2, value1)
        snapshot_view.storages.put(key3, value1)
        results = list(snapshot_view.storages.all())
        self.assertEqual(key2, results[0][0])
        self.assertEqual(key3, results[1][0])
        self.assertEqual(key1, results[2][0])

    def test_issue_1672(self):
        # test if we are affected by https://github.com/neo-project/neo/issues/1672
        self.storagekey1 = storage.StorageKey(self.contract1_hash, b'\x00\x01')
        self.storagekey2 = storage.StorageKey(self.contract1_hash, b'\x00\x02')
        self.storagekey3 = storage.StorageKey(self.contract1_hash, b'\x00\x03')
        self.storagekey4 = storage.StorageKey(self.contract1_hash, b'\x00\x04')

        self.storageitem1 = storage.StorageItem(b'\x01\x01')
        self.storageitem2 = storage.StorageItem(b'\x02\x02')
        self.storageitem3 = storage.StorageItem(b'\x03\x03')
        self.storageitem4 = storage.StorageItem(b'\x04\x04')

        # prepare
        snapshot = self.db.get_snapshotview()
        snapshot.storages.put(self.storagekey1, self.storageitem1)

        raw = self.db.get_rawview()
        raw.storages.put(self.storagekey2, self.storageitem2)
        raw.storages.put(self.storagekey3, self.storageitem3)
        raw.storages.put(self.storagekey4, self.storageitem4)

        # test
        iter = snapshot.storages.find(self.contract1_hash, key_prefix=b'\x00')
        kv_pair = next(iter)
        self.assertEqual(self.storagekey1, kv_pair[0])

        kv_pair = snapshot.storages.get(self.storagekey3)
        kv_pair = next(iter)
        self.assertEqual(self.storagekey2, kv_pair[0])
        self.assertEqual(self.storageitem2, kv_pair[1])

        kv_pair = next(iter)
        self.assertEqual(self.storagekey3, kv_pair[0])
        self.assertEqual(self.storageitem3, kv_pair[1])

        kv_pair = next(iter)
        self.assertEqual(self.storagekey4, kv_pair[0])
        self.assertEqual(self.storageitem4, kv_pair[1])


class AbstractTransactionStorageTest(abc.ABC, unittest.TestCase):
    """
    A helper class to easily test backend specific code
    """

    @abc.abstractmethod
    def db_factory(self):
        """ Implement to return an instance of your DB """

    def setUp(self) -> None:
        self.db = self.db_factory()

        cosigner = payloads.Signer(account=types.UInt160.from_string("d7678dd97c000be3f33e9362e673101bac4ca654"),
                                   scope=payloads.WitnessScope.GLOBAL)

        witness = payloads.Witness(invocation_script=b'', verification_script=b'\x55')

        self.tx1 = payloads.Transaction(version=0,
                                        nonce=123,
                                        system_fee=456,
                                        network_fee=789,
                                        valid_until_block=1,
                                        attributes=[],
                                        signers=[cosigner],
                                        script=b'\x01\x02',
                                        witnesses=[witness])

        self.tx1_hash = self.tx1.hash()
        # by changing the script we change the TX hash
        self.tx2 = deepcopy(self.tx1)
        self.tx2.script = b'\x03\x04'
        self.tx2_hash = self.tx2.hash()

    def test_raw(self):
        raw_view = self.db.get_rawview()

        # we should not find anything in an empty db
        target_tx_hash = types.UInt256.zero()
        with self.assertRaises(KeyError) as context:
            raw_view.transactions.get(target_tx_hash)
        self.assertIsNone(raw_view.transactions.try_get(target_tx_hash))

        # fill the db
        raw_view.transactions.put(self.tx1)
        # and test it is immediately added
        tx_from_db = raw_view.transactions.try_get(self.tx1_hash)
        self.assertIsNotNone(tx_from_db)
        self.assertEqual(self.tx1, tx_from_db)

        # test getting all transactions
        raw_view.transactions.put(self.tx2)
        txs = list(raw_view.transactions.all())
        self.assertEqual(2, len(txs))
        self.assertIn(self.tx1, txs)
        self.assertIn(self.tx2, txs)

        # finally try removing the tx
        raw_view.transactions.delete(self.tx1_hash)
        self.assertIsNone(raw_view.transactions.try_get(self.tx1_hash))

    def test_snapshot_basic_add_delete_get(self):
        # test basic add, delete, get and separation
        raw_view = self.db.get_rawview()
        snapshot_view = self.db.get_snapshotview()

        # we should not find anything in an empty db
        target_tx_hash = types.UInt256.zero()
        with self.assertRaises(KeyError) as context:
            snapshot_view.transactions.get(target_tx_hash)
        self.assertIsNone(snapshot_view.transactions.try_get(target_tx_hash))

        # add item
        snapshot_view.transactions.put(self.tx1)
        # real backend should not be affected until a commit is called
        self.assertIsNone(raw_view.transactions.try_get(self.tx1_hash))

        # persist to backend
        snapshot_view.commit()
        tx_from_db = raw_view.transactions.try_get(self.tx1_hash)
        # and validate
        self.assertIsNotNone(tx_from_db)
        self.assertEqual(self.tx1, tx_from_db)

        # finally, try deleting
        # get a clean view with no cache
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.transactions.delete(self.tx1_hash)

        # real backend should still have it, snapshot not
        self.assertIsNotNone(raw_view.transactions.try_get(self.tx1_hash))
        self.assertIsNone(snapshot_view.transactions.try_get(self.tx1_hash))

        # persist and validate real backend also doesn't have it anymore
        snapshot_view.commit()
        self.assertIsNone(raw_view.transactions.try_get(self.tx1_hash))

    def test_snapshot_add_duplicates(self):
        snapshot_view = self.db.get_snapshotview()

        # test double adding while already in cache
        snapshot_view.transactions.put(self.tx1)
        with self.assertRaises(ValueError):
            snapshot_view.transactions.put(self.tx1)

        # test double adding when not in cache, but in real backend
        snapshot_view.commit()
        # get a clean one with an empty cache
        snapshot_view = self.db.get_snapshotview()
        with self.assertRaises(ValueError):
            snapshot_view.transactions.put(self.tx1)

    def test_snapshot_add_while_cache_marked_deleted(self):
        # an item can exist in the real backend, and be marked in cache to be deleted
        # it should then be possible to delete it from cache without exceptions

        # fill real backend
        raw_view = self.db.get_rawview()
        raw_view.transactions.put(self.tx1)

        # ensure item is marked as deleted in cache
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.transactions.delete(self.tx1_hash)

        # now test by adding add the item again
        success = False
        with suppress(ValueError):
            snapshot_view.transactions.put(self.tx1)
            success = True
        self.assertTrue(success)

    def test_snapshot_delete_various(self):
        snapshot_view = self.db.get_snapshotview()

        # delete non existing item with empty cache should throw no errors
        ok = False
        with suppress(Exception):
            snapshot_view.transactions.delete(self.tx1_hash)
            ok = True
        self.assertTrue(ok)

        # delete an item that was only added to the cache
        snapshot_view.transactions.put(self.tx1)
        snapshot_view.transactions.delete(self.tx1_hash)
        # we test if the cache is empty by looking at the count of items in the cache
        self.assertEqual(0, len(snapshot_view.transactions._dictionary))

        # finally we get an existing item, which puts it into CHANGED state
        # then DELETE it and verify it is marked as deleted

        # start by filling the real backend
        raw_view = self.db.get_rawview()
        raw_view.transactions.put(self.tx1)

        # get the item so it creates a cache entry
        tx_from_db = snapshot_view.transactions.get(self.tx1_hash)
        self.assertIsNotNone(tx_from_db)
        # now delete it
        snapshot_view.transactions.delete(self.tx1_hash)
        # and validate the item in cache is marked as DELETED
        self.assertEqual(1, len(snapshot_view.transactions._dictionary))
        trackable = snapshot_view.transactions._dictionary.get(self.tx1_hash, None)  # type: storage.Trackable
        self.assertIsNotNone(trackable)
        self.assertEqual(storage.TrackState.DELETED, trackable.state)

    def test_snapshot_get_various(self):
        snapshot_view = self.db.get_snapshotview()

        # get non existing item
        with self.assertRaises(KeyError):
            snapshot_view.transactions.get(self.tx1_hash)

        # test read only
        raw_view = self.db.get_rawview()
        raw_view.transactions.put(self.tx1)
        tx = snapshot_view.transactions.get(self.tx1_hash, read_only=True)
        tx.script = b'\x11\x22'

        tx_again = snapshot_view.transactions.get(self.tx1_hash, read_only=True)
        # We validate the hash of the original with the hash of the tx we retrieved.
        # The modification of the script attribute above changes the hash, if it persisted
        # the following test fails
        self.assertEqual(self.tx1_hash, tx_again.hash())

    def test_snapshot_clone_put(self):
        raw_view = self.db.get_rawview()
        snapshot_view = self.db.get_snapshotview()
        snapshot_view.transactions.put(self.tx1)

        clone_view = snapshot_view.clone()
        # validate it has the same tx
        self.assertEqual(self.tx1, clone_view.transactions.try_get(self.tx1_hash))

        # put some in the clone
        clone_view.transactions.put(self.tx2)

        # validate it is not visible anywhere but in the clone
        self.assertIsNone(raw_view.transactions.try_get(self.tx2_hash))
        self.assertIsNone(snapshot_view.transactions.try_get(self.tx2_hash))
        self.assertEqual(self.tx2, clone_view.transactions.try_get(self.tx2_hash))

        # commit changes of the clone back into the snapshot
        # should affect only the snapshot, not the real backend
        clone_view.commit()
        self.assertIsNone(raw_view.transactions.try_get(self.tx2_hash))
        self.assertEqual(self.tx2, snapshot_view.transactions.try_get(self.tx2_hash))

        # finally commit to real db
        snapshot_view.commit()
        self.assertEqual(self.tx2, raw_view.transactions.try_get(self.tx2_hash))

    def test_snapshot_clone_delete(self):
        raw_view = self.db.get_rawview()
        raw_view.transactions.put(self.tx1)
        snapshot_view = self.db.get_snapshotview()

        # perform a get to fill the cache
        snapshot_view.transactions.get(self.tx1_hash)

        clone_view = snapshot_view.clone()
        # now test deleting an item
        clone_view.transactions.delete(self.tx1_hash)
        # test it's gone in the clone, but nowhere else
        self.assertIsNone(clone_view.transactions.try_get(self.tx1_hash))
        self.assertIsNotNone(snapshot_view.transactions.try_get(self.tx1_hash))
        self.assertIsNotNone(raw_view.transactions.try_get(self.tx1_hash))

        # commit the clone into the snapshot
        clone_view.commit()
        # and validate it is also gone in the snapshot but not the real db
        self.assertIsNone(snapshot_view.transactions.try_get(self.tx1_hash))
        self.assertIsNotNone(raw_view.transactions.try_get(self.tx1_hash))

        # finally persist to real db
        snapshot_view.commit()
        self.assertIsNone(raw_view.transactions.try_get(self.tx1_hash))

    def test_snapshot_clone_update(self):
        # special note, we cannot change any of the official Transaction object attributes as that would change
        # the hash of the tx which is used as the identifier to find the item in the cache
        raw_view = self.db.get_rawview()
        raw_view.transactions.put(self.tx1)
        snapshot_view = self.db.get_snapshotview()

        # perform a get to fill the cache
        snapshot_view.transactions.get(self.tx1_hash)

        clone_view = snapshot_view.clone()
        tx_from_clone = clone_view.transactions.get(self.tx1_hash)  # type: payloads.Transaction
        # modify one of augmented attributes
        tx_from_clone.block_height = 1

        # validate the snapshot and real backend are not affected
        tx_from_snapshot = snapshot_view.transactions.get(self.tx1_hash)
        tx_from_real_db = raw_view.transactions.get(self.tx1_hash)
        self.assertNotEqual(1, tx_from_snapshot.block_height)
        self.assertNotEqual(1, tx_from_real_db.block_height)

        # commit clone
        clone_view.commit()
        # now snapshot should be updated, but real db not
        tx_from_snapshot = snapshot_view.transactions.get(self.tx1_hash)
        tx_from_real_db = raw_view.transactions.get(self.tx1_hash)
        self.assertEqual(1, tx_from_snapshot.block_height)
        self.assertNotEqual(1, tx_from_real_db.block_height)

        # finally persist to real db
        snapshot_view.commit()
        tx_from_real_db = raw_view.transactions.get(self.tx1_hash)
        self.assertEqual(1, tx_from_real_db.block_height)

    def test_all(self):
        raw_view = self.db.get_rawview()
        raw_view.transactions.put(self.tx1)
        raw_view.transactions.put(self.tx2)

        snapshot_view = self.db.get_snapshotview()

        # get() a tx to fill the cache so we can test sorting and readonly behaviour
        # tx2's hash comes before tx1 when sorting. So we cache that first as the all() internals
        # collect the results from the backend (=tx1) before results from the cache (=tx2).
        # Therefore if tx2 is found in the first position of the all() results, we can
        # conclude that the sort() happened correctly.
        snapshot_view.transactions.get(self.tx2_hash, read_only=True)

        txs = list(snapshot_view.transactions.all())
        self.assertEqual(2, len(txs))
        self.assertEqual(self.tx2, txs[0])
        self.assertEqual(self.tx1, txs[1])

        # ensure all() results are readonly
        txs[0].block_height = 999
        txs[1].block_height = 999

        tx1_from_snap = snapshot_view.transactions.get(self.tx1_hash, read_only=True)
        tx2_from_snap = snapshot_view.transactions.get(self.tx2_hash, read_only=True)
        self.assertNotEqual(999, tx1_from_snap.block_height)
        self.assertNotEqual(999, tx2_from_snap.block_height)

        # test clone all()
        tx3 = deepcopy(self.tx1)
        tx3.script = b'\x05\x06'
        clone_view = snapshot_view.clone()
        clone_view.transactions.put(tx3)

        txs = list(clone_view.transactions.all())
        self.assertEqual(3, len(txs))
        self.assertEqual(2, len(list(snapshot_view.transactions.all())))
        self.assertEqual(self.tx1, txs[2])
        self.assertEqual(self.tx2, txs[1])
        self.assertEqual(tx3, txs[0])
