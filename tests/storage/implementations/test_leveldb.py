import shutil
import unittest
from sys import stderr
from contextlib import suppress
from tests.storage import storagetest
from neo3.storage import implementations


def setUpModule():
    try:
        options = {'path': './unittest-leveldb'}
        return implementations.LevelDB(options)
    except ModuleNotFoundError as mne:
        print(mne, file=stderr)
        raise


class LevelDBBlocksTestCase(storagetest.AbstractBlockStorageTest):
    def db_factory(self):
        options = {'path': './unittest-leveldb'}
        return implementations.LevelDB(options)

    def tearDown(self) -> None:
        self.db.close()
        with suppress(Exception):
            shutil.rmtree('./unittest-leveldb')


class LevelDBContractsTestCase(storagetest.AbstractContractStorageTest):
    def db_factory(self):
        options = {'path': './unittest-leveldb'}
        return implementations.LevelDB(options)

    def tearDown(self) -> None:
        self.db.close()
        with suppress(Exception):
            shutil.rmtree('./unittest-leveldb')


class LevelDBStoragesTestCase(storagetest.AbstractStorageStorageTest):
    def db_factory(self):
        options = {'path': './unittest-leveldb'}
        return implementations.LevelDB(options)

    def tearDown(self) -> None:
        self.db.close()
        with suppress(Exception):
            shutil.rmtree('./unittest-leveldb')


class LevelDBTransactionsTestCase(storagetest.AbstractTransactionStorageTest):
    def db_factory(self):
        options = {'path': './unittest-leveldb'}
        return implementations.LevelDB(options)

    def tearDown(self) -> None:
        self.db.close()
        with suppress(Exception):
            shutil.rmtree('./unittest-leveldb')


class LevelDBVariousTests(unittest.TestCase):
    def test_plyvel_init_exception(self):
        options = {}
        with self.assertRaises(Exception) as context:
            implementations.LevelDB(options)
        self.assertIn("leveldb exception", str(context.exception))

    def test_no_plyvel_support(self):
        # at this point we know level_db_supported is always true because otherwise it would have failed
        # at `setUpModule` and this test case would never have been called.
        implementations.leveldb.level_db_supported = False
        options = {}
        try:
            with self.assertRaises(Exception) as context:
                implementations.LevelDB(options)
            self.assertIn("plyvel module not found - try 'pip install plyvel", str(context.exception))
        finally:
            implementations.leveldb.level_db_supported = True

