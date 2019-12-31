import shutil
from contextlib import suppress
from tests.storage import storagetest
from neo3.storage import implementations


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