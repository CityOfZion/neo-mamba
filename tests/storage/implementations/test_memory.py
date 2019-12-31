from tests.storage import storagetest
from neo3.storage import implementations


class InMemoryDBBlocksTestCase(storagetest.AbstractBlockStorageTest):
    def db_factory(self):
        return implementations.MemoryDB()

class InMemoryDBContractsTestCase(storagetest.AbstractContractStorageTest):
    def db_factory(self):
        return implementations.MemoryDB()

class InMemoryDBStorageTestCase(storagetest.AbstractStorageStorageTest):
    def db_factory(self):
        return implementations.MemoryDB()

class InMemoryDBTransactionsTestCase(storagetest.AbstractTransactionStorageTest):
    def db_factory(self):
        return implementations.MemoryDB()