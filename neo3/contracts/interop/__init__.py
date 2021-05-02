from __future__ import annotations
from .service import InteropService, InteropDescriptor
# having the decorator out of the __init__ ensures we can use it in the modules below on import
# otherwise we get a circular import issue
from .decorator import register
# the __name__ imports are just to trigger module loading,
# which in turn executes the decorators to register the SYSCALLS
from .contract import __name__
from .crypto import __name__
from .enumerator import IIterator, StorageIterator
from .runtime import __name__
from .storage import storage_put, MAX_STORAGE_VALUE_SIZE, MAX_STORAGE_KEY_SIZE
