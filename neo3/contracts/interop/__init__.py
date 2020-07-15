from .service import InteropService
from .decorator import register
# having the decorator out of the __init__ ensures we can use it in the modules below on import
# otherwise we get a circular import issue
from .decorator import register
# the following imports are just to trigger module loading,
# which in turn executes the decorators to register the SYSCALLS
from .binary import __name__
from .blockchain import __name__
