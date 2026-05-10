from neo3.sc.types import UInt160


def syscall(name: str):
    """
    Marks a function as a direct NeoVM syscall wrapper.

    The compiler will emit a SYSCALL opcode with the interop hash of ``name``
    instead of compiling the function body.  The body must be ``pass``.

    Args:
        name: NeoVM interop method name, e.g. ``"System.Runtime.GetScriptContainer"``.
    """

    def decorator(func):
        return func

    return decorator


def public(name: str = None, safe: bool = False):
    """
    This decorator indicates that a method should be included as entry point in the abi file.

    Args:
        name: custom identifier to be used in the abi.
        safe: if True, the function is restricted to read-only operations and must not modify blockchain state (e.g., no storage writes). Defaults to False.

    Examples:
    >>> @public     # this method will be added to the abi
    ... def callable_function() -> bool:
    ...     return True
    {
        "name": "callable_function",
        "offset": 0,
        "parameters": [],
        "safe": false,
        "returntype": "Boolean"
    }

    >>> @public(name='callableFunction')     # the method will be added with the different name to the abi
    ... def callable_function() -> bool:
    ...     return True
    {
        "name": "callableFunction",
        "offset": 0,
        "parameters": [],
        "safe": false,
        "returntype": "Boolean"
    }

    >>> @public(safe=True)      # the method will be added with the safe flag to the abi
    ... def callable_function() -> bool:
    ...     return True
    {
        "name": "callable_function",
        "offset": 0,
        "parameters": [],
        "safe": true,
        "returntype": "Boolean"
    }
    """

    def decorator_wrapper(*args, **kwargs):
        pass

    return decorator_wrapper


def contract(script_hash: str):
    """
    This decorator identifies a class that should be interpreted as an interface to an existing contract.

    Args:
        script_hash: e.g. 0xd2a4cff31913016155e38e474a2c06d08be276cf

    Returns:

    """

    def decorator_wrapper(cls, *args, **kwargs):
        cls.hash = UInt160.from_string(script_hash)
        return cls

    return decorator_wrapper


def display_name(name: str):
    """
    This decorator identifies which methods from a contract interface should have a different identifier from the one
    interfacing it. It only works in contract interface classes.

    >>> @contract('0xd2a4cff31913016155e38e474a2c06d08be276cf')
    ... class GASInterface:
    ...     @staticmethod
    ...     @display_name('totalSupply')
    ...     def total_supply() -> int:      # the smart contract will call "totalSupply", but when writing the script you can call this method whatever you want to
    ...         pass
    ... @public
    ... def main() -> int:
    ...     return GASInterface.total_supply()

    :param name: Method identifier from the contract manifest.
    :type name: str
    """

    def decorator_wrapper(*args, **kwargs):
        pass

    return decorator_wrapper


def call_flags(flags: "CallFlags"):
    """
    Override the CallFlags used when calling this @contract method.

    By default every @contract method call uses ``CallFlags.ALL``.  Use this
    decorator to restrict the flags — for example ``CallFlags.READ_STATES``
    for read-only contract calls, which costs less gas.

    Must be applied to a ``@staticmethod`` inside a ``@contract`` class.

    >>> @contract('0xd2a4cff31913016155e38e474a2c06d08be276cf')
    ... class GASInterface:
    ...     @staticmethod
    ...     @call_flags(CallFlags.READ_STATES)
    ...     @display_name('totalSupply')
    ...     def total_supply() -> int:
    ...         pass

    :param flags: the ``CallFlags`` value (or int) to use for the SYSCALL.
    """

    def decorator_wrapper(*args, **kwargs):
        pass

    return decorator_wrapper


def event(name: str, *, rename: list[tuple[str, str]] = None):
    """
    A decorator to emit a notification.

    Args:
        name:
        rename:

    Returns:

    """

    def decorator_wrapper(*args, **kwargs):
        pass

    return decorator_wrapper
