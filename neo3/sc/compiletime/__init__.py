from typing import Optional
from neo3.sc.types import UInt160, CallFlags


class Permission:
    """
    Describes one outgoing call permission entry for the contract manifest.

    Examples::

        Permission()                          # allow any contract, any method
        Permission(contract="*", methods="*") # same as above, explicit
        Permission(
            contract="0xd2a4cff31913016155e38e474a2c06d08be276cf",
            methods=["transfer", "balanceOf"],
        )
    """

    def __init__(self, contract: str = "*", methods: "str | list[str]" = "*"):
        """
        Args:
            contract: target contract. Use ``"*"`` to allow calls to any
                contract, ``"0x<40 hex chars>"`` to restrict to a specific
                contract hash, or a 66-character hex-encoded ECPoint to
                restrict to a group.
            methods: allowed methods. Use ``"*"`` to allow any method, or
                pass a list of method name strings to restrict to specific
                methods.
        """
        self.contract = contract
        self.methods = methods


class Group:
    """
    Declares membership in a mutually trusted contract group.

    Example::

        Group(
            pubkey="02c0b60c995bc092e866f15a37c176bb59b7ebacf069ba94c38654a316479b7af4",
            signature="QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==",
        )
    """

    def __init__(self, pubkey: str, signature: str):
        """
        Args:
            pubkey: hex-encoded compressed ECPoint (66 hex chars) of the group
                member's public key.
            signature: base64-encoded secp256r1 signature over the contract
                hash, produced by the group member's private key.
        """
        self.pubkey = pubkey
        self.signature = signature


class ContractManifest:
    """
    Declare contract manifest fields at module scope.

    The compiler extracts the keyword arguments and writes them to the
    .manifest.json output.  Place exactly one call to this class at the top
    level of your contract source file.

    Example::

        from neo3.sc.compiletime import ContractManifest, Permission

        ContractManifest(
            name="MyToken",
            supported_standards=["NEP-17"],
            permissions=[Permission(contract="*", methods="*")],
            trusts=["*"],
            extra={"Author": "Alice"},
        )
    """

    def __init__(
        self,
        name: str = "",
        groups: Optional[list[Group]] = None,
        supported_standards: Optional[list[str]] = None,
        permissions: Optional[list[Permission]] = None,
        trusts: Optional[list[str]] = None,
        extra: Optional[dict] = None,
    ):
        """
        Args:
            name: contract name. Defaults to the output file name when omitted.
            groups: list of ``Group`` entries declaring group membership.
            supported_standards: list of NEP standard identifiers the contract implements, e.g. ``["NEP-17"]``.
            permissions: list of ``Permission`` entries controlling which external contracts and methods this contract may call. Defaults to allow-all when omitted.
            trusts: which contracts or groups are trusted to call this contract.  Pass ``["*"]`` to trust all, or a list of contract hash / ECPoint hex strings to trust specific callers.
            extra: arbitrary JSON-serialisable dict written verbatim to the ``extra`` manifest field, e.g. ``{"Author": "Alice", "Version": "1.0"}``.
        """
        self.name = name
        self.groups = groups or []
        self.supported_standards = supported_standards or []
        self.permissions = permissions or []
        self.trusts = trusts or []
        self.extra = extra


def syscall(name: str):
    """
    Marks a function as a direct NeoVM syscall wrapper.

    The compiler will emit a SYSCALL opcode with the interop hash of ``name`` instead of compiling the function body. The body must be ``pass``.

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
        safe: if True, the function is restricted to read-only operations and must not modify blockchain state (e.g. no storage writes). Defaults to False.

    Examples:
    >>> @public
    ... def callable_function() -> bool:
    ...     return True
    {
        "name": "callable_function",
        "offset": 0,
        "parameters": [],
        "safe": false,
        "returntype": "Boolean"
    }

    >>> @public(name='callableFunction')
    ... def callable_function() -> bool:
    ...     return True
    {
        "name": "callableFunction",
        "offset": 0,
        "parameters": [],
        "safe": false,
        "returntype": "Boolean"
    }

    >>> @public(safe=True)
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
        script_hash: the contract unique identifier e.g. 0xd2a4cff31913016155e38e474a2c06d08be276cf
    """

    def decorator_wrapper(cls, *args, **kwargs):
        cls.hash = UInt160.from_string(script_hash)
        return cls

    return decorator_wrapper


def display_name(name: str):
    """
    This decorator allows you to override the name of the entry point on the called contract. It only works in contract interface classes.

    Args:
        name: the entry point identifier from the called contract manifest.

    >>> @contract('0xd2a4cff31913016155e38e474a2c06d08be276cf')
    ... class GASInterface:
    ...     @staticmethod
    ...     @display_name('totalSupply')
    ...     def total_supply() -> int:      # the smart contract will call "totalSupply"
    ...         pass
    ... @public
    ... def main() -> int:
    ...     return GASInterface.total_supply()
    """

    def decorator_wrapper(*args, **kwargs):
        pass

    return decorator_wrapper


def call_flags(flags: CallFlags):
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

    Args:
        flags: the ``CallFlags`` value to use for the SYSCALL.
    """

    def decorator_wrapper(*args, **kwargs):
        pass

    return decorator_wrapper


def event(name: str, *, rename: list[tuple[str, str]] = None):
    """
    A decorator to emit a notification.

    Args:
        name: the name the event will have in the application logs when emitted
        rename: allow you to rename how parameters show in the manifest. This can be used to overcome reserved keywords issues such as `from`.
    """

    def decorator_wrapper(*args, **kwargs):
        pass

    return decorator_wrapper
