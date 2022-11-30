"""
NEP-15 contract manifest classes for describing smart contract access control.
"""
from __future__ import annotations
import base64
import binascii
import orjson as json  # type: ignore
from typing import Callable, Optional, Any
from neo3.contracts import utils as contractutils, abi
from neo3.core import serialization, types, cryptography, utils as coreutils, interfaces
from neo3.core.serialization import BinaryReader, BinaryWriter


class ContractGroup(interfaces.IJson):
    """
    Describes a set of mutually trusted contracts.

    See Also:
        ContractManifest.
    """

    def __init__(self, public_key: cryptography.ECPoint, signature: bytes):
        self.public_key = public_key
        self.signature = signature

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self.public_key == other.public_key and self.signature == other.signature

    def is_valid(self, contract_hash: types.UInt160) -> bool:
        """
        Validate if the group has agreed on allowing the specific contract_hash.

        Args:
            contract_hash:
        """
        return cryptography.verify_signature(
            contract_hash.to_array(),
            self.signature,
            self.public_key.encode_point(False),
            cryptography.ECCCurve.SECP256R1,
        )

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        json = {
            "pubkey": str(self.public_key),
            "signature": base64.b64encode(self.signature).decode(),
        }
        return json

    @classmethod
    def from_json(cls, json: dict) -> ContractGroup:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary keys.
            ValueError: if the signature length is not 64.
        """
        pubkey = contractutils.validate_type(json["pubkey"], str)
        c = cls(
            public_key=cryptography.ECPoint.deserialize_from_bytes(
                binascii.unhexlify(pubkey)
            ),
            signature=base64.b64decode(
                contractutils.validate_type(json["signature"], str).encode("utf8")
            ),
        )
        if len(c.signature) != 64:
            raise ValueError("Format error - invalid signature length")
        return c


class ContractPermission(interfaces.IJson):
    """
    Describes a single set of outgoing call restrictions for a `System.Contract.Call` SYSCALL.
    It describes what other smart contracts the executing contract is allowed to call and what exact methods on the
    other contract are allowed to be called. This is enforced during runtime.

    Example:
        Contract A (the executing contract) wants to call method `x` on Contract B. The runtime will query the manifest
        of Contract A and ask if this is allowed. The Manifest will search through its permissions (a list of
        ContractPermission objects) and ask if it `is_allowed()`.
    """

    def __init__(
        self,
        contract: ContractPermissionDescriptor,
        methods: WildcardContainer,
    ):
        self.contract = contract
        self.methods = methods

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self.contract == other.contract and self.methods == other.methods

    @classmethod
    def default_permissions(cls) -> ContractPermission:
        """
        Construct a ContractPermission which allows any contract and any method to be called.
        """
        return cls(
            ContractPermissionDescriptor(),  # with no parameters equals to Wildcard
            WildcardContainer.create_wildcard(),
        )

    def is_allowed(
        self,
        target_contract_hash: types.UInt160,
        target_manifest: ContractManifest,
        target_method: str,
    ) -> bool:
        """
        Return if it is allowed to call `target_method` on the target contract.

        Args:
            target_contract_hash: the contract hash of the contract to be called.
            target_manifest: the contract manifest of the contract to be called.
            target_method: the method of the contract to be called.
        """
        if self.contract.is_hash:
            if not self.contract.contract_hash == target_contract_hash:
                return False
        elif self.contract.is_group:
            results = list(
                map(
                    lambda p: p.public_key != self.contract.group,
                    target_manifest.groups,
                )
            )
            if all(results):
                return False
        return self.methods.is_wildcard or target_method in self.methods

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        json = self.contract.to_json()
        # because NEO C# returns a string from "method" instead of sticking to a standard interface
        json.update({"methods": self.methods.to_json()["wildcard"]})
        return json

    @classmethod
    def from_json(cls, json: dict) -> ContractPermission:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary keys.
            ValueError: if a method is zero length.
        """
        cpd = ContractPermissionDescriptor.from_json(json)
        json_wildcard = {"wildcard": json["methods"]}
        methods = WildcardContainer.from_json(json_wildcard)
        for m in methods:
            if len(m) == 0:
                raise ValueError("Format error - methods cannot have length 0")
        return cls(cpd, methods)


class WildcardContainer(interfaces.IJson):
    """
    An internal helper class for ContractManifest attributes.
    """

    def __init__(self, data: Optional[list] = None):
        self._is_wildcard = False
        self._data = data if data else []

    def __contains__(self, item):
        return item in self._data

    def __getitem__(self, index):
        return self._data[index]

    def __len__(self):
        return len(self._data)

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return self._data == other._data

    @classmethod
    def create_wildcard(cls) -> WildcardContainer:
        """
        Creates an instance that indicates any value is allowed.
        """
        instance = cls()
        instance._is_wildcard = True
        return instance

    @property
    def is_wildcard(self) -> bool:
        """
        Indicates if the container is configured to allow all values.
        """
        return self._is_wildcard

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        if self.is_wildcard:
            return {"wildcard": "*"}
        return {"wildcard": list(map(lambda d: str(d), self._data))}

    @classmethod
    def from_json(cls, json: dict):
        """
        Parse object out of JSON data.

        Note: if the value is not '*', and is a Python list, then it will assume
        that the list members are strings or convertible via str().

        If the wildcard should contain other data types, use the alternative `from_json_as_type()` method.

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary key.
            ValueError: if the data supplied cannot recreate a valid object.
        """
        value = json.get("wildcard", None)
        if value is None:
            raise ValueError(f"Invalid JSON - Cannot recreate wildcard from None")
        if value == "*":
            return WildcardContainer.create_wildcard()
        if isinstance(value, list):
            return WildcardContainer(data=list(map(lambda d: str(d), value)))
        raise ValueError(
            f"Invalid JSON - Cannot deduce WildcardContainer type from: {value}"
        )

    @classmethod
    def from_json_as_type(cls, json: dict, conversion_func: Callable):
        """
            Parse object out of JSON data.

            Note: if the value is not '*', and is a Python list, then it will use `conversion_func` to
            parse the members into the expected types.

        Args:
            json: a dictionary.
            conversion_func: a callable that takes 1 argument, which is the element in the value list.

            Example with UInt160:
                {'wildcard': ['0xa400ff00ff00ff00ff00ff00ff00ff00ff00ff01', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']}

                 the first call has as argument '0xa400ff00ff00ff00ff00ff00ff00ff00ff00ff01'.
                 to process this example call
                 WildcardContainer.from_json_as_type(json_data, lambda f: types.UInt160.from_string(f))

        Raises:
            KeyError: if the data supplied does not contain the necessary key.
            ValueError: if the data supplied cannot recreate a valid object.
        """
        value = json.get("wildcard", None)
        if value is None:
            raise ValueError(f"Invalid JSON - Cannot recreate wildcard from None")
        if value == "*":
            return WildcardContainer.create_wildcard()
        if isinstance(value, list):
            return WildcardContainer(
                data=list(map(lambda d: conversion_func(d), value))
            )
        raise ValueError(
            f"Invalid JSON - Cannot deduce WildcardContainer type from: {value}"
        )


class ContractPermissionDescriptor(interfaces.IJson):
    """
    A restriction object that limits the smart contract's calling abilities. Enforced at runtime.

    See Also: ContractManifest.
    """

    def __init__(
        self,
        contract_hash: Optional[types.UInt160] = None,
        group: Optional[cryptography.ECPoint] = None,
    ):
        """
        Create a contract hash or group based restriction. Mutually exclusive.
        Supply no arguments to create a wildcard permission descriptor.

        Raises:
            ValueError: if both contract hash and group arguments are supplied.
        """
        if contract_hash is not None and group is not None:
            raise ValueError("Maximum 1 argument can be supplied")
        self.contract_hash = contract_hash
        self.group = group

    def __eq__(self, other):
        return self.contract_hash == other.contract_hash and self.group == other.group

    @property
    def is_hash(self) -> bool:
        """
        Indicates if the permission is limited to a specific contract hash.
        """
        return self.contract_hash is not None

    @property
    def is_group(self) -> bool:
        """
        Indicates if the permission is limited to a specific group.
        """
        return self.group is not None

    @property
    def is_wildcard(self) -> bool:
        """
        Indicates if the permission is not limited to a specific contract or a specific group.
        """
        return not self.is_hash and not self.is_group

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        # NEO C# deviates here. They return a string
        if self.contract_hash:
            val = "0x" + str(self.contract_hash)
        elif self.group:
            val = str(self.group)
        else:
            val = "*"
        return {"contract": val}

    @classmethod
    def from_json(cls, json: dict) -> ContractPermissionDescriptor:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary key.
            ValueError: if the data supplied cannot recreate a valid object.
        """
        # catches both missing key and None as value
        value = json.get("contract", None)
        if value is None:
            raise ValueError(f"Invalid JSON - Cannot deduce permission type from None")

        if len(value) == 42:
            return cls(contract_hash=types.UInt160.from_string(value[2:]))
        if len(value) == 66:
            ecpoint = cryptography.ECPoint.deserialize_from_bytes(
                binascii.unhexlify(value)
            )
            return cls(group=ecpoint)
        if value == "*":
            return cls()  # no args == wildcard
        raise ValueError(f"Invalid JSON - Cannot deduce permission type from: {value}")

    def to_array(self) -> bytes:
        """Serialize the object."""
        if self.is_hash:
            return self.contract_hash.to_array()  # type: ignore
        if self.is_group:
            return self.group.to_array()  # type: ignore
        # wildcard
        return b""


class ContractManifest(serialization.ISerializable, interfaces.IJson):
    """
    A description of a smart contract's abilities (callable methods & events) as well as a set of restrictions
    describing what external contracts and methods are allowed to be called.

    For more information see:
    https://github.com/neo-project/proposals/blob/3e492ad05d9de97abb6524fb9a73714e2cdc5461/nep-15.mediawiki
    """

    #: The maximum byte size after serialization to be considered valid a valid contract.
    MAX_LENGTH = 0xFFFF

    def __init__(self, name: Optional[str] = None):
        #: Contract name
        self.name: str = name if name else ""
        #: A group represents a set of mutually trusted contracts. A contract will trust and allow any contract in the
        #: same group to invoke it.
        self.groups: list[ContractGroup] = []

        #: The list of NEP standards supported e.g. "NEP-3"
        self.supported_standards: list[str] = []

        #: For technical details of ABI, please refer to NEP-14: NeoContract ABI.
        #: https://github.com/neo-project/proposals/blob/d1f4e9e1a67d22a5755c45595121f80b0971ea64/nep-14.mediawiki
        self.abi: abi.ContractABI = abi.ContractABI(events=[], methods=[])

        #: Permissions describe what external contract(s) and what method(s) on these are allowed to be invoked.
        self.permissions: list[ContractPermission] = [
            ContractPermission.default_permissions()
        ]

        # Update trusts/safe_methods with outcome of https://github.com/neo-project/neo/issues/1664
        # Unfortunately we have to add this nonsense logic or we get deviating VM results.
        self.trusts = WildcardContainer()  # for UInt160 types

        #: Optional user defined data
        self.extra: Optional[dict] = None

    def __len__(self):
        return coreutils.get_var_size(str(self.to_json()).replace(" ", ""))

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return (
            self.name == other.name
            and self.groups == other.groups
            and self.abi == other.abi
            and self.permissions == other.permissions
            and self.trusts == other.trusts
            and self.extra == other.extra
        )

    def __str__(self):
        return json.dumps(self.to_json()).decode()

    def serialize(self, writer: BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_var_string(str(self))

    def deserialize(self, reader: BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self._deserialize_from_json(json.loads(reader.read_var_string(self.MAX_LENGTH)))

    def _deserialize_from_json(self, json: dict) -> None:
        if json["name"] is None:
            self.name = ""
        else:
            self.name = contractutils.validate_type(json["name"], str)
        self.abi = abi.ContractABI.from_json(json["abi"])
        self.groups = list(map(lambda g: ContractGroup.from_json(g), json["groups"]))

        if len(json["features"]) != 0:
            raise ValueError(
                "Manifest features is reserved and cannot have any content at this time"
            )

        self.supported_standards = list(
            map(
                lambda ss: contractutils.validate_type(ss, str),
                json["supportedstandards"],
            )
        )
        self.permissions = list(
            map(lambda p: ContractPermission.from_json(p), json["permissions"])
        )

        if json["trusts"] == "*":
            self.trusts = WildcardContainer.create_wildcard()
        else:
            self.trusts = WildcardContainer.from_json_as_type(
                {"wildcard": json["trusts"]},
                lambda t: ContractPermissionDescriptor.from_json({"contract": t}),
            )

        # converting json key/value back to default WildcardContainer format
        self.extra = json["extra"]

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        if self.trusts.is_wildcard:
            trusts = "*"
        else:
            trusts = list(map(lambda m: m.to_json()["contract"], self.trusts))  # type: ignore
        json: dict[str, Any] = {
            "name": self.name if self.name else None,
            "groups": list(map(lambda g: g.to_json(), self.groups)),
            "features": {},
            "supportedstandards": self.supported_standards,
            "abi": self.abi.to_json(),
            "permissions": list(map(lambda p: p.to_json(), self.permissions)),
            "trusts": trusts,
            "extra": self.extra,
        }
        return json

    @classmethod
    def from_json(cls, json: dict):
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raise:
            KeyError: if the data supplied does not contain the necessary keys.
            ValueError: if the manifest name property has an incorrect format.
            ValueError: if the manifest support standards contains an string.
        """
        manifest = cls()
        manifest._deserialize_from_json(json)
        if manifest.name is None or len(manifest.name) == 0:
            raise ValueError("Format error - invalid 'name'")
        for s in manifest.supported_standards:
            if len(s) == 0:
                raise ValueError(
                    "Format error - supported standards cannot be zero length"
                )
        return manifest

    def is_valid(self, contract_hash: types.UInt160) -> bool:
        """
        Validates the if any of the manifest groups signed the requesting `contract_hash` as permissive.

        An example use-case is to allow creation and updating of smart contracts by a select group.

        Args:
            contract_hash: target contract hash.
        """
        result = list(map(lambda g: g.is_valid(contract_hash), self.groups))
        return all(result)

    def can_call(
        self,
        target_contract_hash: types.UInt160,
        target_manifest: ContractManifest,
        target_method: str,
    ) -> bool:
        """
        Check if this contract is allowed to call `target_method` on `target_contract`.
        """
        results = list(
            map(
                lambda p: p.is_allowed(
                    target_contract_hash, target_manifest, target_method
                ),
                self.permissions,
            )
        )
        return any(results)

    def contains_group(self, public_key: cryptography.ECPoint) -> bool:
        """
        Check if group exists.

        Args:
            public_key: needle to search for.

        Returns:
            `True` if found. `False` otherwise.
        """
        for g in self.groups:
            if public_key == g.public_key:
                return True
        return False

    @classmethod
    def from_file(cls, path: str):
        """
        Create object from a file.

        Args:
            path: location of the file.

        Raises:
            FileNotFoundError: if the path is invalid.
            ValueError: if the file is not a valid ContractManifest.
        """
        with open(path, "rb") as f:
            manifest_bytes = f.read()
            manifest_json = json.loads(manifest_bytes.decode("utf-8"))
            try:
                return cls.from_json(manifest_json)
            except ValueError as e:
                raise ValueError(f"Failed manifest validation with: {e}")

    @classmethod
    def _serializable_init(cls):
        return cls()
