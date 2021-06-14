from __future__ import annotations
import base64
import binascii
import orjson as json  # type: ignore
from typing import List, Callable, Optional, Dict, Any
from neo3 import contracts, vm
from neo3.core import serialization, types, IJson, cryptography, utils
from neo3.core.serialization import BinaryReader, BinaryWriter


class ContractGroup(IJson):
    """
    Describes a set of mutually trusted contracts.

    See Also: ContractManifest.
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
        return cryptography.verify_signature(contract_hash.to_array(),
                                             self.signature,
                                             self.public_key.encode_point(False),
                                             cryptography.ECCCurve.SECP256R1)

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        json = {
            'pubkey': str(self.public_key),
            'signature': base64.b64encode(self.signature).decode()
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
        pubkey = contracts.validate_type(json['pubkey'], str)
        c = cls(
            public_key=cryptography.ECPoint.deserialize_from_bytes(binascii.unhexlify(pubkey)),
            signature=base64.b64decode(contracts.validate_type(json['signature'], str).encode('utf8'))
        )
        if len(c.signature) != 64:
            raise ValueError("Format error - invalid signature length")
        return c

    def to_stack_item(self, reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        struct = vm.StructStackItem(reference_counter)
        struct.append(vm.ByteStringStackItem(self.public_key.to_array()))
        struct.append(vm.ByteStringStackItem(self.signature))
        return struct


class ContractPermission(IJson):
    """
    Describes a single set of outgoing call restrictions for a 'System.Contract.Call' SYSCALL.
    It describes what other smart contracts the executing contract is allowed to call and what exact methods on the
    other contract are allowed to be called. This is enforced during runtime.

    Example:
        Contract A (the executing contract) wants to call method "x" on Contract B. The runtime will query the manifest
        of Contract A and ask if this is allowed. The Manifest will search through its permissions (a list of
        ContractPermission objects) and ask if it "is_allowed(target_contract, target_method)".
    """
    def __init__(self, contract: contracts.ContractPermissionDescriptor, methods: WildcardContainer):
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
        return cls(contracts.ContractPermissionDescriptor(),  # with no parameters equals to Wildcard
                   WildcardContainer.create_wildcard())

    def is_allowed(self, target_contract: contracts.ContractState, target_method: str) -> bool:
        """
        Return if it is allowed to call `target_method` on the target contract.

        Args:
            target_contract: the contract state of the contract to be called.
            target_method: the method of the contract to be called.
        """
        if self.contract.is_hash:
            if not self.contract.contract_hash == target_contract.hash:
                return False
        elif self.contract.is_group:
            results = list(map(lambda p: p.public_key != self.contract.group, target_contract.manifest.groups))
            if all(results):
                return False
        return self.methods.is_wildcard or target_method in self.methods

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        json = self.contract.to_json()
        # because NEO C# returns a string from "method" instead of sticking to a standard interface
        json.update({'methods': self.methods.to_json()['wildcard']})
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
        cpd = contracts.ContractPermissionDescriptor.from_json(json)
        json_wildcard = {'wildcard': json['methods']}
        methods = WildcardContainer.from_json(json_wildcard)
        for m in methods:
            if len(m) == 0:
                raise ValueError("Format error - methods cannot have length 0")
        return cls(cpd, methods)

    def to_stack_item(self, reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        struct = vm.StructStackItem(reference_counter)
        if self.contract.is_wildcard:
            struct.append(vm.NullStackItem())
        elif self.contract.is_hash:
            struct.append(vm.ByteStringStackItem(self.contract.contract_hash.to_array()))  # type: ignore
        else:
            struct.append(vm.ByteStringStackItem(self.contract.group.to_array()))  # type: ignore

        if self.methods.is_wildcard:
            struct.append(vm.NullStackItem())
        else:
            struct.append(
                vm.ArrayStackItem(reference_counter,
                                  list(map(lambda m: vm.ByteStringStackItem(m), self.methods)))  # type: ignore
            )
        return struct


class WildcardContainer(IJson):
    """
    An internal helper class for ContractManifest attributes.
    """
    def __init__(self, data: list = None):
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
            return {'wildcard': '*'}
        return {'wildcard': list(map(lambda d: str(d), self._data))}

    @classmethod
    def from_json(cls, json: dict):
        """
        Parse object out of JSON data.

        Note: if the value is not '*', and is a Python list, then it will assume
        that the list members are strings or convertible via str().

        If the wildcard should contain other data types, use the alternative `from_json_as_type()` method

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary key.
            ValueError: if the data supplied cannot recreate a valid object.
        """
        value = json.get('wildcard', None)
        if value is None:
            raise ValueError(f"Invalid JSON - Cannot recreate wildcard from None")
        if value == '*':
            return WildcardContainer.create_wildcard()
        if isinstance(value, list):
            return WildcardContainer(data=list(map(lambda d: str(d), value)))
        raise ValueError(f"Invalid JSON - Cannot deduce WildcardContainer type from: {value}")

    @classmethod
    def from_json_as_type(cls, json: dict, conversion_func: Callable):
        """
            Parse object out of JSON data.

            Note: if the value is not '*', and is a Python list, then it will use `conversion_func` to
            parse the members into the expected types.

        Args:
            json: a dictionary.
            conversion_func: a callable that takes 1 argument, which is the element in the value list

            Example with UInt160:
                {'wildcard': ['0xa400ff00ff00ff00ff00ff00ff00ff00ff00ff01', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']}

                 the first call has as argument '0xa400ff00ff00ff00ff00ff00ff00ff00ff00ff01'.
                 to process this example call
                 WildcardContainer.from_json_as_type(json_data, lambda f: types.UInt160.from_string(f))

        Raises:
            KeyError: if the data supplied does not contain the necessary key.
            ValueError: if the data supplied cannot recreate a valid object.
        """
        value = json.get('wildcard', None)
        if value is None:
            raise ValueError(f"Invalid JSON - Cannot recreate wildcard from None")
        if value == '*':
            return WildcardContainer.create_wildcard()
        if isinstance(value, list):
            return WildcardContainer(data=list(map(lambda d: conversion_func(d), value)))
        raise ValueError(f"Invalid JSON - Cannot deduce WildcardContainer type from: {value}")


class ContractManifest(serialization.ISerializable, IJson):
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
        self.groups: List[ContractGroup] = []

        #: The list of NEP standards supported e.g. "NEP-3"
        self.supported_standards: List[str] = []

        #: For technical details of ABI, please refer to NEP-14: NeoContract ABI.
        #: https://github.com/neo-project/proposals/blob/d1f4e9e1a67d22a5755c45595121f80b0971ea64/nep-14.mediawiki
        self.abi: contracts.ContractABI = contracts.ContractABI(
            events=[],
            methods=[]
        )

        #: Permissions describe what external contract(s) and what method(s) on these are allowed to be invoked.
        self.permissions: List[contracts.ContractPermission] = [contracts.ContractPermission.default_permissions()]

        # Update trusts/safe_methods with outcome of https://github.com/neo-project/neo/issues/1664
        # Unfortunately we have to add this nonsense logic or we get deviating VM results.
        self.trusts = WildcardContainer()  # for UInt160 types

        #: Optional user defined data
        self.extra: Optional[Dict] = None

    def __len__(self):
        return utils.get_var_size(str(self.to_json()).replace(' ', ''))

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return False
        return (self.name == other.name
                and self.groups == other.groups
                and self.abi == other.abi
                and self.permissions == other.permissions
                and self.trusts == other.trusts
                and self.extra == other.extra)

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
        if json['name'] is None:
            self.name = ""
        else:
            self.name = contracts.validate_type(json['name'], str)
        self.abi = contracts.ContractABI.from_json(json['abi'])
        self.groups = list(map(lambda g: ContractGroup.from_json(g), json['groups']))

        if len(json['features']) != 0:
            raise ValueError("Manifest features is reserved and cannot have any content at this time")

        self.supported_standards = list(map(lambda ss: contracts.validate_type(ss, str), json['supportedstandards']))
        self.permissions = list(map(lambda p: ContractPermission.from_json(p), json['permissions']))

        if json['trusts'] == '*':
            self.trusts = WildcardContainer.create_wildcard()
        else:
            self.trusts = WildcardContainer.from_json_as_type(
                {'wildcard': json['trusts']},
                lambda t: contracts.ContractPermissionDescriptor.from_json({'contract': t}))

        # converting json key/value back to default WildcardContainer format
        self.extra = json['extra']

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        if self.trusts.is_wildcard:
            trusts = '*'
        else:
            trusts = list(map(lambda m: m.to_json()['contract'], self.trusts))  # type: ignore
        json: Dict[str, Any] = {
            "name": self.name if self.name else None,
            "groups": list(map(lambda g: g.to_json(), self.groups)),
            "features": {},
            "supportedstandards": self.supported_standards,
            "abi": self.abi.to_json(),
            "permissions": list(map(lambda p: p.to_json(), self.permissions)),
            "trusts": trusts,
            "extra": self.extra
        }
        return json

    def to_stack_item(self, reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        struct = vm.StructStackItem(reference_counter)
        struct.append(vm.ByteStringStackItem(self.name))
        struct.append(vm.ArrayStackItem(reference_counter,
                                        list(map(lambda g: g.to_stack_item(reference_counter), self.groups)))
                      )
        struct.append(vm.MapStackItem(reference_counter))
        struct.append(vm.ArrayStackItem(reference_counter,
                                        list(map(lambda s: vm.ByteStringStackItem(s), self.supported_standards)))
                      )
        struct.append(self.abi.to_stack_item(reference_counter))
        struct.append(vm.ArrayStackItem(reference_counter,
                                        list(map(lambda p: p.to_stack_item(reference_counter), self.permissions)))
                      )
        if self.trusts.is_wildcard:
            struct.append(vm.NullStackItem())
        else:
            struct.append(
                vm.ArrayStackItem(reference_counter,
                                  list(map(lambda t: vm.ByteStringStackItem(t.to_array()),
                                           self.trusts)))  # type: ignore
            )
        if self.extra is None:
            struct.append(vm.ByteStringStackItem("null"))
        else:
            struct.append(vm.ByteStringStackItem(json.dumps(self.extra)))
        return struct

    @classmethod
    def from_json(cls, json: dict):
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raise:
            KeyError: if the data supplied does not contain the necessary keys.
            ValueError: if the manifest name property has an incorrect format.
            ValueError: if the manifest support standards contains an string
        """
        manifest = cls()
        manifest._deserialize_from_json(json)
        if manifest.name is None or len(manifest.name) == 0:
            raise ValueError("Format error - invalid 'name'")
        for s in manifest.supported_standards:
            if len(s) == 0:
                raise ValueError("Format error - supported standards cannot be zero length")
        return manifest

    def is_valid(self, contract_hash: types.UInt160) -> bool:
        """
        Validates the if any in the manifest groups signed the requesting `contract_hash` as permissive.

        An example use-case is to allow creation and updating of smart contracts by a select group.

        Args:
            contract_hash:
        """
        result = list(map(lambda g: g.is_valid(contract_hash), self.groups))
        return all(result)

    def can_call(self, target_contract: contracts.ContractState, target_method: str) -> bool:
        results = list(map(lambda p: p.is_allowed(target_contract, target_method), self.permissions))
        return any(results)

    @classmethod
    def _serializable_init(cls):
        return cls()
