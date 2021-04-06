from __future__ import annotations
import hashlib
import abc
import struct
from enum import Enum
from typing import List, Optional, Type, TypeVar
from neo3.core import Size as s, serialization, utils, types, IInteroperable, IJson
from neo3.network import payloads
from neo3.vm import VMState
from neo3 import settings, vm, storage, contracts


class TransactionAttributeType(Enum):
    HIGH_PRIORITY = 0x1
    ORACLE_RESPONSE = 0x11


TransactionAttribute_T = TypeVar('TransactionAttribute_T', bound='TransactionAttribute')


class TransactionAttribute(serialization.ISerializable, IJson):
    """
    Attributes that can be attached to a Transaction.
    """
    def __init__(self):
        self.type_: TransactionAttributeType = None
        self.allow_multiple = False

    def __len__(self):
        return s.uint8

    def __eq__(self, other):
        if other is None:
            return False
        if type(self) != type(other):
            return False
        return True

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_uint8(self.type_.value)
        self._serialize_without_type(writer)

    @abc.abstractmethod
    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        """ Serialize the remaining attributes"""

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        if reader.read_uint8() != self.type_.value:
            raise ValueError("Deserialization error - transaction attribute type mismatch")
        self._deserialize_without_type(reader)

    @staticmethod
    def deserialize_from(reader: serialization.BinaryReader) -> TransactionAttribute:
        """
        Deserialize from a binary stream into a new TransactionAttribute
        """
        attribute_type = reader.read_uint8()
        for sub in TransactionAttribute.__subclasses__():
            child = sub._serializable_init()  # type: ignore
            if child.type_.value == attribute_type:
                child._deserialize_without_type(reader)
                return child
        else:
            raise ValueError("Deserialization error - unknown transaction attribute type")

    @abc.abstractmethod
    def _deserialize_without_type(self, reader: serialization.BinaryReader) -> None:
        """ Deserialize the remaining attributes """

    def verify(self, snapshot: storage.Snapshot, tx: Transaction) -> bool:
        return True

    def to_json(self) -> dict:
        return {"type": self.type_}

    @classmethod
    def from_json(cls, json: dict):
        c = cls()
        c.type_ = TransactionAttributeType(json["type"])


class HighPriorityAttribute(TransactionAttribute):
    def __init__(self):
        super(HighPriorityAttribute, self).__init__()
        self.type_ = TransactionAttributeType.HIGH_PRIORITY

    def verify(self, snapshot: storage.Snapshot, tx: Transaction) -> bool:
        committee = contracts.NeoToken().get_committee_address(snapshot)
        for signer in tx.signers:
            if signer.account == committee:
                return True
        return False

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        pass

    def _deserialize_without_type(self, reader: serialization.BinaryReader) -> None:
        pass


class Transaction(payloads.IInventory, IInteroperable):
    """
    Data to be executed by the NEO virtual machine.
    """
    #: the maximum number of bytes a single transaction may consists of
    MAX_TRANSACTION_SIZE = 102400
    #: the maximum time a transaction will be valid from height of creation plus this value. Default is 24h
    MAX_VALID_UNTIL_BLOCK_INCREMENT = 5760
    #: the maximum number of transaction attributes for a single transaction
    MAX_TRANSACTION_ATTRIBUTES = 16

    def __init__(self,
                 version: int,
                 nonce: int,
                 system_fee: int,
                 network_fee: int,
                 valid_until_block: int,
                 attributes: List[TransactionAttribute] = None,
                 signers: List[payloads.Signer] = None,
                 script: bytes = None,
                 witnesses: List[payloads.Witness] = None,
                 protocol_magic: int = None):
        self.version = version
        self.nonce = nonce
        self.system_fee = system_fee
        self.network_fee = network_fee
        self.valid_until_block = valid_until_block
        self.attributes = attributes if attributes else []
        #: A list of authorities used by the :func:`ChecKWitness` smart contract system call.
        self.signers = signers if signers else []
        self.script = script if script else b''
        #: A list of signing authorities used to validate the transaction.
        self.witnesses = witnesses if witnesses else []

        # unofficial attributes
        self.vm_state = VMState.NONE
        self.block_height = 0
        #: The network protocol magic number to use in the Transaction hash function. Defaults to 0x4F454E
        #: Warning: changing this will change the TX hash which can result in dangling transactions in the database as
        #: deletion and duplication checking will fail.
        if protocol_magic:
            self.protocol_magic = protocol_magic
        elif settings.network.magic is not None:
            self.protocol_magic = settings.network.magic
        else:
            self.protocol_magic = 0x4F454E

    def __len__(self):
        return (s.uint8 + s.uint32 + s.uint64 + s.uint64 + s.uint32
                + utils.get_var_size(self.attributes)
                + utils.get_var_size(self.signers)
                + utils.get_var_size(self.script)
                + utils.get_var_size(self.witnesses))

    def __eq__(self, other):
        if other is None:
            return False
        if type(self) != type(other):
            return False
        if self.hash() != other.hash():
            return False
        return True

    def __hash__(self):
        # the TX hash() is a UInt256, we need to return an int
        # so we call hash() on the UInt256
        return hash(self.hash())

    def __deepcopy__(self, memodict={}):
        # not the best, but faster than letting deepcopy() do introspection
        with serialization.BinaryWriter() as bw:
            self.serialize_special(bw)
            with serialization.BinaryReader(bw.to_array()) as br:
                tx = Transaction._serializable_init()
                tx.deserialize_special(br)
                return tx

    def hash(self) -> types.UInt256:
        """
        Get a unique block identifier based on the unsigned data portion of the object.
        """
        with serialization.BinaryWriter() as bw:
            bw.write_uint32(self.protocol_magic)
            self.serialize_unsigned(bw)
            data_to_hash = bytearray(bw._stream.getvalue())
            data = hashlib.sha256(hashlib.sha256(data_to_hash).digest()).digest()
            return types.UInt256(data=data)

    @property
    def sender(self) -> types.UInt160:
        return self.signers[0].account if len(self.signers) > 0 else types.UInt160.zero()

    @property
    def inventory_type(self) -> payloads.InventoryType:
        """
        Inventory type identifier.
        """
        return payloads.InventoryType.TX

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        self.serialize_unsigned(writer)
        writer.write_serializable_list(self.witnesses)

    def serialize_unsigned(self, writer: serialization.BinaryWriter) -> None:
        writer.write_uint8(self.version)
        writer.write_uint32(self.nonce)
        writer.write_int64(self.system_fee)
        writer.write_int64(self.network_fee)
        writer.write_uint32(self.valid_until_block)
        writer.write_serializable_list(self.signers)
        writer.write_serializable_list(self.attributes)
        writer.write_var_bytes(self.script)

    def serialize_special(self, writer: serialization.BinaryWriter) -> None:
        self.serialize(writer)
        writer.write_uint8(int(self.vm_state))
        writer.write_uint32(self.block_height)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.deserialize_unsigned(reader)
        self.witnesses = reader.read_serializable_list(payloads.Witness)

    def deserialize_unsigned(self, reader: serialization.BinaryReader) -> None:
        (self.version,
         self.nonce,
         self.system_fee,
         self.network_fee,
         self.valid_until_block) = struct.unpack("<BIqqI", reader._stream.read(25))
        if self.version > 0:
            raise ValueError("Deserialization error - invalid version")
        if self.system_fee < 0:
            raise ValueError("Deserialization error - negative system fee")
        if self.network_fee < 0:
            raise ValueError("Deserialization error - negative network fee")

        self.signers = Transaction._deserialize_signers(reader, self.MAX_TRANSACTION_ATTRIBUTES)
        self.attributes = Transaction._deserialize_attributes(reader,
                                                              self.MAX_TRANSACTION_ATTRIBUTES - len(self.signers))
        self.script = reader.read_var_bytes(max=65535)
        if len(self.script) == 0:
            raise ValueError("Deserialization error - invalid script length 0")

    def deserialize_special(self, reader: serialization.BinaryReader) -> None:
        self.deserialize(reader)
        self.vm_state = VMState(reader.read_uint8())
        self.block_height = reader.read_uint32()

    def fee_per_byte(self) -> int:
        """
        Calculates the network fee per byte.

        Fee per byte = the TX's networkfee / TX's size

        Warning:
            Should only be called once the transaction is completely build and will no longer be modified.
        """
        return self.network_fee // len(self)

    def from_replica(self, replica) -> None:
        """
        Shallow copy attributes from a reference object.
        """
        self.version = replica.version
        self.nonce = replica.nonce
        self.system_fee = replica.system_fee
        self.network_fee = replica.network_fee
        self.valid_until_block = replica.valid_until_block
        self.attributes = replica.attributes
        self.signers = replica.signers
        self.script = replica.script
        self.witnesses = replica.witnesses
        self.block_height = replica.block_height
        self.vm_state = replica.vm_state

    def to_stack_item(self, reference_counter: vm.ReferenceCounter) -> vm.StackItem:
        """
        Convert self to a VM stack item.

        Args:
            reference_counter: ExecutionEngine reference counter
        """
        array = vm.ArrayStackItem(reference_counter)
        tx_hash = vm.ByteStringStackItem(self.hash().to_array())
        version = vm.IntegerStackItem(self.version)
        nonce = vm.IntegerStackItem(self.nonce)
        sender = vm.ByteStringStackItem(self.sender.to_array())
        system_fee = vm.IntegerStackItem(self.system_fee)
        network_fee = vm.IntegerStackItem(self.network_fee)
        valid_until = vm.IntegerStackItem(self.valid_until_block)
        script = vm.ByteStringStackItem(self.script)
        array.append([tx_hash, version, nonce, sender, system_fee, network_fee, valid_until, script])
        return array

    def get_script_hashes_for_verifying(self, _: storage.Snapshot) -> List[types.UInt160]:
        return list(map(lambda signer: signer.account, self.signers))

    def try_get_attribute(self, needle: Type[TransactionAttribute_T]) -> \
            Optional[TransactionAttribute_T]:
        for attr in self.attributes:
            if isinstance(attr, needle):
                return attr
        else:
            return None

    # TODO: implement Verify methods once we have Snapshot support

    @staticmethod
    def _deserialize_signers(reader: serialization.BinaryReader, max_count: int) -> List[payloads.Signer]:
        count = reader.read_var_int(max_count)
        if count == 0:
            raise ValueError("Deserialization error - signers can't be empty")

        values: List[payloads.Signer] = []
        for i in range(0, count):
            signer = reader.read_serializable(payloads.Signer)
            if signer in values:
                raise ValueError("Deserialization error - duplicate signer")
            values.append(signer)

        return values

    @staticmethod
    def _deserialize_attributes(reader: serialization.BinaryReader, max_count: int) -> List[TransactionAttribute]:
        count = reader.read_var_int(max_count)
        values: List[TransactionAttribute] = []

        for _ in range(0, count):
            attribute = TransactionAttribute.deserialize_from(reader)
            if not attribute.allow_multiple and attribute in values:
                raise ValueError("Deserialization error - duplicate transaction attribute")
            values.append(attribute)
        return values

    @classmethod
    def _serializable_init(cls):
        return cls(0, 0, 0, 0, 99999)
