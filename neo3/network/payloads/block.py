from __future__ import annotations
import hashlib
import struct
from typing import List
from neo3 import vm, storage, settings
from neo3.core import Size as s, serialization, types, utils, cryptography as crypto, IClonable, IInteroperable
from neo3.network import payloads
from bitarray import bitarray  # type: ignore
from copy import deepcopy
from .verification import IVerifiable


class Header(IVerifiable):
    """
    A Block header only object.

    Does not contain any consensus data or transactions.

    See also:
        :class:`~neo3.network.payloads.block.TrimmedBlock`
    """
    def __init__(self, version: int, prev_hash: types.UInt256, timestamp: int, index: int, primary_index: int,
                 next_consensus: types.UInt160, witness: payloads.Witness, merkle_root: types.UInt256 = None, *args,
                 **kwargs):
        super().__init__(*args, **kwargs)
        self.version = version
        self.prev_hash = prev_hash
        self.merkle_root = merkle_root if merkle_root else types.UInt256.zero()
        self.timestamp = timestamp
        self.index = index
        self.primary_index = primary_index
        self.next_consensus = next_consensus
        self.witness = witness

    def __len__(self):
        return s.uint32 + s.uint256 + s.uint256 + s.uint64 + s.uint32 + s.uint8 + s.uint160 + 1 + len(self.witness)

    def __eq__(self, other):
        if other is None:
            return False
        if type(self) != type(other):
            return False
        if self.hash() != other.hash():
            return False
        return True

    def hash(self) -> types.UInt256:
        """
        Get a unique identifier based on the unsigned data portion of the object.
        """
        with serialization.BinaryWriter() as bw:
            self.serialize_unsigned(bw)
            data_to_hash = bytearray(bw._stream.getvalue())
            data = hashlib.sha256(data_to_hash).digest()
            return types.UInt256(data=data)

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        self.serialize_unsigned(writer)
        writer.write_serializable_list([self.witness])

    def serialize_unsigned(self, writer: serialization.BinaryWriter) -> None:
        writer.write_uint32(self.version)
        writer.write_serializable(self.prev_hash)
        writer.write_serializable(self.merkle_root)
        writer.write_uint64(self.timestamp)
        writer.write_uint32(self.index)
        writer.write_uint8(self.primary_index)
        writer.write_serializable(self.next_consensus)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.

        Raises:
            ValueError: if the check byte does not equal.
        """
        self.deserialize_unsigned(reader)
        witnesses = reader.read_serializable_list(payloads.Witness, max=1)
        if len(witnesses) != 1:
            raise ValueError(f"Deserialization error - Witness object count is {len(witnesses)} must be 1")
        self.witness = witnesses[0]

    def deserialize_unsigned(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the unsigned data part of the object from a binary stream.

        Args:
            reader: instance.

        Raises:
            ValueError: if the primary_index field is greater than the configured consensus validator count.
        """
        (self.version,
         prev_hash,
         merkleroot,
         self.timestamp,
         self.index,
         self.primary_index,
         consensus) = struct.unpack("<I32s32sQIB20s", reader._stream.read(101))
        if self.primary_index >= len(settings.standby_validators):
            raise ValueError(f"Deserialization error - primary index {self.primary_index} exceeds validator count "
                             f"{len(settings.standby_validators)}")
        self.prev_hash = types.UInt256(prev_hash)
        self.merkle_root = types.UInt256(merkleroot)
        self.next_consensus = types.UInt160(consensus)

    def get_script_hashes_for_verifying(self, snapshot: storage.Snapshot) -> List[types.UInt160]:
        """
        Helper method to get the data used in verifying the object.
        """
        if self.prev_hash == types.UInt256.zero():
            return [self.witness.script_hash()]
        prev_block = snapshot.blocks.try_get(self.prev_hash, read_only=True)
        if prev_block is None:
            raise ValueError("Can't get next_consensus hash from previous block. Block does not exist")
        return [prev_block.next_consensus]

    @classmethod
    def _serializable_init(cls):
        return cls(0,
                   types.UInt256.zero(),
                   0,
                   0,
                   0,
                   types.UInt160.zero(),
                   payloads.Witness(b'', b''))


class Block(payloads.IInventory):
    """
    The famous Block. I transfer chain state.
    """

    def __init__(self,
                 header: Header,
                 transactions: List[payloads.Transaction] = None,
                 *args,
                 **kwargs
                 ):
        super(Block, self).__init__(*args, **kwargs)
        self.header = header
        self.transactions = [] if transactions is None else transactions

    def __len__(self):
        # calculate the varint length that needs to be inserted before the transaction objects.
        magic_len = utils.get_var_size(len(self.transactions))
        txs_len = sum([len(t) for t in self.transactions])
        return len(self.header) + magic_len + txs_len

    def __eq__(self, other):
        if other is None:
            return False
        if type(self) != type(other):
            return False
        if self.hash() != other.hash():
            return False
        return True

    @property
    def version(self) -> int:
        """ Block data structure version - for internal use """
        return self.header.version

    @property
    def prev_hash(self) -> types.UInt256:
        """ The hash of the previous block """
        return self.header.prev_hash

    @property
    def merkle_root(self) -> types.UInt256:
        """ The merkle root of the transactions in the block """
        return self.header.merkle_root

    @property
    def timestamp(self) -> int:
        """ UTC timestamp in miliseconds """
        return self.header.timestamp

    @property
    def index(self) -> int:
        """ The height of the block """
        return self.header.index

    @property
    def primary_index(self) -> int:
        """ The index into the consensus node list that was used to generate this block """
        return self.header.primary_index

    @property
    def next_consensus(self) -> types.UInt160:
        """ The hash of the consensus node that will generate the next block """
        return self.header.next_consensus

    @property
    def witness(self) -> payloads.Witness:
        """ The witness of this block """
        return self.header.witness

    def hash(self) -> types.UInt256:
        """ A unique identifier based on the unsigned data portion of the object """
        return self.header.hash()

    def get_script_hashes_for_verifying(self, snapshot: storage.Snapshot) -> List[types.UInt160]:
        """
        Helper method to get the data used in verifying the object.
        """
        return self.header.get_script_hashes_for_verifying(snapshot)

    @property
    def inventory_type(self) -> payloads.InventoryType:
        """
        Inventory type identifier.
        """
        return payloads.InventoryType.BLOCK

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_serializable(self.header)
        writer.write_var_int(len(self.transactions))
        for tx in self.transactions:
            writer.write_serializable(tx)

    def serialize_unsigned(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the unsigned part of the object into a binary stream.

        Args:
            writer: instance.
        """
        self.header.serialize_unsigned(writer)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.

        Raises:
            ValueError: if the content count of the block is zero, or if there is a duplicate transaction in the list,
                or if the merkle root does not included the calculated root.
        """
        self.header = reader.read_serializable(Header)
        self.transactions = reader.read_serializable_list(payloads.Transaction, max=0xFFFF)

        if len(set(self.transactions)) != len(self.transactions):
            raise ValueError("Deserialization error - block contains duplicate transaction")

        hashes = [t.hash() for t in self.transactions]
        if crypto.MerkleTree.compute_root(hashes) != self.header.merkle_root:
            raise ValueError("Deserialization error - merkle root mismatch")

    def deserialize_unsigned(self, reader: serialization.BinaryReader) -> None:
        """ Not supported """
        raise NotImplementedError

    def rebuild_merkle_root(self) -> None:
        """
        Recalculates the Merkle root.
        """
        self.header.merkle_root = crypto.MerkleTree.compute_root([t.hash() for t in self.transactions])

    def trim(self) -> TrimmedBlock:
        """
        Reduce a block in size by replacing the transaction objects with their identifying hashes.
        """
        return TrimmedBlock(self.header, [t.hash() for t in self.transactions])

    def from_replica(self, replica: Block) -> None:
        """
        Shallow copy attributes from a reference object.
        """
        self.header = replica.header
        self.transactions = replica.transactions

    @classmethod
    def _serializable_init(cls):
        return cls(Header._serializable_init(), [])


class TrimmedBlock(serialization.ISerializable):
    """
    A size reduced Block instance.

    Contains consensus data and transactions hashes instead of their full objects.
    """

    def __init__(self, header: Header, hashes: List[types.UInt256]):
        super(TrimmedBlock, self).__init__()
        self.header = header
        self.hashes = hashes

    def __len__(self):
        return len(self.header) + utils.get_var_size(self.hashes)

    def __deepcopy__(self, memodict={}):
        # not the best, but faster than letting deepcopy() do introspection
        return self.__class__.deserialize_from_bytes(self.to_array())

    def hash(self):
        """ A unique identifier based on the unsigned data portion of the object """
        return self.header.hash()

    @property
    def index(self):
        """ The height of the block """
        return self.header.index

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_serializable(self.header)
        writer.write_serializable_list(self.hashes)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.header = reader.read_serializable(Header)
        self.hashes = reader.read_serializable_list(types.UInt256, max=0xFFFF)

    @classmethod
    def _serializable_init(cls):
        return cls(Header._serializable_init(), [])


class MerkleBlockPayload(serialization.ISerializable):
    def __init__(self, block: Block, flags: bitarray):
        hashes = [t.hash() for t in block.transactions]
        tree = crypto.MerkleTree(hashes)
        self.flags = flags.tobytes()
        self.tx_count = len(hashes)
        self.hashes = tree.to_hash_array()
        self.header = block.header

    def __len__(self):
        return len(self.header) + s.uint32 + utils.get_var_size(self.hashes) + utils.get_var_size(self.flags)

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_serializable(self.header)
        writer.write_var_int(self.tx_count)
        writer.write_serializable_list(self.hashes)
        writer.write_var_bytes(self.flags)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.header = reader.read_serializable(Header)
        self.tx_count = reader.read_var_int(max=0xFFFF)
        self.hashes = reader.read_serializable_list(types.UInt256, max=self.tx_count)
        self.flags = reader.read_var_bytes(max=(max(self.tx_count, 1) + 7) // 8)

    @classmethod
    def _serializable_init(cls):
        block = payloads.Block._serializable_init()
        flags = bitarray()
        return cls(block, flags)


class HeadersPayload(serialization.ISerializable):
    MAX_HEADERS_COUNT = 2000

    def __init__(self, headers: List[Header] = None):
        """
        Should not be called directly. Use create() instead.
        """
        self.headers = headers if headers else []

    def __len__(self):
        return utils.get_var_size(self.headers)

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_serializable_list(self.headers)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.headers = reader.read_serializable_list(Header)


class GetBlocksPayload(serialization.ISerializable):
    """
    Used to request an array block hashes that can be retrieved via a message with the
    :const:`~neo3.network.message.MessageType.GETDATA` type.
    """
    def __init__(self, hash_start: types.UInt256, count=-1):
        """
        Create payload.

        Args:
            hash_start: starting point from which to return the `next` hash.

                Note:

                    For syncing supply the local best height block hash to receive the hashes in the range of
                    best_height+1 to best_height+1+count

            count: number of hashes to return.
        """
        self.hash_start = hash_start
        self.count = count

    def __len__(self):
        return s.uint256 + s.uint16

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_serializable(self.hash_start)
        writer.write_int16(self.count)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        self.hash_start = reader.read_serializable(types.UInt256)
        self.count = reader.read_int16()

    @classmethod
    def _serializable_init(cls):
        return cls(types.UInt256.zero())


class GetBlockByIndexPayload(serialization.ISerializable):
    """
    Used to request full Block or Header objects via a message with the
    :const:`~neo3.network.message.MessageType.GETBLOCKBYINDEX` or :const:`~neo3.network.message.MessageType.GETHEADERS`
    type respectively.
    """

    def __init__(self, index_start: int, count: int = HeadersPayload.MAX_HEADERS_COUNT):
        """
        Create payload.

        Args:
            index_start: start block height.
            count: number of blocks or headers to requests starting from `index_start`.

        """
        self.index_start = index_start
        self.count = count

    def __len__(self):
        return s.uint32 + s.uint16

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        writer.write_uint32(self.index_start)
        writer.write_int16(self.count)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.

        Raises:
            ValueError: if `count` is zero or exceeds
               :const:`~neo3.network.payloads.getblocks.GetBlockByIndexPayload.MAX_BLOCKS_COUNT`.
        """
        self.index_start = reader.read_uint32()
        self.count = reader.read_int16()
        if self.count < 1 or self.count == 0 or self.count > HeadersPayload.MAX_HEADERS_COUNT:
            raise ValueError("Deserialization error - invalid count")

    @classmethod
    def _serializable_init(cls):
        return cls(0)
