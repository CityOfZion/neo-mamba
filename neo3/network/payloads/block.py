from __future__ import annotations
import hashlib
from typing import List
from neo3.core import Size as s, serialization, types, utils, cryptography as crypto, IClonable
from neo3.network import payloads
from bitarray import bitarray  # type: ignore
from copy import deepcopy


class _BlockBase(serialization.ISerializable):
    def __init__(self,
                 version: int,
                 prev_hash: types.UInt256,
                 timestamp: int,
                 index: int,
                 next_consensus: types.UInt160,
                 witness: payloads.Witness,
                 merkle_root: types.UInt256 = None,
                 ):

        self.version = version
        self.prev_hash = prev_hash
        self.merkle_root = merkle_root if merkle_root else types.UInt256.zero()
        self.timestamp = timestamp
        self.index = index
        self.next_consensus = next_consensus
        self.witness = witness

    def __len__(self):
        return s.uint32 + s.uint256 + s.uint256 + s.uint64 + s.uint32 + s.uint160 + 1 + len(self.witness)

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        self.serialize_unsigned(writer)
        writer.write_uint8(1)
        writer.write_serializable(self.witness)

    def serialize_unsigned(self, writer: serialization.BinaryWriter) -> None:
        writer.write_uint32(self.version)
        writer.write_serializable(self.prev_hash)
        writer.write_serializable(self.merkle_root)
        writer.write_uint64(self.timestamp)
        writer.write_uint32(self.index)
        writer.write_serializable(self.next_consensus)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.

        Raises:
            ValueError: if no witnesses are found.
        """
        self.deserialize_unsigned(reader)
        witness_obj_count = reader.read_uint8()
        if witness_obj_count != 1:
            raise ValueError(f"Deserialization error - Witness object count is {witness_obj_count} must be 1")
        self.witness = reader.read_serializable(payloads.Witness)

    def deserialize_unsigned(self, reader: serialization.BinaryReader) -> None:
        self.version = reader.read_uint32()
        self.prev_hash = reader.read_serializable(types.UInt256)
        self.merkle_root = reader.read_serializable(types.UInt256)
        self.timestamp = reader.read_uint64()
        self.index = reader.read_uint32()
        self.next_consensus = reader.read_serializable(types.UInt160)

    def hash(self) -> types.UInt256:
        """
        Get a unique block identifier based on the unsigned data portion of the object.
        """
        with serialization.BinaryWriter() as bw:
            self.serialize_unsigned(bw)
            data_to_hash = bytearray(bw._stream.getvalue())
            data = hashlib.sha256(hashlib.sha256(data_to_hash).digest()).digest()
            return types.UInt256(data=data)


class Header(_BlockBase):
    """
    A Block header only object.

    Does not contain any consensus data or transactions.

    See also:
        :class:`~neo3.network.payloads.block.TrimmedBlock`
    """
    def __init__(self,
                 version: int,
                 prev_hash: types.UInt256,
                 timestamp: int,
                 index: int,
                 next_consensus: types.UInt160,
                 witness: payloads.Witness,
                 merkle_root: types.UInt256 = None
                 ):
        super(Header, self).__init__(version, prev_hash, timestamp, index, next_consensus, witness, merkle_root)

    def __len__(self):
        return super(Header, self).__len__() + 1

    def __eq__(self, other):
        if other is None:
            return False
        if type(self) != type(other):
            return False
        if self.hash() != other.hash():
            return False
        return True

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        super(Header, self).serialize(writer)
        writer.write_uint8(0)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.

        Raises:
            ValueError: if the check byte does not equal.
        """
        super(Header, self).deserialize(reader)
        tmp = reader.read_uint8()
        if tmp != 0:
            raise ValueError("Deserialization error")

    @classmethod
    def _serializable_init(cls):
        return cls(0,
                   types.UInt256.zero(),
                   0,
                   0,
                   types.UInt160.zero(),
                   payloads.Witness(b'', b''))


class Block(_BlockBase, payloads.IInventory):
    """
    The famous Block. I transfer chain state.
    """
    #: The maximum item count per block. Consensus data and Transactions are considered items.
    MAX_CONTENTS_PER_BLOCK = 65535
    #: The maximum number of transactions allowed to be included in a block.
    MAX_TX_PER_BLOCK = MAX_CONTENTS_PER_BLOCK - 1

    def __init__(self,
                 version: int,
                 prev_hash: types.UInt256,
                 timestamp: int,
                 index: int,
                 next_consensus: types.UInt160,
                 witness: payloads.Witness,
                 consensus_data: payloads.ConsensusData,
                 transactions: List[payloads.Transaction] = None,
                 merkle_root: types.UInt256 = None,
                 ):
        super(Block, self).__init__(version, prev_hash, timestamp, index, next_consensus, witness, merkle_root)
        self.consensus_data = consensus_data
        self.transactions = [] if transactions is None else transactions

    def __len__(self):
        # calculate the varint length that needs to be inserted before the transaction objects.
        magic_len = utils.get_var_size(len(self.transactions))
        txs_len = sum([len(t) for t in self.transactions])
        return super(Block, self).__len__() + magic_len + len(self.consensus_data) + txs_len

    def __eq__(self, other):
        if other is None:
            return False
        if type(self) != type(other):
            return False
        if self.hash() != other.hash():
            return False
        return True

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
        super(Block, self).serialize(writer)
        writer.write_var_int(len(self.transactions) + 1)
        writer.write_serializable(self.consensus_data)
        for tx in self.transactions:
            writer.write_serializable(tx)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.

        Raises:
            ValueError: if the content count of the block is zero, or if there is a duplicate transaction in the list,
                or if the merkle root does not included the calculated root.
        """
        super(Block, self).deserialize(reader)
        content_count = reader.read_var_int(max=self.MAX_CONTENTS_PER_BLOCK)
        if content_count == 0:
            raise ValueError("Deserialization error - no contents")

        self.consensus_data = reader.read_serializable(payloads.ConsensusData)
        tx_count = content_count - 1
        for _ in range(tx_count):
            self.transactions.append(reader.read_serializable(payloads.Transaction))

        if len(set(self.transactions)) != tx_count:
            raise ValueError("Deserialization error - block contains duplicate transaction")

        hashes = [t.hash() for t in self.transactions]
        if Block.calculate_merkle_root(self.consensus_data.hash(), hashes) != self.merkle_root:
            raise ValueError("Deserialization error - merkle root mismatch")

    def rebuild_merkle_root(self) -> None:
        """
        Recalculates the Merkle root.
        """
        self.merkle_root = Block.calculate_merkle_root(self.consensus_data.hash(),
                                                       [t.hash() for t in self.transactions])

    def trim(self) -> TrimmedBlock:
        """
        Reduce a block in size by replacing the consensus data and transaction objects with their identifying hashes.
        """
        hashes = [self.consensus_data.hash()] + [t.hash() for t in self.transactions]
        return TrimmedBlock(version=self.version,
                            prev_hash=self.prev_hash,
                            merkle_root=self.merkle_root,
                            timestamp=self.timestamp,
                            index=self.index,
                            next_consensus=self.next_consensus,
                            witness=self.witness,
                            hashes=hashes,
                            consensus_data=self.consensus_data
                            )

    @staticmethod
    def calculate_merkle_root(consensus_data_hash: types.UInt256,
                              transaction_hashes: List[types.UInt256]) -> types.UInt256:
        """
        Calculate a Merkle root.

        Args:
            consensus_data_hash:
            transaction_hashes:
        """
        hashes = [consensus_data_hash] + transaction_hashes
        return crypto.MerkleTree.compute_root(hashes)

    def from_replica(self, replica: Block) -> None:
        self.version = replica.version
        self.prev_hash = replica.prev_hash
        self.merkle_root = replica.merkle_root
        self.timestamp = replica.timestamp
        self.index = replica.index
        self.next_consensus = replica.next_consensus
        self.witness = replica.witness
        self.consensus_data = replica.consensus_data
        self.transactions = replica.transactions

    @classmethod
    def _serializable_init(cls):
        return cls(0,
                   types.UInt256.zero(),
                   0,
                   0,
                   types.UInt160.zero(),
                   payloads.Witness(b'', b''),
                   payloads.ConsensusData())


class TrimmedBlock(_BlockBase, IClonable):
    """
    A size reduced Block instance.

    Contains consensus data and transactions hashes instead of their full objects.
    """

    def __init__(self,
                 version: int,
                 prev_hash: types.UInt256,
                 timestamp: int,
                 index: int,
                 next_consensus: types.UInt160,
                 witness: payloads.Witness,
                 hashes: List[types.UInt256],
                 consensus_data: payloads.ConsensusData,
                 merkle_root: types.UInt256 = None):
        super(TrimmedBlock, self).__init__(version, prev_hash, timestamp, index, next_consensus, witness, merkle_root)
        self.hashes = hashes
        self.consensus_data = consensus_data

    def __len__(self):
        size = super(TrimmedBlock, self).__len__()
        size += utils.get_var_size(self.hashes)
        if self.consensus_data:
            size += len(self.consensus_data)
        return size

    def __deepcopy__(self, memodict={}):
        # not the best, but faster than letting deepcopy() do introspection
        return TrimmedBlock.deserialize_from_bytes(self.to_array())

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        super(TrimmedBlock, self).serialize(writer)
        writer.write_serializable_list(self.hashes)
        if len(self.hashes) > 0:
            writer.write_serializable(self.consensus_data)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        super(TrimmedBlock, self).deserialize(reader)
        self.hashes = reader.read_serializable_list(types.UInt256)
        if len(self.hashes) > 0:
            self.consensus_data = reader.read_serializable(payloads.ConsensusData)

    def from_replica(self, replica: TrimmedBlock) -> None:
        """
        Shallow copy attributes from a reference object.
        """
        super().from_replica(replica)
        self.version = replica.version
        self.prev_hash = replica.prev_hash
        self.merkle_root = replica.merkle_root
        self.timestamp = replica.timestamp
        self.index = replica.index
        self.next_consensus = replica.next_consensus
        self.witness = replica.witness
        self.hashes = replica.hashes
        self.consensus_data = replica.consensus_data

    def clone(self) -> TrimmedBlock:
        """
        Deep copy
        """
        return deepcopy(self)

    @classmethod
    def _serializable_init(cls):
        return cls(0,
                   types.UInt256.zero(),
                   0,
                   0,
                   types.UInt160.zero(),
                   payloads.Witness(b'', b''),
                   [],
                   payloads.ConsensusData())


class MerkleBlockPayload(_BlockBase):
    def __init__(self, block: Block, flags: bitarray):
        super(MerkleBlockPayload, self).__init__(block.version,
                                                 block.prev_hash,
                                                 block.timestamp,
                                                 block.index,
                                                 block.next_consensus,
                                                 block.witness,
                                                 block.merkle_root)
        hashes = [block.consensus_data.hash()] + [t.hash() for t in block.transactions]
        tree = crypto.MerkleTree(hashes)
        self.flags = flags.tobytes()
        self.content_count = len(hashes)
        self.hashes = tree.to_hash_array()

    def __len__(self):
        return super(MerkleBlockPayload, self).__len__() + s.uint32 + utils.get_var_size(self.hashes) + \
            utils.get_var_size(self.flags)

    @classmethod
    def _serializable_init(cls):
        block = payloads.Block._serializable_init()
        flags = bitarray()
        return cls(block, flags)

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        """
        Serialize the object into a binary stream.

        Args:
            writer: instance.
        """
        super(MerkleBlockPayload, self).serialize(writer)
        writer.write_var_int(self.content_count)
        writer.write_serializable_list(self.hashes)
        writer.write_var_bytes(self.flags)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        """
        Deserialize the object from a binary stream.

        Args:
            reader: instance.
        """
        super(MerkleBlockPayload, self).deserialize(reader)
        self.content_count = reader.read_var_int()
        self.hashes = reader.read_serializable_list(types.UInt256)
        self.flags = reader.read_var_bytes()


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

    @classmethod
    def create(cls, headers: List[Header]) -> HeadersPayload:
        """
        Create payload.

        Args:
            headers: Header objects to include.
        """
        return cls(headers)


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
