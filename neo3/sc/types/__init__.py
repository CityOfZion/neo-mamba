from neo3.api import StackItem, StackItemType
from enum import IntEnum, IntFlag
from typing import Any


class FindOptions(IntFlag):
    """Storage iteration options for System.Storage.Local.Find."""

    NONE = 0
    KEYS_ONLY = 1
    REMOVE_PREFIX = 2
    VALUES_ONLY = 4
    DESERIALIZE_VALUES = 8
    PICK_FIELD0 = 16
    PICK_FIELD1 = 32
    BACKWARDS = 128


class UInt160:
    def __init__(self, data: bytes = b""):
        self.data = data

    def __len__(self):
        pass

    def to_array(self) -> bytes:
        return self.data

    @classmethod
    def zero(cls) -> "UInt160":
        pass

    @classmethod
    def from_string(cls, hash: str) -> "UInt160":
        pass


class UInt256:
    def __init__(self, data: bytes = b""):
        self.data = data

    def __len__(self):
        pass

    def to_array(self) -> bytes:
        return self.data

    @classmethod
    def zero(cls) -> "UInt256":
        pass

    @classmethod
    def from_string(cls, hash: str) -> "UInt256":
        pass


# can't use mamba's ECPoint as that is a C-extension
class ECPoint:
    """
    Represents a coordinate pair for elliptic curve cryptography (ECC) structures.
    """

    zero: "ECPoint"

    def __init__(self, data: bytes = b""):
        self.data = data

    def __len__(self):
        pass

    def to_array(self) -> bytes:
        return self.data


class TrimmedTransaction:
    """
    Represents a trimmed transaction.

    Attributes:
        hash (UInt256): A unique identifier based on the unsigned data portion of the object.
        version (int): The data structure version of the transaction.
        nonce (int): A random number used once in the cryptography.
        sender (UInt160): The sender is the first signer of the transaction; they will pay the fees.
        system_fee (int): The fee paid for executing the script.
        network_fee (int): The fee paid for validation and inclusion in a block by consensus nodes.
        valid_until_block (int): The block height before which the transaction is valid.
        script (bytes): The array of instructions executed by the VM.
    """

    def __init__(self):
        self.hash: UInt256 = UInt256()
        self.version: int = 0
        self.nonce: int = 0
        self.sender: UInt160 = UInt160()
        self.system_fee: int = 0
        self.network_fee: int = 0
        self.valid_until_block: int = 0
        self.script: bytes = b""


class NeoAccountState:
    """Represents the account state of NEO token in the NEO system.

    Attributes:
        balance (int): The current account balance, which equals the votes cast.
        height (int): The height of the block where the balance last changed.
        vote_to (ECPoint): The voting target of the account.
        last_gas_per_vote (int): The last recorded gas per vote value.
    """

    def __init__(self):
        """Initializes a new instance of NeoAccountState with default values."""
        self.balance: int = 0
        self.height: int = 0
        self.vote_to: Optional[ECPoint] = ECPoint(bytes(33))
        self.last_gas_per_vote: int = 0

    @classmethod
    def from_stackitem(cls, si: StackItem):
        if si.type != StackItemType.STRUCT:
            raise ValueError(
                f"item is not of type '{StackItemType.STRUCT}' but of type '{si.type}'"
            )
        items = si.value
        c = cls()
        c.balance = items[0].as_int()
        c.height = items[1].as_int()
        try:
            pk = items[2].as_bytes()
            c.vote_to = ECPoint(pk)
        except Exception:
            c.vote_to = None
        c.last_gas_per_vote = items[3].as_int()
        return c


class ContractState:
    """ """

    def __init__(self):
        self.id: int = 0
        self.update_counter: int = 0
        self.hash: UInt160 = UInt160()
        self.nef: bytes = bytes()
        self.manifest: Any = bytes()

    @classmethod
    def from_stackitem(cls, si: StackItem):
        if si.type != StackItemType.ARRAY:
            raise ValueError(
                f"item is not of type '{StackItemType.ARRAY}' but of type '{si.type}'"
            )
        items = si.value
        c = cls()
        c.id = items[0].as_int()
        c.update_counter = items[1].as_int()
        c.hash = UInt160(items[2].as_bytes())
        c.nef = items[3].as_bytes()
        c.manifest = items[
            4
        ]  # TODO: parse nicely as per https://github.com/neo-project/neo/blob/92678acfee8dba8848764b20f690f97fd984313a/src/Neo/SmartContract/Manifest/ContractManifest.cs#L92
        return c


class CallFlags(IntFlag):
    """
    Describes the required call permissions for contract functions.
    """

    NONE = 0
    READ_STATES = 0x1
    WRITE_STATES = 0x02
    ALLOW_CALL = 0x04
    ALLOW_NOTIFY = 0x08
    STATES = READ_STATES | WRITE_STATES
    READ_ONLY = READ_STATES | ALLOW_CALL
    ALL = STATES | ALLOW_CALL | ALLOW_NOTIFY


class NamedCurveHash(IntEnum):
    """
    Represents the named curve used in ECDSA.

    Check out `Neo's Documentation <https://developers.neo.org/docs/n3/foundation/Cryptography/encryption_algorithm#ecdsa-signing>`__
    to learn more about ECDSA signing.
    """

    SECP256K1SHA256 = 22
    """
    The secp256k1 curve and SHA256 hash algorithm.
    """

    SECP256R1SHA256 = 23
    """
    The secp256r1 curve, which known as prime256v1 or nistP-256, and SHA256 hash algorithm.
    """

    SECP256K1KECCAK256 = 122
    """
    The secp256k1 curve and Keccak256 hash algorithm.
    """

    SECP256R1KECCAK256 = 123
    """
    The secp256r1 curve, which known as prime256v1 or nistP-256, and Keccak256 hash algorithm.
    """


class TrimmedBlock:
    """
    Represents a Trimmedblock.

    For more details, see:
    https://developers.neo.org/docs/n3/foundation/Blocks

    Attributes:
        hash (UInt256): A unique identifier based on the unsigned data portion of the object.
        version (int): The data structure version of the block.
        previous_hash (UInt256): The hash of the previous block.
        merkle_root (UInt256): The merkle root of the transactions.
        timestamp (int): UTC timestamp of the block in milliseconds.
        nonce (int): A random number used once in the cryptography.
        index (int): The index of the block.
        primary_index (int): The primary index of the consensus node that generated this block.
        next_consensus (UInt160): The script hash of the consensus nodes that generates the next block.
        transaction_count (int): The number of transactions on this block.
    """

    def __init__(self):
        self.hash: UInt256 = UInt256()
        self.version: int = 0
        self.previous_hash: UInt256 = UInt256()
        self.merkle_root: UInt256 = UInt256()
        self.timestamp: int = 0
        self.nonce: int = 0
        self.index: int = 0
        self.primary_index: int = 0
        self.next_consensus: UInt160 = UInt160()
        self.transaction_count: int = 0


class Notification:
    """
    Represents an in contract Notification.

    Attributes:
        script_hash (UInt160): the script hash of the notification sender (i.e. which smart contract).
        event_name (str): the notification name.
        state (list): the notification arguments.
    """

    def __init__(self):
        self.script_hash: UInt160 = UInt160()
        self.event_name: str = ""
        self.state: list = []
