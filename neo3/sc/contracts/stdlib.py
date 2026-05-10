from typing import Any

from neo3.sc.compiletime import contract, display_name
from neo3.sc.types import UInt160


@contract("0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0")
class StdLib:
    """
    Represents the StdLib native contract.

    See:
        https://developers.neo.org/docs/n3/reference/scapi/framework/native/StdLib
    """

    hash: UInt160

    @staticmethod
    def serialize(item: Any) -> bytes:
        """Serialize *item* to its NeoVM binary representation."""
        pass

    @staticmethod
    def deserialize(data: bytes) -> Any:
        """Deserialize NeoVM binary *data* back to a stack item."""
        pass

    @staticmethod
    @display_name("jsonSerialize")
    def json_serialize(item: Any) -> str:
        """Serialize *item* to a JSON string."""
        pass

    @staticmethod
    @display_name("jsonDeserialize")
    def json_deserialize(json: str) -> Any:
        """Deserialize a JSON string to a stack item."""
        pass

    @staticmethod
    def itoa(value: int, base: int) -> str:
        """Convert integer *value* to a string in the given *base* (10 or 16)."""
        pass

    @staticmethod
    def atoi(value: str, base: int) -> int:
        """Parse a string *value* as an integer in the given *base* (10 or 16)."""
        pass

    @staticmethod
    @display_name("hexEncode")
    def hex_encode(data: bytes) -> str:
        """Encode *data* as a lowercase hex string."""
        pass

    @staticmethod
    @display_name("hexDecode")
    def hex_decode(hex_str: str) -> bytes:
        """Decode a hex string to bytes."""
        pass

    @staticmethod
    @display_name("base64Encode")
    def base64_encode(data: bytes) -> str:
        """Encode *data* as a Base64 string."""
        pass

    @staticmethod
    @display_name("base64Decode")
    def base64_decode(b64: str) -> bytes:
        """Decode a Base64 string to bytes."""
        pass

    @staticmethod
    @display_name("base58Encode")
    def base58_encode(data: bytes) -> str:
        """Encode *data* as a Base58 string."""
        pass

    @staticmethod
    @display_name("base58Decode")
    def base58_decode(b58: str) -> bytes:
        """Decode a Base58 string to bytes."""
        pass

    @staticmethod
    @display_name("base58CheckEncode")
    def base58_check_encode(data: bytes) -> str:
        """Encode *data* as a Base58Check string (with checksum)."""
        pass

    @staticmethod
    @display_name("base58CheckDecode")
    def base58_check_decode(b58check: str) -> bytes:
        """Decode a Base58Check string, verifying the checksum."""
        pass

    @staticmethod
    @display_name("stringSplit")
    def string_split(s: str, separator: str, remove_empty_entries: bool) -> list:
        """Split string *s* on *separator*."""
        pass

    @staticmethod
    @display_name("memoryCompare")
    def memory_compare(a: bytes, b: bytes) -> int:
        """Return negative, zero, or positive comparing byte strings *a* and *b*."""
        pass

    @staticmethod
    @display_name("memorySearch")
    def memory_search(mem: bytes, pattern: bytes) -> int:
        """Return the first index of *pattern* in *mem*, or -1 if not found."""
        pass

    @staticmethod
    @display_name("memorySearch")
    def memory_search_from(mem: bytes, pattern: bytes, start: int) -> int:
        """Return the first index of *pattern* in *mem* starting at *start*, or -1."""
        pass
