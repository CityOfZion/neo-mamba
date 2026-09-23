from neo3.sc.compiletime import public


@public
def int_in_list(needle: int) -> bool:
    x: list[int] = [1, 2, 3, 4, 5]
    return needle in x


@public
def int_not_in_list(needle: int) -> bool:
    x: list[int] = [1, 2, 3, 4, 5]
    return needle not in x


@public
def int_in_empty_list(needle: int) -> bool:
    x: list[int] = []
    return needle in x


@public
def str_in_list(needle: str) -> bool:
    x: list[str] = ["neo", "gas", "mamba"]
    return needle in x


@public
def bytes_in_list(needle: bytes) -> bool:
    x: list[bytes] = [b"\x01", b"\x02\x03"]
    return needle in x


@public
def bytearray_in_list(needle: bytes) -> bool:
    # Distinct Buffer objects with equal content must match (Python value semantics)
    x: list[bytearray] = [bytearray(b"\x01"), bytearray(b"\x02\x03")]
    return bytearray(needle) in x


@public
def key_not_in_dict(key: str) -> bool:
    d: dict[str, int] = {"a": 1, "b": 2}
    return key not in d


@public
def substr_in_str(needle: str, haystack: str) -> bool:
    return needle in haystack


@public
def substr_not_in_str(needle: str, haystack: str) -> bool:
    return needle not in haystack


@public
def subbytes_in_bytes(needle: bytes, haystack: bytes) -> bool:
    return needle in haystack


@public
def subbytes_in_bytearray(needle: bytes, haystack: bytes) -> bool:
    return needle in bytearray(haystack)


@public
def subbytearray_in_bytes(needle: bytes, haystack: bytes) -> bool:
    return bytearray(needle) in haystack
