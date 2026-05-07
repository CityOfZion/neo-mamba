import unittest

from neo3.compiler import (
    AnyType,
    BoolType,
    BytearrayType,
    BytesType,
    ClassType,
    DictType,
    ECPointType,
    IntType,
    IteratorType,
    ListType,
    NoneType,
    OptionalType,
    StrType,
    TupleType,
    TypecheckError,
    UInt160Type,
    UInt256Type,
    UnionType,
    compile_function,
)


class TestTypePredicates(unittest.TestCase):
    """item-14: is_numeric() and is_byteslike() predicates on type objects."""

    def test_is_numeric_true_for_int(self):
        self.assertTrue(IntType().is_numeric())

    def test_is_numeric_true_for_bool(self):
        self.assertTrue(BoolType().is_numeric())

    def test_is_numeric_false_for_str(self):
        self.assertFalse(StrType().is_numeric())

    def test_is_numeric_false_for_bytes(self):
        self.assertFalse(BytesType().is_numeric())

    def test_is_numeric_false_for_bytearray(self):
        self.assertFalse(BytearrayType().is_numeric())

    def test_is_numeric_false_for_list(self):
        self.assertFalse(ListType(IntType()).is_numeric())

    def test_is_numeric_false_for_none(self):
        self.assertFalse(NoneType().is_numeric())

    def test_is_numeric_false_for_any(self):
        self.assertFalse(AnyType().is_numeric())

    def test_is_byteslike_true_for_bytes(self):
        self.assertTrue(BytesType().is_byteslike())

    def test_is_byteslike_true_for_bytearray(self):
        self.assertTrue(BytearrayType().is_byteslike())

    def test_is_byteslike_true_for_str(self):
        self.assertTrue(StrType().is_byteslike())

    def test_is_byteslike_false_for_int(self):
        self.assertFalse(IntType().is_byteslike())

    def test_is_byteslike_false_for_bool(self):
        self.assertFalse(BoolType().is_byteslike())

    def test_is_byteslike_false_for_list(self):
        self.assertFalse(ListType(BytesType()).is_byteslike())

    def test_is_byteslike_false_for_none(self):
        self.assertFalse(NoneType().is_byteslike())

    def test_is_byteslike_false_for_uint160(self):
        self.assertFalse(UInt160Type().is_byteslike())

    def test_all_types_have_both_predicates(self):
        all_types = [
            IntType(),
            BoolType(),
            BytesType(),
            BytearrayType(),
            StrType(),
            ListType(IntType()),
            DictType(IntType(), IntType()),
            TupleType((IntType(),)),
            NoneType(),
            OptionalType(IntType()),
            ClassType("Foo"),
            AnyType(),
            IteratorType(),
            UInt160Type(),
            UInt256Type(),
            ECPointType(),
            UnionType((IntType(), StrType())),
        ]
        for t in all_types:
            self.assertIsInstance(
                t.is_numeric(), bool, msg=f"{type(t).__name__}.is_numeric()"
            )
            self.assertIsInstance(
                t.is_byteslike(), bool, msg=f"{type(t).__name__}.is_byteslike()"
            )


class TestECPoint(unittest.TestCase):

    def test_ecpoint_constructor_from_bytes_compiles(self):
        src = """\
from neo3.sc.types import ECPoint
def f(b: bytes) -> ECPoint:
    return ECPoint(b)
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_ecpoint_constructor_emits_no_convert(self):
        src = """\
from neo3.sc.types import ECPoint
def f(b: bytes) -> ECPoint:
    return ECPoint(b)
"""
        bc = compile_function(src)
        self.assertNotIn(0xDB, bc)  # no CONVERT — already a ByteString

    def test_ecpoint_constructor_rejects_non_bytes(self):
        src = """\
from neo3.sc.types import ECPoint
def f(n: int) -> ECPoint:
    return ECPoint(n)
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_ecpoint_to_array_compiles(self):
        src = """\
from neo3.sc.types import ECPoint
def f(pk: ECPoint) -> bytes:
    return pk.to_array()
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_ecpoint_to_array_roundtrip(self):
        src = """\
from neo3.sc.types import ECPoint
def f(b: bytes) -> bytes:
    pk: ECPoint = ECPoint(b)
    return pk.to_array()
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_ecpoint_literal_wrong_size_raises(self):
        # 11 bytes — too short for ECPoint (needs 33)
        lit = "b'" + "\\x00" * 11 + "'"
        src = f"from neo3.sc.types import ECPoint\ndef f() -> ECPoint:\n    return ECPoint({lit})\n"
        with self.assertRaises(TypecheckError) as ctx:
            compile_function(src)
        self.assertIn("33", str(ctx.exception))

    def test_ecpoint_literal_correct_size_compiles(self):
        # 33 bytes — correct ECPoint size
        lit = "b'\\x02" + "\\x00" * 32 + "'"
        src = f"from neo3.sc.types import ECPoint\ndef f() -> ECPoint:\n    return ECPoint({lit})\n"
        self.assertIsInstance(compile_function(src), bytes)


class TestUInt160(unittest.TestCase):

    def test_uint160_literal_correct_size_compiles(self):
        # 20 bytes — correct UInt160 size
        lit = "b'" + "\\x00" * 20 + "'"
        src = f"from neo3.sc.types import UInt160\ndef f() -> UInt160:\n    return UInt160({lit})\n"
        self.assertIsInstance(compile_function(src), bytes)

    def test_uint160_literal_wrong_size_raises(self):
        # 10 bytes — too short
        lit = "b'" + "\\x00" * 10 + "'"
        src = f"from neo3.sc.types import UInt160\ndef f() -> UInt160:\n    return UInt160({lit})\n"
        with self.assertRaises(TypecheckError) as ctx:
            compile_function(src)
        self.assertIn("20", str(ctx.exception))

    def test_uint160_dynamic_bytes_compiles(self):
        src = """\
from neo3.sc.types import UInt160
def f(b: bytes) -> UInt160:
    return UInt160(b)
"""
        self.assertIsInstance(compile_function(src), bytes)


class TestUInt256(unittest.TestCase):

    def test_uint256_literal_correct_size_compiles(self):
        # 32 bytes — correct UInt256 size
        lit = "b'" + "\\x00" * 32 + "'"
        src = f"from neo3.sc.types import UInt256\ndef f() -> UInt256:\n    return UInt256({lit})\n"
        self.assertIsInstance(compile_function(src), bytes)

    def test_uint256_literal_wrong_size_raises(self):
        # 20 bytes — too short
        lit = "b'" + "\\x00" * 20 + "'"
        src = f"from neo3.sc.types import UInt256\ndef f() -> UInt256:\n    return UInt256({lit})\n"
        with self.assertRaises(TypecheckError) as ctx:
            compile_function(src)
        self.assertIn("32", str(ctx.exception))

    def test_uint256_dynamic_bytes_compiles(self):
        src = """\
from neo3.sc.types import UInt256
def f(b: bytes) -> UInt256:
    return UInt256(b)
"""
        self.assertIsInstance(compile_function(src), bytes)
