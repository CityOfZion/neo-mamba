import unittest

from neo3.compiler import TypecheckError, compile_function
from neo3.vm import OpCode

# [c, i] -> [c, i + (i < 0) * len(c)], emitted before PICKITEM/SETITEM/SUBSTR
_WRAP = bytes(
    [OpCode.OVER, OpCode.SIZE, OpCode.OVER, OpCode.PUSHINT8, 0]
    + [OpCode.LT, OpCode.MUL, OpCode.ADD]
)


class TestNegativeIndexLoad(unittest.TestCase):

    def test_list_variable_index_wraps(self):
        src = "def f(x: list[int], i: int) -> int:\n    return x[i]"
        bc = compile_function(src)
        self.assertIn(_WRAP + bytes([OpCode.PICKITEM]), bc)

    def test_bytes_variable_index_wraps(self):
        src = "def f(x: bytes, i: int) -> int:\n    return x[i]"
        self.assertIn(_WRAP + bytes([OpCode.PICKITEM]), compile_function(src))

    def test_bytearray_variable_index_wraps(self):
        src = "def f(x: bytearray, i: int) -> int:\n    return x[i]"
        self.assertIn(_WRAP + bytes([OpCode.PICKITEM]), compile_function(src))

    def test_str_variable_index_wraps(self):
        src = "def f(x: str, i: int) -> str:\n    return x[i]"
        self.assertIn(_WRAP, compile_function(src))

    def test_non_negative_literal_index_is_unchanged(self):
        src = "def f(x: list[int]) -> int:\n    return x[2]"
        bc = compile_function(src)
        self.assertNotIn(OpCode.SIZE, bc)
        self.assertIn(bytes([OpCode.PUSHINT8, 2, OpCode.PICKITEM]), bc)

    def test_negative_literal_index_uses_len_without_runtime_test(self):
        src = "def f(x: list[int]) -> int:\n    return x[-1]"
        bc = compile_function(src)
        self.assertIn(
            bytes([OpCode.DUP, OpCode.SIZE, OpCode.PUSHINT8, 1, OpCode.SUB]), bc
        )
        self.assertNotIn(OpCode.MUL, bc)

    def test_dict_index_is_not_wrapped(self):
        src = "def f(d: dict[int, int], k: int) -> int:\n    return d[k]"
        bc = compile_function(src)
        self.assertNotIn(OpCode.SIZE, bc)
        self.assertNotIn(OpCode.MUL, bc)


class TestNegativeIndexStore(unittest.TestCase):

    def test_list_variable_index_store_wraps(self):
        src = "def f(x: list[int], i: int) -> None:\n    x[i] = 5"
        self.assertIn(_WRAP, compile_function(src))

    def test_bytearray_variable_index_store_wraps(self):
        src = "def f(x: bytearray, i: int) -> None:\n    x[i] = 5"
        self.assertIn(_WRAP, compile_function(src))

    def test_dict_store_is_not_wrapped(self):
        src = "def f(d: dict[int, int], k: int) -> None:\n    d[k] = 5"
        bc = compile_function(src)
        self.assertNotIn(OpCode.SIZE, bc)
        self.assertNotIn(OpCode.MUL, bc)


class TestNegativeTupleIndex(unittest.TestCase):

    def test_negative_literal_compiles(self):
        src = "def f(t: tuple[int, str]) -> str:\n    return t[-1]"
        self.assertIsInstance(compile_function(src), bytes)

    def test_negative_literal_type_is_element_type(self):
        src = "def f(t: tuple[int, str]) -> int:\n    return t[-1]"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_negative_literal_out_of_range_raises(self):
        src = "def f(t: tuple[int, str]) -> int:\n    return t[-3]"
        with self.assertRaises(TypecheckError) as ctx:
            compile_function(src)
        self.assertIn("tuple index -3 out of range", str(ctx.exception))


class TestSliceBoundsClamp(unittest.TestCase):

    def test_bytes_slice_bounds_are_wrapped(self):
        for body in ("x[i:]", "x[:i]", "x[i:i]", "x[i:i:2]"):
            with self.subTest(body=body):
                src = f"def f(x: bytes, i: int) -> bytes:\n    return {body}"
                self.assertIn(_WRAP, compile_function(src))

    def test_bytes_slice_count_floors_at_zero(self):
        src = "def f(x: bytes, a: int, b: int) -> bytes:\n    return x[a:b]"
        bc = compile_function(src)
        self.assertIn(bytes([OpCode.PUSHINT8, 0, OpCode.MAX, OpCode.SUBSTR]), bc)


if __name__ == "__main__":
    unittest.main()
