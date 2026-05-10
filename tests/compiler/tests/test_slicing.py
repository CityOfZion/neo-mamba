import unittest

from neo3.compiler import TypecheckError, compile_function

from tests.compiler.tests.helpers import _build_cfg


class TestSliceBytes(unittest.TestCase):

    def test_left_compiles(self):
        src = """
def f(data: bytes) -> bytes:
    return data[:5]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8D, bc)  # LEFT

    def test_substr_compiles(self):
        src = """
def f(data: bytes) -> bytes:
    return data[2:6]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8C, bc)  # SUBSTR

    def test_right_compiles(self):
        src = """
def f(data: bytes) -> bytes:
    return data[3:]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8E, bc)  # RIGHT

    def test_full_slice_compiles(self):
        src = """
def f(data: bytes) -> bytes:
    return data[:]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertNotIn(0x8C, bc)  # no SUBSTR
        self.assertNotIn(0x8D, bc)  # no LEFT
        self.assertNotIn(0x8E, bc)  # no RIGHT

    def test_left_cfg_op(self):
        src = """
def f(data: bytes) -> bytes:
    return data[:5]
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("LEFT", ops)

    def test_substr_cfg_op(self):
        src = """
def f(data: bytes) -> bytes:
    return data[2:6]
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("SUBSTR", ops)

    def test_right_cfg_op(self):
        src = """
def f(data: bytes) -> bytes:
    return data[3:]
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("RIGHT", ops)

    def test_slice_assigned_to_local(self):
        src = """
def f(data: bytes) -> bytes:
    result: bytes = data[1:4]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_slice_with_variable_indices(self):
        src = """
def f(data: bytes, start: int, stop: int) -> bytes:
    return data[start:stop]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8C, bc)  # SUBSTR


class TestSliceBytearray(unittest.TestCase):

    def test_left_bytearray_has_convert(self):
        src = """
def f(buf: bytearray) -> bytearray:
    return buf[:5]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8D, bc)  # LEFT
        self.assertIn(0xDB, bc)  # CONVERT

    def test_substr_bytearray_has_convert(self):
        src = """
def f(buf: bytearray) -> bytearray:
    return buf[2:6]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8C, bc)  # SUBSTR
        self.assertIn(0xDB, bc)  # CONVERT

    def test_right_bytearray_has_convert(self):
        src = """
def f(buf: bytearray) -> bytearray:
    return buf[3:]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8E, bc)  # RIGHT
        self.assertIn(0xDB, bc)  # CONVERT

    def test_bytearray_slice_cfg_has_convert(self):
        src = """
def f(buf: bytearray) -> bytearray:
    return buf[1:4]
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("CONVERT", ops)


class TestSliceStr(unittest.TestCase):

    def test_left_str_compiles(self):
        src = """
def f(s: str) -> str:
    return s[:5]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8D, bc)  # LEFT
        self.assertNotIn(0xDB, bc)  # no CONVERT

    def test_substr_str_compiles(self):
        src = """
def f(s: str) -> str:
    return s[2:6]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8C, bc)  # SUBSTR
        self.assertNotIn(0xDB, bc)  # no CONVERT

    def test_right_str_compiles(self):
        src = """
def f(s: str) -> str:
    return s[3:]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x8E, bc)  # RIGHT
        self.assertNotIn(0xDB, bc)  # no CONVERT


class TestSliceErrors(unittest.TestCase):

    def test_slice_of_int_raises(self):
        src = """
def f(n: int) -> int:
    return n[:5]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_slice_of_bool_raises(self):
        src = """
def f(b: bool) -> bool:
    return b[:2]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_negative_step_raises(self):
        src = """
def f(data: bytes) -> bytes:
    return data[::-1]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_zero_step_raises(self):
        src = """
def f(data: bytes) -> bytes:
    return data[::0]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_step_1_is_allowed(self):
        src = """
def f(data: bytes) -> bytes:
    return data[1:5:1]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)


class TestSliceStep(unittest.TestCase):

    def test_bytes_step2_compiles(self):
        src = """
def f(data: bytes) -> bytes:
    return data[::2]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xD0, bc)  # SETITEM

    def test_bytes_step_with_start(self):
        src = """
def f(data: bytes) -> bytes:
    return data[1::2]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xD0, bc)

    def test_bytes_step_with_start_stop(self):
        src = """
def f(data: bytes) -> bytes:
    return data[0:8:3]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xD0, bc)

    def test_bytearray_step_no_convert(self):
        # bytearray result stays as Buffer — no CONVERT(0xDB) needed
        src = """
def f(buf: bytearray) -> bytearray:
    return buf[::2]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xD0, bc)  # SETITEM
        self.assertNotIn(0xDB, bc)  # no CONVERT

    def test_str_step_has_convert(self):
        # str result must CONVERT Buffer → ByteString (0x28)
        src = """
def f(s: str) -> str:
    return s[::2]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xD0, bc)  # SETITEM
        self.assertIn(0xDB, bc)  # CONVERT present

    def test_step_cfg_has_setitem(self):
        src = """
def f(data: bytes) -> bytes:
    return data[::2]
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("SETITEM", ops)

    def test_step_variable(self):
        # variable step should compile without error
        src = """
def f(data: bytes, k: int) -> bytes:
    return data[::k]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_step_assigned_to_local(self):
        src = """
def f(data: bytes) -> bytes:
    result: bytes = data[0:6:2]
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_step_stop_clamped_to_length(self):
        # stop > len(data) must not fault: MIN opcode clamps stop to SIZE(data)
        src = """
def f(data: bytes) -> bytes:
    return data[0:8:2]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xB9, bc)  # MIN — clamps stop to len(data)


if __name__ == "__main__":
    unittest.main()
