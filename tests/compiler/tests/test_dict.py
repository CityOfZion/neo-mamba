import unittest

from neo3.compiler import TypecheckError, compile_function

from tests.compiler.tests.helpers import _build_cfg


class TestDictType(unittest.TestCase):

    def test_dict_str_int_annotation(self):
        src = """
def f(d: dict[str, int]) -> int:
    return d["key"]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_dict_int_bool_annotation(self):
        src = """
def f(d: dict[int, bool]) -> bool:
    return d[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_dict_bytes_int_annotation(self):
        src = """
def f(d: dict[bytes, int]) -> int:
    return d[b"k"]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_dict_bool_str_annotation(self):
        src = """
def f(d: dict[bool, str]) -> str:
    return d[True]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_dict_invalid_key_type_raises(self):
        src = """
def f(d: dict[list[int], int]) -> int:
    return d[0]
"""
        with self.assertRaises((TypecheckError, TypeError)):
            compile_function(src)

    def test_dict_int_key_local(self):
        src = """
def f() -> int:
    d: dict[int, int] = {}
    d[1] = 42
    return d[1]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)


class TestDictLiteral(unittest.TestCase):

    def test_empty_dict_has_newmap(self):
        src = """
def f() -> int:
    d: dict[str, int] = {}
    d["x"] = 1
    return d["x"]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xC8, bc)  # NEWMAP

    def test_nonempty_dict_has_newmap_and_setitem(self):
        src = """
def f() -> int:
    d: dict[str, int] = {"a": 1, "b": 2}
    return d["a"]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xC8, bc)  # NEWMAP
        self.assertIn(0xD0, bc)  # SETITEM

    def test_dict_literal_cfg_ops(self):
        src = """
def f() -> int:
    d: dict[str, int] = {"x": 10}
    return d["x"]
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("NEWMAP", ops)
        self.assertIn("SETITEM", ops)

    def test_heterogeneous_keys_raises(self):
        src = """
def f() -> int:
    d: dict[str, int] = {"a": 1, 2: 3}
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_heterogeneous_values_raises(self):
        src = """
def f() -> int:
    d: dict[str, int] = {"a": 1, "b": True}
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_invalid_key_type_in_literal_raises(self):
        src = """
def f(lst: list[int]) -> int:
    d: dict[list[int], int] = {}
    return 0
"""
        with self.assertRaises((TypecheckError, TypeError)):
            compile_function(src)


class TestDictIndex(unittest.TestCase):

    def test_index_compiles(self):
        src = """
def f(d: dict[str, int]) -> int:
    return d["key"]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCE, bc)  # PICKITEM

    def test_index_result_has_val_type(self):
        src = """
def f(d: dict[str, int]) -> int:
    x: int = d["k"]
    return x
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_index_wrong_key_type_raises(self):
        src = """
def f(d: dict[str, int]) -> int:
    return d[42]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_index_cfg_has_pickitem(self):
        src = """
def f(d: dict[str, int]) -> int:
    return d["k"]
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("PICKITEM", ops)

    def test_index_int_key(self):
        src = """
def f(d: dict[int, str]) -> str:
    return d[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)


class TestDictSetItem(unittest.TestCase):

    def test_setitem_compiles(self):
        src = """
def f() -> int:
    d: dict[str, int] = {}
    d["x"] = 99
    return d["x"]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xD0, bc)  # SETITEM

    def test_setitem_wrong_val_type_raises(self):
        src = """
def f() -> int:
    d: dict[str, int] = {}
    d["x"] = True
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_setitem_wrong_key_type_raises(self):
        src = """
def f() -> int:
    d: dict[str, int] = {}
    d[1] = 42
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestDictLen(unittest.TestCase):

    def test_len_dict_compiles(self):
        src = """
def f(d: dict[str, int]) -> int:
    return len(d)
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCA, bc)  # SIZE

    def test_len_dict_cfg_has_size(self):
        src = """
def f(d: dict[str, int]) -> int:
    return len(d)
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("SIZE", ops)


class TestDictHasKey(unittest.TestCase):

    def test_haskey_compiles(self):
        src = """
def f(d: dict[str, int]) -> bool:
    return "x" in d
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCB, bc)  # HASKEY

    def test_haskey_cfg_op(self):
        src = """
def f(d: dict[str, int]) -> bool:
    return "x" in d
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("HASKEY", ops)

    def test_haskey_wrong_key_type_raises(self):
        src = """
def f(d: dict[str, int]) -> bool:
    return 42 in d
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_haskey_in_if(self):
        src = """
def f(d: dict[str, int]) -> int:
    if "k" in d:
        return 1
    return 0
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCB, bc)  # HASKEY

    def test_haskey_in_while(self):
        src = """
def f(d: dict[str, int]) -> int:
    total: int = 0
    while "k" in d:
        total = total + 1
        break
    return total
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCB, bc)  # HASKEY

    def test_haskey_non_dict_raises(self):
        src = """
def f(lst: list[int]) -> bool:
    return 1 in lst
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


if __name__ == "__main__":
    unittest.main()
