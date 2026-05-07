import unittest

from neo3.compiler import TypecheckError, compile_function

from tests.compiler.tests.helpers import _build_cfg


class TestListType(unittest.TestCase):

    def test_list_int_annotation(self):
        src = """
def f(lst: list[int]) -> int:
    return lst[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_list_bool_annotation(self):
        src = """
def f(lst: list[bool]) -> bool:
    return lst[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_list_str_annotation(self):
        src = """
def f(lst: list[str]) -> str:
    return lst[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_list_bytes_annotation(self):
        src = """
def f(lst: list[bytes]) -> bytes:
    return lst[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)


class TestListLiteral(unittest.TestCase):

    def test_list_literal_compiles(self):
        src = """
def f() -> int:
    lst: list[int] = [1, 2, 3]
    return lst[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xC2, bc)  # NEWARRAY0

    def test_list_literal_has_append(self):
        src = """
def f() -> int:
    lst: list[int] = [1, 2, 3]
    return lst[0]
"""
        bc = compile_function(src)
        self.assertIn(0xCF, bc)  # APPEND

    def test_empty_list_with_annotation(self):
        src = """
def f() -> int:
    lst: list[int] = []
    lst.append(42)
    return lst[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xC2, bc)  # NEWARRAY0

    def test_heterogeneous_list_raises(self):
        src = """
def f() -> int:
    lst: list[int] = [1, True]
    return lst[0]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_list_literal_cfg_ops(self):
        src = """
def f() -> int:
    lst: list[int] = [10, 20]
    return lst[0]
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("NEWARRAY0", ops)
        self.assertIn("APPEND", ops)


class TestListAppend(unittest.TestCase):

    def test_append_compiles(self):
        src = """
def f() -> int:
    lst: list[int] = []
    lst.append(7)
    return lst[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCF, bc)  # APPEND

    def test_append_wrong_type_raises(self):
        src = """
def f() -> int:
    lst: list[int] = []
    lst.append(True)
    return lst[0]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_append_on_non_list_raises(self):
        src = """
def f(b: bytes) -> int:
    b.append(1)
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestListIndex(unittest.TestCase):

    def test_index_compiles(self):
        src = """
def f(lst: list[int]) -> int:
    return lst[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCE, bc)  # PICKITEM

    def test_index_result_has_elem_type(self):
        src = """
def f(lst: list[int]) -> int:
    x: int = lst[2]
    return x
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_index_result_bool_elem(self):
        src = """
def f(lst: list[bool]) -> bool:
    return lst[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_index_non_int_index_raises(self):
        src = """
def f(lst: list[int]) -> int:
    return lst[True]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_index_cfg_has_pickitem(self):
        src = """
def f(lst: list[int]) -> int:
    return lst[0]
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("PICKITEM", ops)


class TestListSetItem(unittest.TestCase):

    def test_setitem_compiles(self):
        src = """
def f() -> int:
    lst: list[int] = [1, 2, 3]
    lst[0] = 99
    return lst[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xD0, bc)  # SETITEM

    def test_setitem_wrong_type_raises(self):
        src = """
def f() -> int:
    lst: list[int] = [1, 2]
    lst[0] = True
    return lst[0]
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestListLen(unittest.TestCase):

    def test_len_list_compiles(self):
        src = """
def f(lst: list[int]) -> int:
    return len(lst)
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCA, bc)  # SIZE

    def test_len_list_cfg_has_size(self):
        src = """
def f(lst: list[int]) -> int:
    return len(lst)
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("SIZE", ops)


class TestListForLoop(unittest.TestCase):

    def test_for_list_compiles(self):
        src = """
def f(lst: list[int]) -> int:
    total: int = 0
    for x in lst:
        total = total + x
    return total
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_for_list_cfg_has_pickitem(self):
        src = """
def f(lst: list[int]) -> int:
    total: int = 0
    for x in lst:
        total = total + x
    return total
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("PICKITEM", ops)

    def test_for_non_list_raises(self):
        src = """
def f(n: int) -> int:
    total: int = 0
    for x in n:
        total = total + x
    return total
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_for_list_bool_elem(self):
        src = """
def f(lst: list[bool]) -> bool:
    result: bool = False
    for x in lst:
        result = x
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)


if __name__ == "__main__":
    unittest.main()
