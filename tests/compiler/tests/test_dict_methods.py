import unittest

from neo3.compiler import TypecheckError, compile_function

from tests.compiler.tests.helpers import _build_cfg


class TestDictKeys(unittest.TestCase):

    def test_keys_compiles(self):
        src = """
def f(d: dict[int, str]) -> int:
    keys: list[int] = d.keys()
    return keys[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCC, bc)  # KEYS

    def test_keys_cfg_op(self):
        src = """
def f(d: dict[int, str]) -> int:
    keys: list[int] = d.keys()
    return keys[0]
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("KEYS", ops)

    def test_keys_result_is_list_of_key_type(self):
        src = """
def f(d: dict[int, str]) -> int:
    keys: list[int] = d.keys()
    return keys[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_keys_len(self):
        src = """
def f(d: dict[str, int]) -> int:
    return len(d.keys())
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCC, bc)  # KEYS
        self.assertIn(0xCA, bc)  # SIZE

    def test_for_keys(self):
        src = """
def f(d: dict[str, int]) -> int:
    total: int = 0
    for k in d.keys():
        total = total + 1
    return total
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCC, bc)  # KEYS

    def test_for_keys_cfg_has_pickitem(self):
        src = """
def f(d: dict[str, int]) -> int:
    total: int = 0
    for k in d.keys():
        total = total + 1
    return total
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("KEYS", ops)
        self.assertIn("PICKITEM", ops)  # indexing into the keys array


class TestDictValues(unittest.TestCase):

    def test_values_compiles(self):
        src = """
def f(d: dict[str, int]) -> int:
    vals: list[int] = d.values()
    return vals[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCD, bc)  # VALUES

    def test_values_cfg_op(self):
        src = """
def f(d: dict[str, int]) -> int:
    vals: list[int] = d.values()
    return vals[0]
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("VALUES", ops)

    def test_values_result_is_list_of_val_type(self):
        src = """
def f(d: dict[int, str]) -> str:
    vals: list[str] = d.values()
    return vals[0]
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_values_len(self):
        src = """
def f(d: dict[str, int]) -> int:
    return len(d.values())
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCD, bc)  # VALUES
        self.assertIn(0xCA, bc)  # SIZE

    def test_for_values(self):
        src = """
def f(d: dict[str, int]) -> int:
    total: int = 0
    for v in d.values():
        total = total + v
    return total
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCD, bc)  # VALUES

    def test_for_values_cfg_has_pickitem(self):
        src = """
def f(d: dict[str, int]) -> int:
    total: int = 0
    for v in d.values():
        total = total + v
    return total
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("VALUES", ops)
        self.assertIn("PICKITEM", ops)


class TestDictItems(unittest.TestCase):

    def test_items_compiles(self):
        src = """
def f(d: dict[str, int]) -> int:
    total: int = 0
    for k, v in d.items():
        total = total + v
    return total
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCC, bc)  # KEYS (items desugars via keys)
        self.assertIn(0xCE, bc)  # PICKITEM

    def test_items_cfg_ops(self):
        src = """
def f(d: dict[str, int]) -> int:
    total: int = 0
    for k, v in d.items():
        total = total + v
    return total
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("KEYS", ops)
        self.assertIn("PICKITEM", ops)

    def test_items_key_var_has_key_type(self):
        src = """
def f(d: dict[str, int]) -> str:
    result: str = "none"
    for k, v in d.items():
        result = k
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_items_val_var_has_val_type(self):
        src = """
def f(d: dict[str, int]) -> int:
    result: int = 0
    for k, v in d.items():
        result = v
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_items_non_dict_raises(self):
        src = """
def f(lst: list[int]) -> int:
    total: int = 0
    for k, v in lst.items():
        total = total + v
    return total
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_items_wrong_tuple_size_raises(self):
        src = """
def f(d: dict[str, int]) -> int:
    total: int = 0
    for k, v, w in d.items():
        total = total + v
    return total
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_items_with_break(self):
        src = """
def f(d: dict[str, int]) -> int:
    result: int = 0
    for k, v in d.items():
        result = v
        break
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)

    def test_items_int_key(self):
        src = """
def f(d: dict[int, str]) -> str:
    result: str = "x"
    for k, v in d.items():
        result = v
    return result
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCC, bc)  # KEYS


class TestDictGet(unittest.TestCase):

    def test_get_with_default_compiles(self):
        src = """
def f(d: dict[str, int]) -> int:
    return d.get("k", 0)
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCB, bc)  # HASKEY
        self.assertIn(0xCE, bc)  # PICKITEM

    def test_get_with_default_cfg_ops(self):
        src = """
def f(d: dict[str, int]) -> int:
    return d.get("k", 0)
"""
        cfg = _build_cfg(src)
        ops = [i.op for b in cfg.blocks.values() for i in b.instructions]
        self.assertIn("HASKEY", ops)
        self.assertIn("PICKITEM", ops)
        self.assertIn("OVER", ops)
        self.assertIn("DROP", ops)

    def test_get_without_default_compiles(self):
        src = """
def f(d: dict[str, int]) -> int:
    v = d.get("k")
    if v is None:
        return -1
    return v
"""
        bc = compile_function(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0xCB, bc)  # HASKEY

    def test_get_key_type_mismatch_raises(self):
        src = """
def f(d: dict[str, int]) -> int:
    return d.get(1, 0)
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_get_default_type_mismatch_raises(self):
        src = """
def f(d: dict[str, int]) -> int:
    return d.get("k", "not an int")
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_get_too_many_args_raises(self):
        src = """
def f(d: dict[str, int]) -> int:
    return d.get("k", 0, 1)
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_get_no_args_raises(self):
        src = """
def f(d: dict[str, int]) -> int:
    return d.get()
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_get_on_non_dict_raises(self):
        src = """
def f(n: int) -> int:
    return n.get(1, 0)
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestDictMethodErrors(unittest.TestCase):

    def test_unknown_method_raises(self):
        src = """
def f(d: dict[str, int]) -> int:
    return d.pop()
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_method_on_non_dict_raises(self):
        src = """
def f(n: int) -> int:
    return n.keys()
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_tuple_target_without_items_raises(self):
        src = """
def f(lst: list[int]) -> int:
    total: int = 0
    for k, v in lst:
        total = total + 1
    return total
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)


if __name__ == "__main__":
    unittest.main()
