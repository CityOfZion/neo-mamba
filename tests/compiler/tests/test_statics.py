import unittest

from neo3.compiler import TypecheckError, compile_function, compile_module


class TestStaticFieldBytecode(unittest.TestCase):

    def test_initsslot_present(self):
        src = """
count: int = 0

def f() -> int:
    return count
"""
        bc = compile_module(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x56, bc)  # INITSSLOT

    def test_no_statics_no_initsslot(self):
        src = """
def f() -> int:
    x: int = 1
    return x
"""
        bc = compile_function(src)
        self.assertNotIn(0x56, bc)  # no INITSSLOT

    def test_ldsfld_on_read(self):
        src = """
total: int = 0

def f() -> int:
    return total
"""
        bc = compile_module(src)
        self.assertIn(0x5F, bc)  # LDSFLD

    def test_stsfld_on_write(self):
        src = """
total: int = 0

def f() -> int:
    total = 42
    return total
"""
        bc = compile_module(src)
        self.assertIn(0x67, bc)  # STSFLD


class TestStaticFieldTypes(unittest.TestCase):

    def test_static_int(self):
        src = """
count: int = 0

def increment() -> int:
    count = count + 1
    return count
"""
        bc = compile_module(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x56, bc)  # INITSSLOT

    def test_static_str(self):
        src = """
name: str = "hello"

def get_name() -> str:
    return name
"""
        bc = compile_module(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x56, bc)  # INITSSLOT

    def test_static_bool(self):
        src = """
flag: bool = False

def get_flag() -> bool:
    return flag
"""
        bc = compile_module(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x56, bc)  # INITSSLOT

    def test_static_no_initializer(self):
        # bare annotation without value — not currently supported inside functions,
        # but at module level we skip if value is None
        # (currently compile_module only registers statics with value)
        # Test that a static with initializer compiles fine
        src = """
count: int = 0

def f() -> int:
    return count
"""
        bc = compile_module(src)
        self.assertIsInstance(bc, bytes)


class TestStaticFieldSharing(unittest.TestCase):

    def test_two_functions_share_static(self):
        src = """
total: int = 0

def add(n: int) -> int:
    total = total + n
    return total

def get() -> int:
    return total
"""
        bc = compile_module(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x56, bc)  # INITSSLOT
        self.assertIn(0x5F, bc)  # LDSFLD
        self.assertIn(0x67, bc)  # STSFLD

    def test_multiple_statics(self):
        src = """
a: int = 1
b: int = 2

def f() -> int:
    return a + b
"""
        bc = compile_module(src)
        self.assertIsInstance(bc, bytes)
        # INITSSLOT operand should be 2
        idx = bc.index(0x56)
        self.assertEqual(bc[idx + 1], 2)


class TestStaticFieldErrors(unittest.TestCase):

    def test_redeclare_static_as_local_raises(self):
        src = """
count: int = 0

def f() -> int:
    count: int = 5
    return count
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)

    def test_static_wrong_type_raises(self):
        src = """
count: int = 0

def f() -> int:
    count = True
    return count
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)

    def test_non_literal_initializer_raises(self):
        # We can't have an expression as a static initializer, only literals
        src = """
a: int = 1
b: int = a + 1

def f() -> int:
    return b
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)


class TestStaticFieldCFG(unittest.TestCase):

    def test_cfg_has_ldsfld(self):
        # Build CFG directly to check ops — requires passing statics to HIRBuilder
        # We use compile_module to verify end-to-end; CFG helper doesn't support statics
        src = """
x: int = 0

def f() -> int:
    return x
"""
        bc = compile_module(src)
        self.assertIn(0x5F, bc)  # LDSFLD

    def test_cfg_has_stsfld(self):
        src = """
x: int = 0

def f() -> int:
    x = 7
    return x
"""
        bc = compile_module(src)
        self.assertIn(0x67, bc)  # STSFLD


if __name__ == "__main__":
    unittest.main()
