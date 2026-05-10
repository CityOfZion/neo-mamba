import unittest

from neo3.compiler import TypecheckError, compile_module


class TestGlobalKeyword(unittest.TestCase):

    def test_global_write_compiles(self):
        src = """
x: int = 0

def f() -> int:
    global x
    x = 42
    return x
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_global_emits_stsfld_on_write(self):
        src = """
x: int = 0

def f() -> int:
    global x
    x = 99
    return x
"""
        bc = compile_module(src)
        self.assertIn(0x67, bc)  # STSFLD

    def test_global_emits_ldsfld_on_read(self):
        src = """
x: int = 0

def f() -> int:
    global x
    x = 1
    return x
"""
        bc = compile_module(src)
        self.assertIn(0x5F, bc)  # LDSFLD

    def test_global_mid_function_still_works(self):
        # global declared after some statements — pre-scan means position doesn't matter
        src = """
counter: int = 0

def increment() -> int:
    counter = counter + 1
    global counter
    return counter
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_multiple_globals(self):
        src = """
a: int = 0
b: int = 0

def swap() -> int:
    global a, b
    a = 10
    b = 20
    return a
"""
        self.assertIsInstance(compile_module(src), bytes)

    def test_global_shares_slot_with_static(self):
        # Two functions accessing the same static — one via explicit global
        src = """
total: int = 0

def add(n: int) -> int:
    global total
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

    def test_global_undeclared_name_raises(self):
        src = """
def f() -> int:
    global missing
    return 0
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)

    def test_global_local_only_name_raises(self):
        src = """
def f() -> int:
    global y
    y = 1
    return y
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)
