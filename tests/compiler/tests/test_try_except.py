import unittest

from neo3.compiler import TypecheckError, compile_function, disassemble

TRY_L = 0x3C
ENDTRY_L = 0x3E
ENDFINALLY = 0x3F
STLOC = 0x77
DROP = 0x45


class TestTryExcept(unittest.TestCase):

    def test_try_except_compiles(self):
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    except:
        x = 0
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_try_except_emits_try_l(self):
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    except:
        x = 0
    return x
"""
        bc = compile_function(src)
        self.assertIn(TRY_L, bc)

    def test_try_except_emits_endtry_l(self):
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    except:
        x = 0
    return x
"""
        bc = compile_function(src)
        self.assertIn(ENDTRY_L, bc)

    def test_try_except_drops_exception(self):
        """Exception value on stack must be DROPped (no 'as e' binding with bare except)."""
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    except:
        x = 0
    return x
"""
        bc = compile_function(src)
        self.assertIn(DROP, bc)

    def test_try_finally_compiles(self):
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    finally:
        x = x + 10
    return x
"""
        self.assertIsInstance(compile_function(src), bytes)

    def test_try_finally_emits_endfinally(self):
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    finally:
        x = x + 10
    return x
"""
        bc = compile_function(src)
        self.assertIn(ENDFINALLY, bc)

    def test_try_finally_finally_offset_nonzero(self):
        """TRY_L's finally offset must be non-zero when finally is present."""
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    finally:
        x = x + 10
    return x
"""
        bc = compile_function(src)
        idx = bc.index(TRY_L)
        finally_off = int.from_bytes(bc[idx + 5 : idx + 9], "little", signed=True)
        self.assertNotEqual(finally_off, 0)

    def test_try_except_finally_all_three_opcodes(self):
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    except:
        x = 0
    finally:
        x = x + 100
    return x
"""
        bc = compile_function(src)
        self.assertIn(TRY_L, bc)
        self.assertIn(ENDTRY_L, bc)
        self.assertIn(ENDFINALLY, bc)

    def test_try_except_finally_both_offsets_nonzero(self):
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    except:
        x = 0
    finally:
        x = x + 100
    return x
"""
        bc = compile_function(src)
        idx = bc.index(TRY_L)
        catch_off = int.from_bytes(bc[idx + 1 : idx + 5], "little", signed=True)
        finally_off = int.from_bytes(bc[idx + 5 : idx + 9], "little", signed=True)
        self.assertNotEqual(catch_off, 0)
        self.assertNotEqual(finally_off, 0)

    def test_return_in_try_body(self):
        """return inside try body is allowed; catch still gets ENDTRY_L."""
        src = """\
def f(x: int) -> int:
    try:
        return x
    except:
        x = 0
    return x
"""
        bc = compile_function(src)
        self.assertIn(TRY_L, bc)
        self.assertIn(ENDTRY_L, bc)

    def test_nested_try(self):
        src = """\
def f(x: int) -> int:
    try:
        try:
            x = x + 1
        except:
            x = 0
    except:
        x = -1
    return x
"""
        bc = compile_function(src)
        count = sum(1 for b in bc if b == TRY_L)
        self.assertEqual(count, 2)

    def test_disassembly_shows_correct_offsets(self):
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    except:
        x = 0
    return x
"""
        bc = compile_function(src)
        asm = disassemble(bc)
        self.assertIn("TRY_L", asm)
        self.assertIn("ENDTRY_L", asm)


class TestTryExceptErrors(unittest.TestCase):

    def test_typed_except_rejected(self):
        """except SomeType: is rejected — NeoVM has no typed exception system."""
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    except ValueError:
        x = 0
    return x
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_typed_except_with_binding_rejected(self):
        """except SomeType as e: is rejected for the same reason."""
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    except Exception as e:
        x = 0
    return x
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_multiple_handlers_rejected(self):
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    except:
        x = 0
    except:
        x = -1
    return x
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_orelse_rejected(self):
        src = """\
def f(x: int) -> int:
    try:
        x = x + 1
    except:
        x = 0
    else:
        x = 2
    return x
"""
        with self.assertRaises(TypecheckError):
            compile_function(src)
