import unittest

from neo3.compiler import TypecheckError, compile_function

from tests.compiler.tests.helpers import _build_cfg

_CONVERT = 0xDB
_CAT = 0x8B
_SYSCALL = 0x41  # contract_call (itoa uses this)


class TestStrBool(unittest.TestCase):
    """str(bool) now produces 'True'/'False' strings — Python semantics."""

    def test_str_true_compiles(self):
        src = "def f() -> str:\n    return str(True)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_str_false_compiles(self):
        src = "def f() -> str:\n    return str(False)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_str_bool_arg_compiles(self):
        src = "def f(b: bool) -> str:\n    return str(b)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_str_bool_does_not_emit_convert(self):
        src = "def f(b: bool) -> str:\n    return str(b)"
        bc = compile_function(src)
        self.assertNotIn(_CONVERT, bc)

    def test_str_bool_cfg_has_two_branches(self):
        cfg = _build_cfg("def f(b: bool) -> str:\n    return str(b)")
        # IfExp produces a tern_then and tern_else block
        labels = list(cfg.blocks.keys())
        tern_blocks = [l for l in labels if "tern" in l]
        self.assertGreaterEqual(len(tern_blocks), 2)


class TestFStringCompiles(unittest.TestCase):

    def test_empty_fstring(self):
        src = 'def f() -> str:\n    return f""'
        self.assertIsInstance(compile_function(src), bytes)

    def test_fstring_literal_only(self):
        src = 'def f() -> str:\n    return f"hello"'
        self.assertIsInstance(compile_function(src), bytes)

    def test_fstring_single_str_var(self):
        src = 'def f(s: str) -> str:\n    return f"{s}"'
        self.assertIsInstance(compile_function(src), bytes)

    def test_fstring_str_prefix(self):
        src = 'def f(s: str) -> str:\n    return f"hello {s}"'
        self.assertIsInstance(compile_function(src), bytes)

    def test_fstring_int_var(self):
        src = 'def f(n: int) -> str:\n    return f"n={n}"'
        self.assertIsInstance(compile_function(src), bytes)

    def test_fstring_bool_var(self):
        src = 'def f(flag: bool) -> str:\n    return f"{flag}"'
        self.assertIsInstance(compile_function(src), bytes)

    def test_fstring_multi_str(self):
        src = 'def f(a: str, b: str, c: str) -> str:\n    return f"{a} + {b} = {c}"'
        self.assertIsInstance(compile_function(src), bytes)

    def test_fstring_s_conversion_allowed(self):
        src = 'def f(s: str) -> str:\n    return f"{s!s}"'
        self.assertIsInstance(compile_function(src), bytes)


class TestFStringOpcodes(unittest.TestCase):

    def test_fstring_str_var_emits_cat(self):
        bc = compile_function('def f(s: str) -> str:\n    return f"hello {s}"')
        self.assertIn(_CAT, bc)

    def test_fstring_int_var_emits_syscall(self):
        # int interpolation calls StdLib itoa via contract_call (SYSCALL)
        bc = compile_function('def f(n: int) -> str:\n    return f"n={n}"')
        self.assertIn(_SYSCALL, bc)

    def test_fstring_bool_var_no_convert(self):
        bc = compile_function('def f(flag: bool) -> str:\n    return f"{flag}"')
        self.assertNotIn(_CONVERT, bc)

    def test_fstring_bool_var_has_ternary_blocks(self):
        cfg = _build_cfg('def f(flag: bool) -> str:\n    return f"{flag}"')
        labels = list(cfg.blocks.keys())
        tern_blocks = [l for l in labels if "tern" in l]
        self.assertGreaterEqual(len(tern_blocks), 2)

    def test_fstring_multi_str_emits_multiple_cats(self):
        bc = compile_function(
            'def f(a: str, b: str, c: str) -> str:\n    return f"{a} and {b} = {c}"'
        )
        self.assertGreaterEqual(bc.count(_CAT), 3)


class TestFStringErrors(unittest.TestCase):

    def test_format_spec_raises(self):
        src = 'def f(n: int) -> str:\n    return f"{n:08d}"'
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_r_conversion_raises(self):
        src = 'def f(s: str) -> str:\n    return f"{s!r}"'
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_a_conversion_raises(self):
        src = 'def f(s: str) -> str:\n    return f"{s!a}"'
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_bytes_interpolation_raises(self):
        src = 'def f(b: bytes) -> str:\n    return f"{b}"'
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_bytearray_interpolation_raises(self):
        src = 'def f(b: bytearray) -> str:\n    return f"{b}"'
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_list_interpolation_raises(self):
        src = 'def f(xs: list[str]) -> str:\n    return f"{xs}"'
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_optional_interpolation_raises(self):
        from typing import Optional

        src = (
            "from typing import Optional\n"
            "def f(s: Optional[str]) -> str:\n"
            '    return f"{s}"'
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)
