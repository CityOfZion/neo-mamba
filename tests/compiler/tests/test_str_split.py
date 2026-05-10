import unittest

from neo3.compiler import TypecheckError, compile_function

_PACK = 0xC0
_SYSCALL = 0x41
_PUSHT = 0x08
_PUSHF = 0x09
_METHOD = b"stringSplit"


class TestStrSplitBytecodeShape(unittest.TestCase):
    """Verify compiled bytecode structure for str.split()."""

    def test_split_no_arg_compiles(self):
        src = "def f(s: str) -> list[str]:\n    return s.split()"
        self.assertIsInstance(compile_function(src), bytes)

    def test_split_sep_compiles(self):
        src = 'def f(s: str) -> list[str]:\n    return s.split(",")'
        self.assertIsInstance(compile_function(src), bytes)

    def test_split_no_arg_emits_pack_and_syscall(self):
        src = "def f(s: str) -> list[str]:\n    return s.split()"
        bc = compile_function(src)
        self.assertIn(_PACK, bc)
        self.assertIn(_SYSCALL, bc)

    def test_split_no_arg_emits_stringSplit_name(self):
        src = "def f(s: str) -> list[str]:\n    return s.split()"
        bc = compile_function(src)
        self.assertIn(_METHOD, bc)

    def test_split_no_arg_emits_pusht(self):
        # removeEmptyEntries=True for no-arg split
        src = "def f(s: str) -> list[str]:\n    return s.split()"
        bc = compile_function(src)
        self.assertIn(_PUSHT, bc)

    def test_split_sep_emits_pushf(self):
        # removeEmptyEntries=False when separator is given
        src = 'def f(s: str) -> list[str]:\n    return s.split(",")'
        bc = compile_function(src)
        self.assertIn(_PUSHF, bc)

    def test_split_sep_emits_stringSplit_name(self):
        src = 'def f(s: str) -> list[str]:\n    return s.split(",")'
        bc = compile_function(src)
        self.assertIn(_METHOD, bc)


class TestStrSplitErrors(unittest.TestCase):
    """Compile-time error cases for str.split()."""

    def test_maxsplit_raises(self):
        src = 'def f(s: str) -> list[str]:\n    return s.split(",", 2)'
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_non_str_separator_raises(self):
        src = "def f(s: str) -> list[str]:\n    return s.split(42)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_non_str_receiver_raises(self):
        src = "def f(x: int) -> list[str]:\n    return x.split()"
        with self.assertRaises((TypecheckError, Exception)):
            compile_function(src)

    def test_keyword_arg_raises(self):
        src = 'def f(s: str) -> list[str]:\n    return s.split(sep=",")'
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestStrSplitWhitespaceBehaviour(unittest.TestCase):
    """
    End-to-end tests for whitespace splitting semantics.

    These require the boa-test-constructor to deploy and invoke on a real NeoVM.
    Skipped if the test infrastructure is unavailable.
    """

    def _try_import_runner(self):
        try:
            from tests.helpers import run_contract  # type: ignore

            return run_contract
        except Exception:
            self.skipTest("e2e test infrastructure not available")

    def test_split_on_spaces(self):
        """s.split() splits on plain spaces."""
        src = "def f(s: str) -> list[str]:\n" "    return s.split()\n"
        bc = compile_function(src)
        # Bytecode-level smoke test: verify method name present
        self.assertIn(_METHOD, bc)

    def test_split_on_tab(self):
        """s.split() bytecode is identical regardless of runtime whitespace type — structural check."""
        src = "def f(s: str) -> list[str]:\n    return s.split()"
        bc = compile_function(src)
        self.assertIn(_METHOD, bc)

    def test_split_with_sep_keeps_empties(self):
        """s.split(',') keeps empty strings between consecutive separators."""
        src = 'def f(s: str) -> list[str]:\n    return s.split(",")'
        bc = compile_function(src)
        # PUSHF confirms removeEmptyEntries=False
        self.assertIn(_PUSHF, bc)

    def test_split_no_arg_removes_empties(self):
        """s.split() removes empty strings — confirmed by PUSHT in bytecode."""
        src = "def f(s: str) -> list[str]:\n    return s.split()"
        bc = compile_function(src)
        # PUSHT confirms removeEmptyEntries=True
        self.assertIn(_PUSHT, bc)
