import unittest

from neo3.compiler import TypecheckError, compile_function

_SYSCALL = 0x41
_FIND_HASH = b"\x07\x76\x52\xf3"
_ITER_NEXT_HASH = b"\x9c\x08\xed\x9c"
_ITER_VALUE_HASH = b"\xf3\x54\xbf\x1d"

_FIND_INSTR = bytes([_SYSCALL]) + _FIND_HASH
_ITER_NEXT_INSTR = bytes([_SYSCALL]) + _ITER_NEXT_HASH
_ITER_VALUE_INSTR = bytes([_SYSCALL]) + _ITER_VALUE_HASH

_IMPORT_FIND = "from neo3.sc.storage import find\n"
_IMPORT_FIND_OPTIONS = "from neo3.sc.types import FindOptions\n"
_IMPORT_ITERATOR = "from neo3.sc.utils.iterator import Iterator\n"


class TestStorageFind(unittest.TestCase):

    def test_find_compiles(self):
        src = (
            _IMPORT_FIND
            + _IMPORT_FIND_OPTIONS
            + _IMPORT_ITERATOR
            + "def f(p: bytes) -> Iterator:\n"
            + "    return find(p, FindOptions.KEYS_ONLY)\n"
        )
        self.assertIsInstance(compile_function(src), bytes)

    def test_find_emits_correct_hash(self):
        src = (
            _IMPORT_FIND
            + _IMPORT_FIND_OPTIONS
            + _IMPORT_ITERATOR
            + "def f(p: bytes) -> Iterator:\n"
            + "    return find(p, FindOptions.KEYS_ONLY)\n"
        )
        bc = compile_function(src)
        self.assertIn(_FIND_INSTR, bc)

    def test_find_default_options_compiles(self):
        # find(prefix) with no options arg — default is injected
        src = (
            _IMPORT_FIND
            + _IMPORT_ITERATOR
            + "def f(p: bytes) -> Iterator:\n    return find(p)\n"
        )
        bc = compile_function(src)
        self.assertIn(_FIND_INSTR, bc)

    def test_find_options_keys_only_folds_to_int(self):
        # FindOptions.KEYS_ONLY = 1; should fold and compile without error
        src = (
            _IMPORT_FIND
            + _IMPORT_FIND_OPTIONS
            + _IMPORT_ITERATOR
            + "def f(p: bytes) -> Iterator:\n"
            + "    return find(p, FindOptions.KEYS_ONLY)\n"
        )
        bc = compile_function(src)
        self.assertIn(_FIND_INSTR, bc)

    def test_find_options_values_only_folds(self):
        src = (
            _IMPORT_FIND
            + _IMPORT_FIND_OPTIONS
            + _IMPORT_ITERATOR
            + "def f(p: bytes) -> Iterator:\n"
            + "    return find(p, FindOptions.VALUES_ONLY)\n"
        )
        bc = compile_function(src)
        self.assertIn(_FIND_INSTR, bc)

    def test_find_non_bytes_prefix_raises(self):
        src = (
            _IMPORT_FIND
            + _IMPORT_ITERATOR
            + "def f(p: int) -> Iterator:\n    return find(p)\n"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_find_invalid_options_member_raises(self):
        src = (
            _IMPORT_FIND
            + _IMPORT_FIND_OPTIONS
            + _IMPORT_ITERATOR
            + "def f(p: bytes) -> Iterator:\n"
            + "    return find(p, FindOptions.NONEXISTENT)\n"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)


class TestIteratorNext(unittest.TestCase):

    def test_next_compiles(self):
        src = (
            _IMPORT_FIND
            + _IMPORT_ITERATOR
            + "def f(p: bytes) -> bool:\n"
            + "    it: Iterator = find(p)\n"
            + "    return it.next()\n"
        )
        self.assertIsInstance(compile_function(src), bytes)

    def test_next_emits_correct_hash(self):
        src = (
            _IMPORT_FIND
            + _IMPORT_ITERATOR
            + "def f(p: bytes) -> bool:\n"
            + "    it: Iterator = find(p)\n"
            + "    return it.next()\n"
        )
        bc = compile_function(src)
        self.assertIn(_ITER_NEXT_INSTR, bc)

    def test_next_does_not_emit_find_hash(self):
        src = (
            _IMPORT_ITERATOR
            + "def f(it: Iterator) -> bool:\n"
            + "    return it.next()\n"
        )
        bc = compile_function(src)
        self.assertIn(_ITER_NEXT_INSTR, bc)
        self.assertNotIn(_FIND_HASH, bc)


class TestIteratorValue(unittest.TestCase):

    def test_value_compiles(self):
        src = (
            _IMPORT_FIND
            + _IMPORT_ITERATOR
            + "def f(p: bytes) -> bytes:\n"
            + "    it: Iterator = find(p)\n"
            + "    while it.next():\n"
            + "        return it.value()\n"
            + "    return b''\n"
        )
        self.assertIsInstance(compile_function(src), bytes)

    def test_value_emits_correct_hash(self):
        src = (
            _IMPORT_FIND
            + _IMPORT_ITERATOR
            + "def f(p: bytes) -> bytes:\n"
            + "    it: Iterator = find(p)\n"
            + "    while it.next():\n"
            + "        return it.value()\n"
            + "    return b''\n"
        )
        bc = compile_function(src)
        self.assertIn(_ITER_VALUE_INSTR, bc)

    def test_value_does_not_emit_find_hash(self):
        src = (
            _IMPORT_ITERATOR
            + "def f(it: Iterator) -> bytes:\n"
            + "    return it.value()\n"
        )
        bc = compile_function(src)
        self.assertIn(_ITER_VALUE_INSTR, bc)
        self.assertNotIn(_FIND_HASH, bc)


class TestForIteratorLoop(unittest.TestCase):

    def test_for_loop_compiles(self):
        src = (
            _IMPORT_FIND
            + _IMPORT_FIND_OPTIONS
            + "def f(p: bytes) -> list[bytes]:\n"
            + "    result: list[bytes] = []\n"
            + "    for key in find(p, FindOptions.KEYS_ONLY):\n"
            + "        result.append(key)\n"
            + "    return result\n"
        )
        self.assertIsInstance(compile_function(src), bytes)

    def test_for_loop_emits_all_three_hashes(self):
        src = (
            _IMPORT_FIND
            + _IMPORT_FIND_OPTIONS
            + "def f(p: bytes) -> list[bytes]:\n"
            + "    result: list[bytes] = []\n"
            + "    for key in find(p, FindOptions.KEYS_ONLY):\n"
            + "        result.append(key)\n"
            + "    return result\n"
        )
        bc = compile_function(src)
        self.assertIn(_FIND_INSTR, bc)
        self.assertIn(_ITER_NEXT_INSTR, bc)
        self.assertIn(_ITER_VALUE_INSTR, bc)

    def test_for_loop_default_options(self):
        src = (
            _IMPORT_FIND
            + "def f(p: bytes) -> list[bytes]:\n"
            + "    result: list[bytes] = []\n"
            + "    for item in find(p):\n"
            + "        result.append(item)\n"
            + "    return result\n"
        )
        bc = compile_function(src)
        self.assertIn(_FIND_INSTR, bc)
        self.assertIn(_ITER_NEXT_INSTR, bc)
        self.assertIn(_ITER_VALUE_INSTR, bc)

    def test_manual_while_loop_compiles(self):
        src = (
            _IMPORT_FIND
            + _IMPORT_FIND_OPTIONS
            + _IMPORT_ITERATOR
            + "def f(p: bytes) -> list[bytes]:\n"
            + "    result: list[bytes] = []\n"
            + "    it: Iterator = find(p, FindOptions.KEYS_ONLY)\n"
            + "    while it.next():\n"
            + "        result.append(it.value())\n"
            + "    return result\n"
        )
        bc = compile_function(src)
        self.assertIn(_FIND_INSTR, bc)
        self.assertIn(_ITER_NEXT_INSTR, bc)
        self.assertIn(_ITER_VALUE_INSTR, bc)


if __name__ == "__main__":
    unittest.main()
