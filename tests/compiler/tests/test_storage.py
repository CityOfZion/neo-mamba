import unittest

from neo3.compiler import TypecheckError, compile_function

_SYSCALL = 0x41
_STORAGE_GET_HASH = b"\xd5\x8d\x5e\xe8"
_STORAGE_PUT_HASH = b"\x39\x0c\xe3\x0a"
_STORAGE_DELETE_HASH = b"\x75\x54\xf5\x94"

_STORAGE_GET_INSTR = bytes([_SYSCALL]) + _STORAGE_GET_HASH
_STORAGE_PUT_INSTR = bytes([_SYSCALL]) + _STORAGE_PUT_HASH
_STORAGE_DELETE_INSTR = bytes([_SYSCALL]) + _STORAGE_DELETE_HASH

_IMPORT_DIRECT = "from neo3.sc.storage import get, put, delete\n"
_IMPORT_NS = "import neo3.sc.storage as storage\n"
_IMPORT_OPT = "from typing import Optional\n"


class TestStorageGet(unittest.TestCase):

    def test_get_compiles(self):
        src = (
            _IMPORT_OPT
            + _IMPORT_DIRECT
            + "def f(k: bytes) -> Optional[bytes]:\n    return get(k)"
        )
        self.assertIsInstance(compile_function(src), bytes)

    def test_get_emits_syscall_opcode(self):
        src = (
            _IMPORT_OPT
            + _IMPORT_DIRECT
            + "def f(k: bytes) -> Optional[bytes]:\n    return get(k)"
        )
        bc = compile_function(src)
        self.assertIn(_SYSCALL, bc)

    def test_get_emits_correct_hash(self):
        src = (
            _IMPORT_OPT
            + _IMPORT_DIRECT
            + "def f(k: bytes) -> Optional[bytes]:\n    return get(k)"
        )
        bc = compile_function(src)
        self.assertIn(_STORAGE_GET_HASH, bc)

    def test_get_emits_complete_instruction(self):
        src = (
            _IMPORT_OPT
            + _IMPORT_DIRECT
            + "def f(k: bytes) -> Optional[bytes]:\n    return get(k)"
        )
        bc = compile_function(src)
        self.assertIn(_STORAGE_GET_INSTR, bc)

    def test_get_does_not_emit_put_hash(self):
        src = (
            _IMPORT_OPT
            + _IMPORT_DIRECT
            + "def f(k: bytes) -> Optional[bytes]:\n    return get(k)"
        )
        bc = compile_function(src)
        self.assertNotIn(_STORAGE_PUT_HASH, bc)

    def test_get_does_not_emit_delete_hash(self):
        src = (
            _IMPORT_OPT
            + _IMPORT_DIRECT
            + "def f(k: bytes) -> Optional[bytes]:\n    return get(k)"
        )
        bc = compile_function(src)
        self.assertNotIn(_STORAGE_DELETE_HASH, bc)

    def test_get_via_module_namespace(self):
        src = (
            _IMPORT_OPT
            + _IMPORT_NS
            + "def f(k: bytes) -> Optional[bytes]:\n    return storage.get(k)"
        )
        bc = compile_function(src)
        self.assertIn(_STORAGE_GET_INSTR, bc)

    def test_get_alias_emits_correct_instruction(self):
        src = (
            _IMPORT_OPT
            + "from neo3.sc.storage import get as store_get\n"
            + "def f(k: bytes) -> Optional[bytes]:\n    return store_get(k)"
        )
        bc = compile_function(src)
        self.assertIn(_STORAGE_GET_INSTR, bc)


class TestStoragePut(unittest.TestCase):

    def test_put_compiles(self):
        src = _IMPORT_DIRECT + "def f(k: bytes, v: bytes) -> None:\n    put(k, v)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_put_emits_correct_instruction(self):
        src = _IMPORT_DIRECT + "def f(k: bytes, v: bytes) -> None:\n    put(k, v)"
        bc = compile_function(src)
        self.assertIn(_STORAGE_PUT_INSTR, bc)

    def test_put_does_not_emit_get_hash(self):
        src = _IMPORT_DIRECT + "def f(k: bytes, v: bytes) -> None:\n    put(k, v)"
        bc = compile_function(src)
        self.assertNotIn(_STORAGE_GET_HASH, bc)

    def test_put_via_module_namespace(self):
        src = _IMPORT_NS + "def f(k: bytes, v: bytes) -> None:\n    storage.put(k, v)"
        bc = compile_function(src)
        self.assertIn(_STORAGE_PUT_INSTR, bc)

    def test_put_alias_emits_correct_instruction(self):
        src = (
            "from neo3.sc.storage import put as store_put\n"
            "def f(k: bytes, v: bytes) -> None:\n    store_put(k, v)"
        )
        bc = compile_function(src)
        self.assertIn(_STORAGE_PUT_INSTR, bc)

    def test_put_value_pushed_before_key(self):
        # key arg is LDARG 0, value is LDARG 1
        # Correct stack order: LDARG 1 (value) then LDARG 0 (key) then SYSCALL
        src = _IMPORT_DIRECT + "def f(k: bytes, v: bytes) -> None:\n    put(k, v)"
        bc = compile_function(src)
        idx = bc.index(_STORAGE_PUT_INSTR[0])  # position of SYSCALL byte
        while bc[idx : idx + 5] != _STORAGE_PUT_INSTR:
            idx = bc.index(_STORAGE_PUT_INSTR[0], idx + 1)
        # The two LDARG instructions must appear before the SYSCALL
        LDARG = 0x7F
        ldarg_positions = [i for i, b in enumerate(bc[:idx]) if b == LDARG]
        self.assertGreaterEqual(len(ldarg_positions), 2)
        # Last LDARG before SYSCALL is for key (arg 0), second-to-last is for value (arg 1)
        self.assertEqual(bc[ldarg_positions[-1] + 1], 0)  # key = arg 0
        self.assertEqual(bc[ldarg_positions[-2] + 1], 1)  # value = arg 1


class TestStorageDelete(unittest.TestCase):

    def test_delete_compiles(self):
        src = _IMPORT_DIRECT + "def f(k: bytes) -> None:\n    delete(k)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_delete_emits_correct_instruction(self):
        src = _IMPORT_DIRECT + "def f(k: bytes) -> None:\n    delete(k)"
        bc = compile_function(src)
        self.assertIn(_STORAGE_DELETE_INSTR, bc)

    def test_delete_does_not_emit_get_hash(self):
        src = _IMPORT_DIRECT + "def f(k: bytes) -> None:\n    delete(k)"
        bc = compile_function(src)
        self.assertNotIn(_STORAGE_GET_HASH, bc)

    def test_delete_via_module_namespace(self):
        src = _IMPORT_NS + "def f(k: bytes) -> None:\n    storage.delete(k)"
        bc = compile_function(src)
        self.assertIn(_STORAGE_DELETE_INSTR, bc)

    def test_delete_alias_emits_correct_instruction(self):
        src = (
            "from neo3.sc.storage import delete as store_del\n"
            "def f(k: bytes) -> None:\n    store_del(k)"
        )
        bc = compile_function(src)
        self.assertIn(_STORAGE_DELETE_INSTR, bc)


class TestStorageAllTogether(unittest.TestCase):

    def test_all_three_in_one_function(self):
        src = (
            _IMPORT_OPT
            + _IMPORT_DIRECT
            + "def f(k: bytes, v: bytes) -> Optional[bytes]:\n"
            + "    put(k, v)\n"
            + "    result: Optional[bytes] = get(k)\n"
            + "    delete(k)\n"
            + "    return result\n"
        )
        bc = compile_function(src)
        self.assertIn(_STORAGE_GET_INSTR, bc)
        self.assertIn(_STORAGE_PUT_INSTR, bc)
        self.assertIn(_STORAGE_DELETE_INSTR, bc)

    def test_import_all_three_separate_functions(self):
        src = (
            _IMPORT_OPT
            + _IMPORT_DIRECT
            + "def do_put(k: bytes, v: bytes) -> None:\n    put(k, v)\n"
            + "def do_get(k: bytes) -> Optional[bytes]:\n    return get(k)\n"
            + "def do_delete(k: bytes) -> None:\n    delete(k)\n"
        )
        bc = compile_function(src)
        self.assertIn(_STORAGE_GET_INSTR, bc)
        self.assertIn(_STORAGE_PUT_INSTR, bc)
        self.assertIn(_STORAGE_DELETE_INSTR, bc)


class TestStorageTypeErrors(unittest.TestCase):

    def test_get_int_key_raises(self):
        src = _IMPORT_DIRECT + "def f(k: int) -> bytes:\n    return get(k)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_get_str_key_raises(self):
        src = _IMPORT_DIRECT + "def f(k: str) -> bytes:\n    return get(k)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_put_int_key_raises(self):
        src = _IMPORT_DIRECT + "def f(k: int, v: bytes) -> None:\n    put(k, v)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_put_int_value_raises(self):
        src = _IMPORT_DIRECT + "def f(k: bytes, v: int) -> None:\n    put(k, v)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_put_str_value_raises(self):
        src = _IMPORT_DIRECT + "def f(k: bytes, v: str) -> None:\n    put(k, v)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_delete_int_key_raises(self):
        src = _IMPORT_DIRECT + "def f(k: int) -> None:\n    delete(k)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_get_wrong_arg_count_raises(self):
        src = (
            _IMPORT_DIRECT
            + "def f(k: bytes, k2: bytes) -> bytes:\n    return get(k, k2)"
        )
        with self.assertRaises((TypecheckError, Exception)):
            compile_function(src)

    def test_put_missing_value_raises(self):
        src = _IMPORT_DIRECT + "def f(k: bytes) -> None:\n    put(k)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_delete_too_many_args_raises(self):
        src = _IMPORT_DIRECT + "def f(k: bytes, k2: bytes) -> None:\n    delete(k, k2)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_get_as_statement_raises(self):
        src = _IMPORT_DIRECT + "def f(k: bytes) -> None:\n    get(k)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_put_as_expression_raises(self):
        src = (
            _IMPORT_DIRECT + "def f(k: bytes, v: bytes) -> bytes:\n    return put(k, v)"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_delete_as_expression_raises(self):
        src = _IMPORT_DIRECT + "def f(k: bytes) -> bytes:\n    return delete(k)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_import_invalid_name_raises(self):
        src = "from neo3.sc.storage import nonexistent\ndef f() -> None:\n    pass"
        with self.assertRaises(TypecheckError):
            compile_function(src)


if __name__ == "__main__":
    unittest.main()
