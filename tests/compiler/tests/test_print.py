import unittest

from neo3.compiler import TypecheckError, _SYSCALL_CONTRACT_CALL, compile_function

_SYSCALL = 0x41
_SYSTEM_RUNTIME_LOG = b"\xcf\xe7\x47\x96"


class TestPrintStr(unittest.TestCase):

    def test_print_str_literal_compiles(self):
        src = 'def f() -> None:\n    print("hello")'
        self.assertIsInstance(compile_function(src), bytes)

    def test_print_emits_syscall_opcode(self):
        src = 'def f() -> None:\n    print("hello")'
        bc = compile_function(src)
        self.assertIn(_SYSCALL, bc)

    def test_print_emits_runtime_log_hash(self):
        src = 'def f() -> None:\n    print("hello")'
        bc = compile_function(src)
        self.assertIn(_SYSTEM_RUNTIME_LOG, bc)

    def test_print_syscall_bytes_sequence(self):
        src = 'def f() -> None:\n    print("hello")'
        bc = compile_function(src)
        syscall_instr = bytes([_SYSCALL]) + _SYSTEM_RUNTIME_LOG
        self.assertIn(syscall_instr, bc)

    def test_print_str_var_compiles(self):
        src = "def f(msg: str) -> None:\n    print(msg)"
        self.assertIsInstance(compile_function(src), bytes)


class TestPrintBytes(unittest.TestCase):

    def test_print_bytes_literal_compiles(self):
        src = 'def f() -> None:\n    print(b"hello")'
        self.assertIsInstance(compile_function(src), bytes)

    def test_print_bytes_var_compiles(self):
        src = "def f(msg: bytes) -> None:\n    print(msg)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_print_bytes_emits_syscall(self):
        src = 'def f() -> None:\n    print(b"hello")'
        bc = compile_function(src)
        syscall_instr = bytes([_SYSCALL]) + _SYSTEM_RUNTIME_LOG
        self.assertIn(syscall_instr, bc)


class TestPrintErrors(unittest.TestCase):

    def test_print_int_arg_raises(self):
        src = "def f(x: int) -> None:\n    print(x)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_print_bool_arg_raises(self):
        src = "def f(x: bool) -> None:\n    print(x)"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_print_no_args_raises(self):
        src = "def f() -> None:\n    print()"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_print_two_args_raises(self):
        src = 'def f() -> None:\n    print("a", "b")'
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_print_result_assigned_raises(self):
        # print() is void; assigning its result is not allowed
        src = 'def f() -> None:\n    x: int = print("hi")'
        with self.assertRaises((TypecheckError, Exception)):
            compile_function(src)


class TestPrintList(unittest.TestCase):

    def test_print_list_compiles(self):
        src = "def f(items: list) -> None:\n    print(items)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_print_list_typed_compiles(self):
        src = "def f(items: list[int]) -> None:\n    print(items)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_print_list_str_compiles(self):
        src = "def f(items: list[str]) -> None:\n    print(items)"
        self.assertIsInstance(compile_function(src), bytes)

    def test_print_list_emits_syscall_runtime_log(self):
        src = "def f(items: list[int]) -> None:\n    print(items)"
        bc = compile_function(src)
        self.assertIn(bytes([_SYSCALL]) + _SYSTEM_RUNTIME_LOG, bc)

    def test_print_list_emits_contract_call(self):
        src = "def f(items: list[int]) -> None:\n    print(items)"
        bc = compile_function(src)
        self.assertIn(_SYSCALL_CONTRACT_CALL, bc)

    def test_print_empty_list_compiles(self):
        src = "def f() -> None:\n    items: list[int] = []\n    print(items)"
        self.assertIsInstance(compile_function(src), bytes)
