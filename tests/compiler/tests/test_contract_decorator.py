import unittest

from neo3.compiler import TypecheckError, compile_function
from neo3 import vm as _neo3_vm
from neo3.core.types import UInt160

_SYSCALL_CONTRACT_CALL = _neo3_vm.Syscalls.get_by_name(
    "System.Contract.Call"
).number.to_bytes(4, "little")
_STDLIB_HASH = UInt160.from_string(
    "0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0"
).to_array()

_CONTRACT_DEF = """\
from typing import Any
from neo3.sc.compiletime import contract
from neo3.sc.types import UInt160

@contract('0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0')
class StdLib:
    hash: UInt160

    @staticmethod
    def serialize(item: Any) -> bytes:
        pass

    @staticmethod
    def deserialize(data: bytes) -> Any:
        pass

    @staticmethod
    def atoi(value: str, base: int) -> int:
        pass

"""


class TestContractDecoratorCompiles(unittest.TestCase):

    def test_single_arg_call_compiles(self):
        src = (
            _CONTRACT_DEF + "def f(x: int) -> bytes:\n    return StdLib.serialize(x)\n"
        )
        self.assertIsInstance(compile_function(src), bytes)

    def test_two_arg_call_compiles(self):
        src = _CONTRACT_DEF + "def f(s: str) -> int:\n    return StdLib.atoi(s, 10)\n"
        self.assertIsInstance(compile_function(src), bytes)

    def test_zero_arg_call_compiles(self):
        src = (
            "from neo3.sc.compiletime import contract\n"
            "from neo3.sc.types import UInt160\n"
            "@contract('0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0')\n"
            "class Foo:\n"
            "    @staticmethod\n"
            "    def ping() -> int:\n"
            "        pass\n"
            "def f() -> int:\n    return Foo.ping()\n"
        )
        self.assertIsInstance(compile_function(src), bytes)

    def test_return_type_any_accepted(self):
        src = (
            _CONTRACT_DEF
            + "from typing import Any\ndef f(d: bytes) -> Any:\n    return StdLib.deserialize(d)\n"
        )
        self.assertIsInstance(compile_function(src), bytes)


class TestContractDecoratorBytecode(unittest.TestCase):

    def _bc(self, body: str) -> bytes:
        return compile_function(_CONTRACT_DEF + body)

    def test_emits_syscall_contract_call(self):
        bc = self._bc("def f(x: int) -> bytes:\n    return StdLib.serialize(x)\n")
        self.assertIn(_SYSCALL_CONTRACT_CALL, bc)

    def test_emits_contract_hash(self):
        bc = self._bc("def f(x: int) -> bytes:\n    return StdLib.serialize(x)\n")
        self.assertIn(_STDLIB_HASH, bc)

    def test_emits_method_name(self):
        bc = self._bc("def f(x: int) -> bytes:\n    return StdLib.serialize(x)\n")
        self.assertIn(b"serialize", bc)

    def test_different_method_name_in_bytecode(self):
        bc = self._bc("def f(s: str) -> int:\n    return StdLib.atoi(s, 10)\n")
        self.assertIn(b"atoi", bc)
        self.assertNotIn(b"serialize", bc)

    def test_does_not_emit_call_l_for_contract_method(self):
        from neo3.compiler import OpCode

        bc = self._bc("def f(x: int) -> bytes:\n    return StdLib.serialize(x)\n")
        self.assertNotIn(bytes([OpCode.CALL_L.value]), bc)


class TestContractDecoratorTypecheck(unittest.TestCase):

    def test_rejects_instance_method(self):
        src = (
            "from neo3.sc.compiletime import contract\n"
            "from neo3.sc.types import UInt160\n"
            "@contract('0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0')\n"
            "class Bad:\n"
            "    def method(self) -> int:\n"
            "        pass\n"
            "def f() -> int:\n    return 0\n"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_rejects_classmethod(self):
        src = (
            "from neo3.sc.compiletime import contract\n"
            "from neo3.sc.types import UInt160\n"
            "@contract('0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0')\n"
            "class Bad:\n"
            "    @classmethod\n"
            "    def method(cls) -> int:\n"
            "        pass\n"
            "def f() -> int:\n    return 0\n"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_rejects_non_pass_body(self):
        src = (
            "from neo3.sc.compiletime import contract\n"
            "from neo3.sc.types import UInt160\n"
            "@contract('0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0')\n"
            "class Bad:\n"
            "    @staticmethod\n"
            "    def method() -> int:\n"
            "        return 42\n"
            "def f() -> int:\n    return 0\n"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_wrong_arg_count_raises(self):
        src = (
            _CONTRACT_DEF
            + "def f(x: int) -> bytes:\n    return StdLib.serialize(x, x)\n"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_unknown_method_raises(self):
        src = (
            _CONTRACT_DEF
            + "def f(x: int) -> bytes:\n    return StdLib.nonexistent(x)\n"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_arg_type_mismatch_raises(self):
        # atoi expects (str, int); passing (int, int) should fail
        src = _CONTRACT_DEF + "def f(x: int) -> int:\n    return StdLib.atoi(x, 10)\n"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_docstring_in_class_allowed(self):
        src = (
            "from neo3.sc.compiletime import contract\n"
            "from neo3.sc.types import UInt160\n"
            "@contract('0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0')\n"
            "class WithDoc:\n"
            "    'A contract wrapper.'\n"
            "    @staticmethod\n"
            "    def method() -> int:\n"
            "        pass\n"
            "def f() -> int:\n    return WithDoc.method()\n"
        )
        self.assertIsInstance(compile_function(src), bytes)


class TestDisplayNameDecorator(unittest.TestCase):

    _GAS_DEF = """\
from neo3.sc.compiletime import contract, display_name

@contract('0xd2a4cff31913016155e38e474a2c06d08be276cf')
class GASInterface:
    @staticmethod
    @display_name('totalSupply')
    def total_supply() -> int:
        pass

    @staticmethod
    def transfer(amount: int) -> bool:
        pass

"""

    def test_display_name_changes_method_string_in_bytecode(self):
        src = (
            self._GAS_DEF + "def f() -> int:\n    return GASInterface.total_supply()\n"
        )
        bc = compile_function(src)
        self.assertIn(b"totalSupply", bc)
        self.assertNotIn(b"total_supply", bc)

    def test_without_display_name_uses_python_name(self):
        src = (
            self._GAS_DEF
            + "def f(a: int) -> bool:\n    return GASInterface.transfer(a)\n"
        )
        bc = compile_function(src)
        self.assertIn(b"transfer", bc)

    def test_display_name_compiles(self):
        src = (
            self._GAS_DEF + "def f() -> int:\n    return GASInterface.total_supply()\n"
        )
        self.assertIsInstance(compile_function(src), bytes)

    def test_display_name_imported_as_alias(self):
        src = (
            "from neo3.sc.compiletime import contract, display_name as dn\n"
            "@contract('0xd2a4cff31913016155e38e474a2c06d08be276cf')\n"
            "class GAS:\n"
            "    @staticmethod\n"
            "    @dn('totalSupply')\n"
            "    def total_supply() -> int:\n"
            "        pass\n"
            "def f() -> int:\n    return GAS.total_supply()\n"
        )
        bc = compile_function(src)
        self.assertIn(b"totalSupply", bc)
        self.assertNotIn(b"total_supply", bc)

    def test_display_name_on_regular_class_raises(self):
        src = (
            "from neo3.sc.compiletime import display_name\n"
            "class Foo:\n"
            "    @staticmethod\n"
            "    @display_name('bar')\n"
            "    def baz() -> int:\n"
            "        return 0\n"
            "def f() -> int:\n    return 0\n"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_display_name_without_arg_raises(self):
        src = (
            "from neo3.sc.compiletime import contract, display_name\n"
            "@contract('0xd2a4cff31913016155e38e474a2c06d08be276cf')\n"
            "class Bad:\n"
            "    @staticmethod\n"
            "    @display_name\n"
            "    def method() -> int:\n"
            "        pass\n"
            "def f() -> int:\n    return 0\n"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_display_name_non_string_arg_raises(self):
        src = (
            "from neo3.sc.compiletime import contract, display_name\n"
            "@contract('0xd2a4cff31913016155e38e474a2c06d08be276cf')\n"
            "class Bad:\n"
            "    @staticmethod\n"
            "    @display_name(42)\n"
            "    def method() -> int:\n"
            "        pass\n"
            "def f() -> int:\n    return 0\n"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)


if __name__ == "__main__":
    unittest.main()
