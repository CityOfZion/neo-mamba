import unittest

from neo3.compiler import TypecheckError, compile_function


class TestTypeInferenceCompiles(unittest.TestCase):

    def test_infer_int_literal(self):
        src = "def f() -> int:\n    x = 5\n    return x\n"
        self.assertIsInstance(compile_function(src), bytes)

    def test_infer_bool_literal(self):
        src = "def f() -> bool:\n    x = True\n    return x\n"
        self.assertIsInstance(compile_function(src), bytes)

    def test_infer_bytes_literal(self):
        src = "def f() -> bytes:\n    x = b'hi'\n    return x\n"
        self.assertIsInstance(compile_function(src), bytes)

    def test_infer_str_literal(self):
        src = "def f() -> str:\n    x = 'hello'\n    return x\n"
        self.assertIsInstance(compile_function(src), bytes)

    def test_infer_from_call_return_type(self):
        src = (
            "def g() -> int:\n    return 42\n"
            "def f() -> int:\n    x = g()\n    return x\n"
        )
        self.assertIsInstance(compile_function(src), bytes)

    def test_infer_from_binop(self):
        src = "def f(a: int, b: int) -> int:\n    x = a + b\n    return x\n"
        self.assertIsInstance(compile_function(src), bytes)

    def test_infer_empty_list(self):
        src = "def f() -> int:\n" "    x = []\n" "    x.append(1)\n" "    return 0\n"
        self.assertIsInstance(compile_function(src), bytes)

    def test_infer_empty_dict(self):
        src = "def f() -> int:\n" "    x = {}\n" "    return 0\n"
        self.assertIsInstance(compile_function(src), bytes)

    def test_explicit_annotation_still_works(self):
        src = "def f() -> int:\n    x: int = 5\n    return x\n"
        self.assertIsInstance(compile_function(src), bytes)

    def test_reassignment_same_type_compiles(self):
        src = "def f() -> int:\n    x = 5\n    x = 3\n    return x\n"
        self.assertIsInstance(compile_function(src), bytes)

    def test_infer_from_local(self):
        src = "def f(a: int) -> int:\n    x = a\n    return x\n"
        self.assertIsInstance(compile_function(src), bytes)


class TestTypeInferenceErrors(unittest.TestCase):

    def test_none_assignment_raises(self):
        src = "def f() -> int:\n    x = None\n    return 0\n"
        with self.assertRaises(TypecheckError) as ctx:
            compile_function(src)
        self.assertIn("Optional", str(ctx.exception))

    def test_reassignment_type_mismatch_raises(self):
        src = "def f() -> int:\n    x = 5\n    x = 'hello'\n    return x\n"
        with self.assertRaises(TypecheckError):
            compile_function(src)

    def test_inferred_type_used_for_subsequent_check(self):
        # x inferred as int; passing it where str expected should error
        src = (
            "def g(s: str) -> str:\n    return s\n"
            "def f() -> str:\n    x = 5\n    return g(x)\n"
        )
        with self.assertRaises(TypecheckError):
            compile_function(src)


if __name__ == "__main__":
    unittest.main()
