"""P4-15: Unit tests for NEF and manifest generation via compile_to_nef."""

import hashlib
import json
import os
import tempfile
import unittest

from neo3.compiler import compile_to_nef

# Minimal contract with one @public method and one @public(safe=True) method.
_SRC = """
from neo3.sc.compiletime import public

@public
def add(a: int, b: int) -> int:
    return a + b

@public(safe=True)
def safe_get(x: int) -> int:
    return x
"""

_SRC_VOID = """
from neo3.sc.compiletime import public

@public
def reset() -> None:
    return
"""


def _write_contract(src: str, stem: str = "contract") -> tuple[bytes, dict]:
    """Compile *src* via compile_to_nef and return (nef_bytes, manifest_dict)."""
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, f"{stem}.nef")
        compile_to_nef(src, out)
        with open(out, "rb") as f:
            nef_bytes = f.read()
        with open(os.path.join(d, f"{stem}.manifest.json"), encoding="utf-8") as f:
            manifest = json.load(f)
    return nef_bytes, manifest


class TestNefMagic(unittest.TestCase):
    """NEF binary layout checks."""

    def setUp(self):
        self.nef_bytes, _ = _write_contract(_SRC)

    def test_magic_bytes(self):
        # NEF3 magic = 0x3346454E (little-endian) → bytes 4e 45 46 33
        self.assertEqual(self.nef_bytes[:4], bytes.fromhex("4e454633"))

    def test_checksum_valid(self):
        # Last 4 bytes are double-SHA256 of everything before them.
        body = self.nef_bytes[:-4]
        expected = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
        self.assertEqual(self.nef_bytes[-4:], expected)

    def test_nef_is_bytes(self):
        self.assertIsInstance(self.nef_bytes, bytes)

    def test_minimum_length(self):
        # magic(4) + compiler(64) + source(var≥1) + reserved(1) +
        # tokens(var≥1) + reserved2(2) + script(var≥1) + checksum(4) ≥ 79
        self.assertGreaterEqual(len(self.nef_bytes), 79)


class TestManifestStructure(unittest.TestCase):
    """Manifest JSON structure checks."""

    def setUp(self):
        _, self.manifest = _write_contract(_SRC, stem="my_contract")

    def test_name_matches_stem(self):
        self.assertEqual(self.manifest["name"], "my_contract")

    def test_abi_present(self):
        self.assertIn("abi", self.manifest)

    def test_methods_list_present(self):
        self.assertIn("methods", self.manifest["abi"])

    def test_method_names_present(self):
        names = {m["name"] for m in self.manifest["abi"]["methods"]}
        self.assertIn("add", names)
        self.assertIn("safe_get", names)

    def test_add_has_correct_offset(self):
        add_m = next(m for m in self.manifest["abi"]["methods"] if m["name"] == "add")
        self.assertEqual(add_m["offset"], 0)

    def test_safe_get_offset_after_add(self):
        add_m = next(m for m in self.manifest["abi"]["methods"] if m["name"] == "add")
        safe_m = next(
            m for m in self.manifest["abi"]["methods"] if m["name"] == "safe_get"
        )
        self.assertGreater(safe_m["offset"], add_m["offset"])

    def test_add_parameters(self):
        add_m = next(m for m in self.manifest["abi"]["methods"] if m["name"] == "add")
        params = add_m["parameters"]
        self.assertEqual(len(params), 2)
        self.assertEqual(params[0]["name"], "a")
        self.assertEqual(params[0]["type"], "Integer")
        self.assertEqual(params[1]["name"], "b")
        self.assertEqual(params[1]["type"], "Integer")

    def test_add_return_type(self):
        add_m = next(m for m in self.manifest["abi"]["methods"] if m["name"] == "add")
        self.assertEqual(add_m["returntype"], "Integer")

    def test_safe_true_marker(self):
        safe_m = next(
            m for m in self.manifest["abi"]["methods"] if m["name"] == "safe_get"
        )
        self.assertTrue(safe_m["safe"])

    def test_non_safe_method_not_marked_safe(self):
        add_m = next(m for m in self.manifest["abi"]["methods"] if m["name"] == "add")
        self.assertFalse(add_m.get("safe", False))


class TestManifestVoidReturn(unittest.TestCase):
    """Void return type in manifest."""

    def test_void_return_type(self):
        _, manifest = _write_contract(_SRC_VOID)
        reset_m = next(m for m in manifest["abi"]["methods"] if m["name"] == "reset")
        self.assertEqual(reset_m["returntype"], "Void")

    def test_void_no_parameters(self):
        _, manifest = _write_contract(_SRC_VOID)
        reset_m = next(m for m in manifest["abi"]["methods"] if m["name"] == "reset")
        self.assertEqual(reset_m["parameters"], [])


class TestNefOutputFiles(unittest.TestCase):
    """Verify both output files are created."""

    def test_both_files_created(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "c.nef")
            compile_to_nef(_SRC, out)
            self.assertTrue(os.path.exists(out))
            self.assertTrue(os.path.exists(os.path.join(d, "c.manifest.json")))


class TestSafePublicWriteCheck(unittest.TestCase):
    """@public(safe=True) functions must not call state-modifying storage operations."""

    _IMPORTS = (
        "from neo3.sc.compiletime import public\n"
        "from neo3.sc.storage import put, delete\n"
    )

    def _compile(self, src: str) -> bytes:
        from neo3.compiler import compile_function

        return compile_function(src)

    def test_safe_with_storage_put_raises(self):
        from neo3.compiler import TypecheckError

        src = (
            self._IMPORTS + "@public(safe=True)\n"
            "def f(k: bytes, v: bytes) -> None:\n"
            "    put(k, v)\n"
        )
        with self.assertRaises(TypecheckError) as ctx:
            self._compile(src)
        self.assertIn("safe=True", str(ctx.exception))
        self.assertIn("storage.put", str(ctx.exception))
        self.assertIn("safe=False", str(ctx.exception))

    def test_safe_with_storage_delete_raises(self):
        from neo3.compiler import TypecheckError

        src = (
            self._IMPORTS + "@public(safe=True)\n"
            "def f(k: bytes) -> None:\n"
            "    delete(k)\n"
        )
        with self.assertRaises(TypecheckError) as ctx:
            self._compile(src)
        self.assertIn("storage.delete", str(ctx.exception))

    def test_safe_transitive_write_raises(self):
        from neo3.compiler import TypecheckError

        src = (
            self._IMPORTS + "def helper(k: bytes, v: bytes) -> None:\n"
            "    put(k, v)\n"
            "@public(safe=True)\n"
            "def f(k: bytes, v: bytes) -> None:\n"
            "    helper(k, v)\n"
        )
        with self.assertRaises(TypecheckError):
            self._compile(src)

    def test_safe_readonly_does_not_raise(self):
        src = (
            "from typing import Optional\n"
            "from neo3.sc.compiletime import public\n"
            "from neo3.sc.storage import get\n"
            "@public(safe=True)\n"
            "def f(k: bytes) -> Optional[bytes]:\n"
            "    return get(k)\n"
        )
        self.assertIsInstance(self._compile(src), bytes)

    def test_non_safe_with_storage_put_does_not_raise(self):
        src = (
            self._IMPORTS + "@public\n"
            "def f(k: bytes, v: bytes) -> None:\n"
            "    put(k, v)\n"
        )
        self.assertIsInstance(self._compile(src), bytes)

    def test_io_error_on_unwritable_nef(self):
        with self.assertRaises(OSError):
            compile_to_nef(_SRC, "/no/such/dir/out.nef")
