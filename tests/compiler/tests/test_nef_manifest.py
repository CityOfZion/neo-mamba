"""P4-15: Unit tests for NEF and manifest generation via compile_to_nef."""

import hashlib
import json
import os
import tempfile
import unittest

from neo3.compiler import compile_to_nef, CompilerWarning

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
        src_path = os.path.join(d, f"{stem}.py")
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(src)
        compile_to_nef(src_path)
        with open(os.path.join(d, f"{stem}.nef"), "rb") as f:
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
            src_path = os.path.join(d, "c.py")
            with open(src_path, "w", encoding="utf-8") as f:
                f.write(_SRC)
            compile_to_nef(src_path)
            self.assertTrue(os.path.exists(os.path.join(d, "c.nef")))
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
        with tempfile.TemporaryDirectory() as d:
            src_path = os.path.join(d, "out.py")
            with open(src_path, "w", encoding="utf-8") as f:
                f.write(_SRC)
            with self.assertRaises(OSError):
                compile_to_nef(src_path, output_dir="/no/such/dir")


class TestContractManifestOverride(unittest.TestCase):
    """ContractManifest(...) call overrides manifest fields in compile_to_nef output."""

    def _compile(self, src: str) -> dict:
        _, manifest = _write_contract(src)
        return manifest

    def test_name_override(self):
        src = """
from neo3.sc.compiletime import public, ContractManifest
ContractManifest(name="MyToken")
@public
def x() -> int:
    return 1
"""
        manifest = self._compile(src)
        self.assertEqual(manifest["name"], "MyToken")

    def test_supported_standards(self):
        src = """
from neo3.sc.compiletime import public, ContractManifest
ContractManifest(supported_standards=["NEP-17", "NEP-11"])
@public
def x() -> int:
    return 1
"""
        manifest = self._compile(src)
        self.assertEqual(manifest["supportedstandards"], ["NEP-17", "NEP-11"])

    def test_permissions_wildcard(self):
        src = """
from neo3.sc.compiletime import public, ContractManifest, Permission
ContractManifest(permissions=[Permission(contract="*", methods="*")])
@public
def x() -> int:
    return 1
"""
        manifest = self._compile(src)
        perms = manifest["permissions"]
        self.assertEqual(len(perms), 1)
        self.assertEqual(perms[0]["contract"], "*")
        self.assertEqual(perms[0]["methods"], "*")

    def test_permissions_specific_methods(self):
        src = """
from neo3.sc.compiletime import public, ContractManifest, Permission
ContractManifest(
    permissions=[
        Permission(
            contract="0xd2a4cff31913016155e38e474a2c06d08be276cf",
            methods=["transfer", "balanceOf"],
        )
    ]
)
@public
def x() -> int:
    return 1
"""
        manifest = self._compile(src)
        perms = manifest["permissions"]
        self.assertEqual(len(perms), 1)
        self.assertEqual(
            perms[0]["contract"],
            "0xd2a4cff31913016155e38e474a2c06d08be276cf",
        )
        self.assertEqual(perms[0]["methods"], ["transfer", "balanceOf"])

    def test_trusts_wildcard(self):
        src = """
from neo3.sc.compiletime import public, ContractManifest
ContractManifest(trusts=["*"])
@public
def x() -> int:
    return 1
"""
        manifest = self._compile(src)
        self.assertEqual(manifest["trusts"], ["*"])

    def test_extra(self):
        src = """
from neo3.sc.compiletime import public, ContractManifest
ContractManifest(extra={"Author": "Alice", "Version": "1.0"})
@public
def x() -> int:
    return 1
"""
        manifest = self._compile(src)
        self.assertEqual(manifest["extra"], {"Author": "Alice", "Version": "1.0"})

    def test_groups(self):
        src = """
from neo3.sc.compiletime import public, ContractManifest, Group
ContractManifest(
    groups=[
        Group(
            pubkey="02c0b60c995bc092e866f15a37c176bb59b7ebacf069ba94c38654a316479b7af4",
            signature="QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==",
        )
    ]
)
@public
def x() -> int:
    return 1
"""
        manifest = self._compile(src)
        groups = manifest["groups"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(
            groups[0]["pubkey"],
            "02c0b60c995bc092e866f15a37c176bb59b7ebacf069ba94c38654a316479b7af4",
        )
        self.assertEqual(
            groups[0]["signature"],
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==",
        )

    def test_abi_not_overwritten(self):
        """Manifest override must not discard the ABI generated from @public methods."""
        src = """
from neo3.sc.compiletime import public, ContractManifest
ContractManifest(name="Overridden", extra={"note": "test"})
@public
def add(a: int, b: int) -> int:
    return a + b
"""
        manifest = self._compile(src)
        self.assertEqual(manifest["name"], "Overridden")
        names = [m["name"] for m in manifest["abi"]["methods"]]
        self.assertIn("add", names)

    def test_duplicate_manifest_call_raises(self):
        from neo3.compiler import TypecheckError

        src = """
from neo3.sc.compiletime import public, ContractManifest
ContractManifest(name="First")
ContractManifest(name="Second")
@public
def x() -> int:
    return 1
"""
        with self.assertRaises(TypecheckError) as ctx:
            _write_contract(src)
        self.assertIn("at most once", str(ctx.exception))

    def test_unknown_field_raises(self):
        from neo3.compiler import TypecheckError

        src = """
from neo3.sc.compiletime import public, ContractManifest
ContractManifest(unknown_field="oops")
@public
def x() -> int:
    return 1
"""
        with self.assertRaises(TypecheckError) as ctx:
            _write_contract(src)
        self.assertIn("unknown_field", str(ctx.exception))

    def test_permission_positional_args(self):
        """Permission("*", ["transfer"]) with positional args is parsed correctly."""
        src = """
from neo3.sc.compiletime import public, ContractManifest, Permission
ContractManifest(permissions=[Permission("*", ["transfer"])])
@public
def x() -> int:
    return 1
"""
        manifest = self._compile(src)
        perms = manifest["permissions"]
        self.assertEqual(len(perms), 1)
        self.assertEqual(perms[0]["contract"], "*")
        self.assertEqual(perms[0]["methods"], ["transfer"])

    def test_permission_duplicate_arg_raises(self):
        """Permission("*", contract="0x...") — same param via positional and keyword → error."""
        from neo3.compiler import TypecheckError

        src = """
from neo3.sc.compiletime import public, ContractManifest, Permission
ContractManifest(permissions=[Permission("*", contract="*")])
@public
def x() -> int:
    return 1
"""
        with self.assertRaises(TypecheckError) as ctx:
            _write_contract(src)
        self.assertIn("multiple values", str(ctx.exception))

    def test_group_positional_args(self):
        """Group(pubkey, signature) with positional args is parsed correctly."""
        src = """
from neo3.sc.compiletime import public, ContractManifest, Group
ContractManifest(
    groups=[Group(
        "02c0b60c995bc092e866f15a37c176bb59b7ebacf069ba94c38654a316479b7af4",
        "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==",
    )]
)
@public
def x() -> int:
    return 1
"""
        manifest = self._compile(src)
        groups = manifest["groups"]
        self.assertEqual(len(groups), 1)
        self.assertEqual(
            groups[0]["pubkey"],
            "02c0b60c995bc092e866f15a37c176bb59b7ebacf069ba94c38654a316479b7af4",
        )

    def test_group_duplicate_arg_raises(self):
        """Group(pubkey_val, pubkey=...) — same param via positional and keyword → error."""
        from neo3.compiler import TypecheckError

        src = """
from neo3.sc.compiletime import public, ContractManifest, Group
ContractManifest(groups=[Group(
    "02c0b60c995bc092e866f15a37c176bb59b7ebacf069ba94c38654a316479b7af4",
    pubkey="02c0b60c995bc092e866f15a37c176bb59b7ebacf069ba94c38654a316479b7af4",
)])
@public
def x() -> int:
    return 1
"""
        with self.assertRaises(TypecheckError) as ctx:
            _write_contract(src)
        self.assertIn("multiple values", str(ctx.exception))

    def test_contract_manifest_positional_name(self):
        """ContractManifest("MyToken") with positional name arg is parsed correctly."""
        src = """
from neo3.sc.compiletime import public, ContractManifest
ContractManifest("MyToken")
@public
def x() -> int:
    return 1
"""
        manifest = self._compile(src)
        self.assertEqual(manifest["name"], "MyToken")

    def test_contract_manifest_duplicate_arg_raises(self):
        """ContractManifest("Foo", name="Bar") — same param positional and keyword → error."""
        from neo3.compiler import TypecheckError

        src = """
from neo3.sc.compiletime import public, ContractManifest
ContractManifest("Foo", name="Bar")
@public
def x() -> int:
    return 1
"""
        with self.assertRaises(TypecheckError) as ctx:
            _write_contract(src)
        self.assertIn("multiple values", str(ctx.exception))

    def test_permission_invalid_contract_raises(self):
        from neo3.compiler import TypecheckError

        src = """
from neo3.sc.compiletime import public, ContractManifest, Permission
ContractManifest(permissions=[Permission(contract="notvalid")])
@public
def x() -> int:
    return 1
"""
        with self.assertRaises(TypecheckError) as ctx:
            _write_contract(src)
        self.assertIn("permissions.contract", str(ctx.exception))

    def test_group_invalid_pubkey_raises(self):
        from neo3.compiler import TypecheckError

        src = """
from neo3.sc.compiletime import public, ContractManifest, Group
ContractManifest(groups=[Group(pubkey="notahex", signature="QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQ==")])
@public
def x() -> int:
    return 1
"""
        with self.assertRaises(TypecheckError) as ctx:
            _write_contract(src)
        self.assertIn("ECPoint", str(ctx.exception))

    def test_group_invalid_signature_raises(self):
        from neo3.compiler import TypecheckError

        src = """
from neo3.sc.compiletime import public, ContractManifest, Group
ContractManifest(groups=[Group(pubkey="02c0b60c995bc092e866f15a37c176bb59b7ebacf069ba94c38654a316479b7af4", signature="tooshort")])
@public
def x() -> int:
    return 1
"""
        with self.assertRaises(TypecheckError) as ctx:
            _write_contract(src)
        self.assertIn("signature", str(ctx.exception))


# Reusable @contract class definition for permission validation tests.
_STDLIB_CONTRACT_DEF = """\
from typing import Any
from neo3.sc.compiletime import contract
from neo3.sc.types import UInt160

@contract('0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0')
class StdLib:
    @staticmethod
    def serialize(item: Any) -> bytes:
        pass

    @staticmethod
    def deserialize(data: bytes) -> Any:
        pass

"""

_STDLIB_HASH = "0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0"
_OTHER_HASH = "0xd2a4cff31913016155e38e474a2c06d08be276cf"


class TestPermissionValidation(unittest.TestCase):
    """Compile-time validation that declared permissions cover all external calls."""

    def _compile_ok(self, src: str) -> dict:
        _, manifest = _write_contract(src)
        return manifest

    def _compile_err(self, src: str) -> str:
        from neo3.compiler import TypecheckError

        with self.assertRaises(TypecheckError) as ctx:
            _write_contract(src)
        return str(ctx.exception)

    def test_no_override_no_error(self):
        """No ContractManifest → default wildcard permissions, no validation needed."""
        src = (
            _STDLIB_CONTRACT_DEF + "from neo3.sc.compiletime import public\n"
            "@public\n"
            "def f(x: int) -> bytes:\n"
            "    return StdLib.serialize(x)\n"
        )
        self._compile_ok(src)

    def test_full_wildcard_ok(self):
        """Permission(contract='*', methods='*') covers any external call."""
        src = (
            _STDLIB_CONTRACT_DEF
            + "from neo3.sc.compiletime import public, ContractManifest, Permission\n"
            "ContractManifest(permissions=[Permission(contract='*', methods='*')])\n"
            "@public\n"
            "def f(x: int) -> bytes:\n"
            "    return StdLib.serialize(x)\n"
        )
        self._compile_ok(src)

    def test_contract_wildcard_ok(self):
        """contract='*' with a specific method list covers any contract for those methods."""
        src = (
            _STDLIB_CONTRACT_DEF
            + "from neo3.sc.compiletime import public, ContractManifest, Permission\n"
            f"ContractManifest(permissions=[Permission(contract='*', methods=['serialize'])])\n"
            "@public\n"
            "def f(x: int) -> bytes:\n"
            "    return StdLib.serialize(x)\n"
        )
        self._compile_ok(src)

    def test_methods_wildcard_ok(self):
        """methods='*' covers all methods on a specific contract."""
        src = (
            _STDLIB_CONTRACT_DEF
            + "from neo3.sc.compiletime import public, ContractManifest, Permission\n"
            f"ContractManifest(permissions=[Permission(contract='{_STDLIB_HASH}', methods='*')])\n"
            "@public\n"
            "def f(x: int) -> bytes:\n"
            "    return StdLib.serialize(x)\n"
        )
        self._compile_ok(src)

    def test_exact_match_ok(self):
        """Exact (contract, method) permission covers the call."""
        src = (
            _STDLIB_CONTRACT_DEF
            + "from neo3.sc.compiletime import public, ContractManifest, Permission\n"
            f"ContractManifest(permissions=[Permission(contract='{_STDLIB_HASH}', methods=['serialize'])])\n"
            "@public\n"
            "def f(x: int) -> bytes:\n"
            "    return StdLib.serialize(x)\n"
        )
        self._compile_ok(src)

    def test_missing_method_raises(self):
        """Permission lists only 'serialize' but contract also calls 'deserialize' → error."""
        src = (
            _STDLIB_CONTRACT_DEF + "from typing import Any\n"
            "from neo3.sc.compiletime import public, ContractManifest, Permission\n"
            f"ContractManifest(permissions=[Permission(contract='{_STDLIB_HASH}', methods=['serialize'])])\n"
            "@public\n"
            "def f(x: int) -> Any:\n"
            "    StdLib.serialize(x)\n"
            "    return StdLib.deserialize(b'data')\n"
        )
        msg = self._compile_err(src)
        self.assertIn("deserialize", msg)
        self.assertIn(_STDLIB_HASH, msg)

    def test_missing_contract_raises(self):
        """Permission covers a different contract hash → error for StdLib calls."""
        src = (
            _STDLIB_CONTRACT_DEF
            + "from neo3.sc.compiletime import public, ContractManifest, Permission\n"
            f"ContractManifest(permissions=[Permission(contract='{_OTHER_HASH}', methods=['serialize'])])\n"
            "@public\n"
            "def f(x: int) -> bytes:\n"
            "    return StdLib.serialize(x)\n"
        )
        msg = self._compile_err(src)
        self.assertIn("serialize", msg)
        self.assertIn(_STDLIB_HASH, msg)

    def test_multiple_missing_reported_together(self):
        """Both uncovered calls appear in the single error message."""
        src = (
            _STDLIB_CONTRACT_DEF + "from typing import Any\n"
            "from neo3.sc.compiletime import public, ContractManifest, Permission\n"
            f"ContractManifest(permissions=[Permission(contract='{_OTHER_HASH}', methods=['serialize'])])\n"
            "@public\n"
            "def f(x: int) -> Any:\n"
            "    StdLib.serialize(x)\n"
            "    return StdLib.deserialize(b'data')\n"
        )
        msg = self._compile_err(src)
        self.assertIn("serialize", msg)
        self.assertIn("deserialize", msg)

    def test_dynamic_call_warns(self):
        """call_contract() warns with location info pointing to the call site."""
        src = (
            "from typing import Any\n"
            "from neo3.sc.compiletime import public, ContractManifest, Permission\n"
            "from neo3.sc.types import UInt160, CallFlags\n"
            "from neo3.sc.utils import call_contract\n"
            f"ContractManifest(permissions=[Permission(contract='{_STDLIB_HASH}', methods=['transfer'])])\n"
            "@public\n"
            "def f(h: UInt160) -> Any:\n"
            "    return call_contract(h, 'balanceOf', [], CallFlags.ALL)\n"
        )
        with self.assertWarns(CompilerWarning) as ctx:
            _write_contract(src)
        messages = [str(w.message) for w in ctx.warnings]
        dyn_msgs = [m for m in messages if "dynamic" in m.lower()]
        self.assertTrue(dyn_msgs, "expected a dynamic-call warning")
        self.assertTrue(
            all("line" in m for m in dyn_msgs), "expected line number in warning"
        )

    def test_dynamic_call_two_sites_two_warnings(self):
        """Two distinct call_contract() call sites produce two separate warnings."""
        src = (
            "from typing import Any\n"
            "from neo3.sc.compiletime import public, ContractManifest, Permission\n"
            "from neo3.sc.types import UInt160, CallFlags\n"
            "from neo3.sc.utils import call_contract\n"
            f"ContractManifest(permissions=[Permission(contract='{_STDLIB_HASH}', methods=['itoa'])])\n"
            "@public\n"
            "def f(h: UInt160) -> Any:\n"
            "    call_contract(h, 'itoa', [1, 10], CallFlags.ALL)\n"
            "    return call_contract(h, 'atoi', ['1'], CallFlags.ALL)\n"
        )
        with self.assertWarns(CompilerWarning) as ctx:
            _write_contract(src)
        dyn_msgs = [
            str(w.message) for w in ctx.warnings if "dynamic" in str(w.message).lower()
        ]
        self.assertEqual(len(dyn_msgs), 2, "expected one warning per call site")

    def test_group_and_dynamic_both_warn(self):
        """Group-based permission + call_contract() → both warnings are emitted with location."""
        src = (
            "from typing import Any\n"
            "from neo3.sc.compiletime import public, ContractManifest, Permission\n"
            "from neo3.sc.types import UInt160, CallFlags\n"
            "from neo3.sc.utils import call_contract\n"
            "ContractManifest(permissions=[\n"
            f"    Permission('*', ['itoa']),\n"
            "    Permission('02c0b60c995bc092e866f15a37c176bb59b7ebacf069ba94c38654a316479b7af4', 'atoi'),\n"
            "])\n"
            "@public\n"
            "def f(h: UInt160) -> Any:\n"
            "    return call_contract(h, 'itoa', [42, 10], CallFlags.ALL)\n"
        )
        with self.assertWarns(CompilerWarning) as ctx:
            _write_contract(src)
        messages = [str(w.message) for w in ctx.warnings]
        group_msgs = [m for m in messages if "group" in m.lower()]
        dyn_msgs = [m for m in messages if "dynamic" in m.lower()]
        self.assertTrue(group_msgs, "expected a group-permission warning")
        self.assertTrue(dyn_msgs, "expected a dynamic-call warning")
        self.assertTrue(
            all("line" in m for m in group_msgs),
            "expected line number in group warning",
        )
        self.assertTrue(
            all("line" in m for m in dyn_msgs),
            "expected line number in dynamic warning",
        )

    def test_group_permission_warns(self):
        """ECPoint-based permission warns with location pointing to the Permission entry."""
        src = (
            _STDLIB_CONTRACT_DEF
            + "from neo3.sc.compiletime import public, ContractManifest, Permission\n"
            "ContractManifest(permissions=["
            "Permission(contract='02c0b60c995bc092e866f15a37c176bb59b7ebacf069ba94c38654a316479b7af4',"
            " methods=['serialize'])"
            "])\n"
            "@public\n"
            "def f(x: int) -> bytes:\n"
            "    return StdLib.serialize(x)\n"
        )
        with self.assertWarns(CompilerWarning) as ctx:
            _write_contract(src)
        group_msgs = [
            str(w.message) for w in ctx.warnings if "group" in str(w.message).lower()
        ]
        self.assertTrue(group_msgs, "expected a group-permission warning")
        self.assertTrue(
            all("line" in m for m in group_msgs), "expected line number in warning"
        )
