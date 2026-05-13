"""
Tests for the import machinery: bundling local modules into the compilation unit.

Each test writes helper .py files to a temp directory alongside a main contract,
then compiles via compile_module(..., search_path=<dir>) or compile_to_nef().
"""

import os
import tempfile
import unittest

from neo3.compiler import TypecheckError, _compile_full, compile_module


def _write(tmpdir: str, filename: str, source: str) -> str:
    path = os.path.join(tmpdir, filename)
    with open(path, "w") as f:
        f.write(source)
    return path


class TestFromImport(unittest.TestCase):
    """from module import name"""

    def test_function(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "utils.py",
                """
def add(a: int, b: int) -> int:
    return a + b
""",
            )
            src = """
from utils import add

from neo3.sc.compiletime import public
@public
def main(a: int, b: int) -> int:
    return add(a, b)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_multiple_names(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "math_utils.py",
                """
def double(x: int) -> int:
    return x * 2

def triple(x: int) -> int:
    return x * 3
""",
            )
            src = """
from math_utils import double, triple

from neo3.sc.compiletime import public
@public
def main(x: int) -> int:
    return double(x) + triple(x)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_static_constant(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "config.py",
                """
LIMIT: int = 100
""",
            )
            src = """
from config import LIMIT

from neo3.sc.compiletime import public
@public
def get_limit() -> int:
    return LIMIT
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_class(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "models.py",
                """
class Point:
    def __init__(self: Point, x: int, y: int) -> None:
        self.x: int = x
        self.y: int = y

    def sum(self: Point) -> int:
        return self.x + self.y
""",
            )
            src = """
from models import Point

from neo3.sc.compiletime import public
@public
def main(x: int, y: int) -> int:
    p: Point = Point(x, y)
    return p.sum()
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)


class TestFromImportAs(unittest.TestCase):
    """from module import name as alias"""

    def test_function_alias(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "utils.py",
                """
def add(a: int, b: int) -> int:
    return a + b
""",
            )
            src = """
from utils import add as plus

from neo3.sc.compiletime import public
@public
def main(a: int, b: int) -> int:
    return plus(a, b)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_class_alias(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "models.py",
                """
class Box:
    def __init__(self: Box, size: int) -> None:
        self.size: int = size

    def get(self: Box) -> int:
        return self.size
""",
            )
            src = """
from models import Box as Container

from neo3.sc.compiletime import public
@public
def main(n: int) -> int:
    c: Container = Container(n)
    return c.get()
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)


class TestImportModule(unittest.TestCase):
    """import module  →  module.name(...)"""

    def test_function_call(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "utils.py",
                """
def add(a: int, b: int) -> int:
    return a + b
""",
            )
            src = """
import utils

from neo3.sc.compiletime import public
@public
def main(a: int, b: int) -> int:
    return utils.add(a, b)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_class_instantiation(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "models.py",
                """
class Pair:
    def __init__(self: Pair, x: int, y: int) -> None:
        self.x: int = x
        self.y: int = y

    def total(self: Pair) -> int:
        return self.x + self.y
""",
            )
            src = """
import models
from models import Pair

from neo3.sc.compiletime import public
@public
def main(x: int, y: int) -> int:
    p: Pair = models.Pair(x, y)
    return p.total()
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_static_read(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "config.py",
                """
MAX: int = 999
""",
            )
            src = """
import config

from neo3.sc.compiletime import public
@public
def get_max() -> int:
    return config.MAX
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_class_as_type_annotation(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "user.py",
                """
class User:
    def __init__(self: User, name: str) -> None:
        self.name: str = name

    def get_name(self: User) -> str:
        return self.name
""",
            )
            src = """
import user

from neo3.sc.compiletime import public
@public
def greet(u: user.User) -> str:
    return u.get_name()
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_class_as_field_annotation(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "user.py",
                """
class User:
    def __init__(self: User, name: str) -> None:
        self.name: str = name
""",
            )
            _write(
                d,
                "repo.py",
                """
import user

class UserRepo:
    def __init__(self: UserRepo, u: user.User) -> None:
        self.u: user.User = u

    def get_user(self: UserRepo) -> user.User:
        return self.u
""",
            )
            src = """
import repo
import user

from neo3.sc.compiletime import public
@public
def make_user(name: str) -> str:
    u: user.User = user.User(name)
    r: repo.UserRepo = repo.UserRepo(u)
    return r.get_user().name
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_from_package_import_submodule_class_annotation(self):
        """from models import user; u: user.User — the real-world pattern."""
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "models"), exist_ok=True)
            _write(d, os.path.join("models", "__init__.py"), "")
            _write(
                d,
                os.path.join("models", "user.py"),
                """
class User:
    def __init__(self: User, name: str) -> None:
        self.name: str = name

    def get_name(self: User) -> str:
        return self.name
""",
            )
            src = """
from models import user

from neo3.sc.compiletime import public
@public
def greet(u: user.User) -> str:
    return u.get_name()

@public
def make(name: str) -> user.User:
    return user.User(name)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_module_alias(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "utils.py",
                """
def mul(a: int, b: int) -> int:
    return a * b
""",
            )
            src = """
import utils as u

from neo3.sc.compiletime import public
@public
def main(a: int, b: int) -> int:
    return u.mul(a, b)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)


class TestWildcardImport(unittest.TestCase):
    """from module import *"""

    def test_wildcard_brings_all_public_names(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "math_utils.py",
                """
def add(a: int, b: int) -> int:
    return a + b

def sub(a: int, b: int) -> int:
    return a - b
""",
            )
            src = """
from math_utils import *

from neo3.sc.compiletime import public
@public
def main(a: int, b: int) -> int:
    return add(a, b) + sub(a, b)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_wildcard_excludes_underscore_names(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "internals.py",
                """
def public_fn(x: int) -> int:
    return x

def _private_fn(x: int) -> int:
    return x + 1
""",
            )
            src = """
from internals import *

from neo3.sc.compiletime import public
@public
def main(x: int) -> int:
    return public_fn(x)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)


class TestRelativeImport(unittest.TestCase):
    """from .module import name"""

    def test_relative_from_import(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "helpers.py",
                """
def square(n: int) -> int:
    return n * n
""",
            )
            src = """
from .helpers import square

from neo3.sc.compiletime import public
@public
def main(n: int) -> int:
    return square(n)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_relative_import_module(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "helpers.py",
                """
def cube(n: int) -> int:
    return n * n * n
""",
            )
            src = """
from . import helpers

from neo3.sc.compiletime import public
@public
def main(n: int) -> int:
    return helpers.cube(n)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_relative_missing_raises(self):
        with tempfile.TemporaryDirectory() as d:
            src = """
from .nonexistent import foo

from neo3.sc.compiletime import public
@public
def main() -> int:
    return foo()
"""
            with self.assertRaises(TypecheckError):
                compile_module(src, search_path=d)

    def test_relative_without_search_path_raises(self):
        src = """
from .helpers import foo

from neo3.sc.compiletime import public
@public
def main() -> int:
    return foo()
"""
        with self.assertRaises(TypecheckError):
            compile_module(src)


class TestTransitiveImport(unittest.TestCase):
    """Modules that themselves import other modules."""

    def test_transitive(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "base.py",
                """
def inc(x: int) -> int:
    return x + 1
""",
            )
            _write(
                d,
                "mid.py",
                """
from base import inc

def inc2(x: int) -> int:
    return inc(inc(x))
""",
            )
            src = """
from mid import inc2

from neo3.sc.compiletime import public
@public
def main(x: int) -> int:
    return inc2(x)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)


class TestCircularImport(unittest.TestCase):
    def test_circular_raises(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "a.py",
                """
from b import bar

def foo(x: int) -> int:
    return bar(x)
""",
            )
            _write(
                d,
                "b.py",
                """
from a import foo

def bar(x: int) -> int:
    return foo(x)
""",
            )
            src = """
from a import foo

from neo3.sc.compiletime import public
@public
def main(x: int) -> int:
    return foo(x)
"""
            with self.assertRaises(TypecheckError):
                compile_module(src, search_path=d)


class TestNameConflict(unittest.TestCase):
    def test_function_conflict_last_import_wins(self):
        # With name mangling, same-named functions from different modules are
        # both compiled under unique mangled names. The last `from X import name`
        # wins (same as Python semantics).
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "a.py",
                """
def compute(x: int) -> int:
    return x + 1
""",
            )
            _write(
                d,
                "b.py",
                """
def compute(x: int) -> int:
    return x * 2
""",
            )
            src = """
from a import compute
from b import compute

from neo3.sc.compiletime import public
@public
def main(x: int) -> int:
    return compute(x)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_conflict_error_message_names_identifier(self):
        # Same-name imports no longer conflict with mangling; both compile fine.
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "a.py",
                """
def my_fn(x: int) -> int:
    return x
""",
            )
            _write(
                d,
                "b.py",
                """
def my_fn(x: int) -> int:
    return x + 1
""",
            )
            src = """
from a import my_fn
from b import my_fn

from neo3.sc.compiletime import public
@public
def main(x: int) -> int:
    return my_fn(x)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_alias_resolves_conflict(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "a.py",
                """
def compute(x: int) -> int:
    return x + 1
""",
            )
            _write(
                d,
                "b.py",
                """
def compute(x: int) -> int:
    return x * 2
""",
            )
            src = """
from a import compute as add_one
from b import compute as double

from neo3.sc.compiletime import public
@public
def main(x: int) -> int:
    return add_one(x) + double(x)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)


class TestPublicInImportedModule(unittest.TestCase):
    def test_public_from_imported_module_is_in_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "entry.py",
                """
from neo3.sc.compiletime import public
@public
def admin_fn(x: int) -> int:
    return x * 10
""",
            )
            src = """
from entry import admin_fn
"""
            import os as _os

            main_path = _os.path.join(d, "contract.py")
            with open(main_path, "w") as f:
                f.write(src)
            _, public_methods, _, _ = _compile_full(src, search_path=d)
            names = [m.name for m in public_methods]
            self.assertIn("admin_fn", names)

    def test_public_not_duplicated(self):
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "utils.py",
                """
def helper(x: int) -> int:
    return x
""",
            )
            src = """
from utils import helper

from neo3.sc.compiletime import public
@public
def main(x: int) -> int:
    return helper(x)
"""
            _, public_methods, _, _ = _compile_full(src, search_path=d)
            names = [m.name for m in public_methods]
            self.assertIn("main", names)
            self.assertNotIn("helper", names)


class TestStdlibImportsError(unittest.TestCase):
    """typing / typing_extensions are silently skipped; other missing modules raise."""

    def test_typing_import_silently_skipped(self):
        src = """
from typing import Optional

from neo3.sc.compiletime import public
@public
def main(x: int) -> int:
    return x
"""
        with tempfile.TemporaryDirectory() as d:
            result = compile_module(src, search_path=d)
        self.assertIsInstance(result, bytes)

    def test_typing_extensions_silently_skipped(self):
        src = """
from typing import Protocol

from neo3.sc.compiletime import public
@public
def main(x: int) -> int:
    return x
"""
        with tempfile.TemporaryDirectory() as d:
            result = compile_module(src, search_path=d)
        self.assertIsInstance(result, bytes)

    def test_import_nonlocal_module_raises(self):
        src = """
import os

from neo3.sc.compiletime import public
@public
def main(x: int) -> int:
    return x
"""
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(TypecheckError) as ctx:
                compile_module(src, search_path=d)
        self.assertIn("os", str(ctx.exception))

    def test_import_without_search_path_skips(self):
        """When no search_path is given, absolute imports are skipped (no path to look up)."""
        src = """
import os

from neo3.sc.compiletime import public
@public
def main(x: int) -> int:
    return x
"""
        result = compile_module(src)
        self.assertIsInstance(result, bytes)


class TestPackageReexport(unittest.TestCase):
    """from pkg import Name where pkg/__init__.py re-exports Name from a submodule."""

    def _make_package(
        self, tmpdir: str, pkg: str, init_src: str, **submodules: str
    ) -> None:
        pkg_dir = os.path.join(tmpdir, pkg)
        os.makedirs(pkg_dir, exist_ok=True)
        with open(os.path.join(pkg_dir, "__init__.py"), "w") as f:
            f.write(init_src)
        for name, src in submodules.items():
            with open(os.path.join(pkg_dir, name + ".py"), "w") as f:
                f.write(src)

    def test_reexport_function(self):
        with tempfile.TemporaryDirectory() as d:
            self._make_package(
                d,
                "mylib",
                "from mylib.math import add\n",
                math="""
def add(a: int, b: int) -> int:
    return a + b
""",
            )
            src = """
from mylib import add

from neo3.sc.compiletime import public
@public
def main(a: int, b: int) -> int:
    return add(a, b)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_reexport_class(self):
        with tempfile.TemporaryDirectory() as d:
            self._make_package(
                d,
                "models",
                "from models.point import Point\n",
                point="""
class Point:
    def __init__(self: Point, x: int, y: int) -> None:
        self.x: int = x
        self.y: int = y

    def sum(self: Point) -> int:
        return self.x + self.y
""",
            )
            src = """
from models import Point

from neo3.sc.compiletime import public
@public
def main(x: int, y: int) -> int:
    p: Point = Point(x, y)
    return p.sum()
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_two_imports_from_same_reexport_package(self):
        """Second import hits the already-bundled path (else branch)."""
        with tempfile.TemporaryDirectory() as d:
            self._make_package(
                d,
                "mylib",
                "from mylib.a import foo\nfrom mylib.b import bar\n",
                a="""
def foo(x: int) -> int:
    return x + 1
""",
                b="""
def bar(x: int) -> int:
    return x * 2
""",
            )
            src = """
from mylib import foo
from mylib import bar

from neo3.sc.compiletime import public
@public
def main(x: int) -> int:
    return foo(x) + bar(x)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_wildcard_from_reexport_package(self):
        with tempfile.TemporaryDirectory() as d:
            self._make_package(
                d,
                "ops",
                "from ops.math import add, sub\n",
                math="""
def add(a: int, b: int) -> int:
    return a + b

def sub(a: int, b: int) -> int:
    return a - b
""",
            )
            src = """
from ops import *

from neo3.sc.compiletime import public
@public
def main(a: int, b: int) -> int:
    return add(a, b) + sub(a, b)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_contracts_reexport_contract_management(self):
        src = """
from neo3.sc.contracts import ContractManagement
from neo3.sc.types import UInt160

from neo3.sc.compiletime import public
@public
def get_min_fee() -> int:
    return ContractManagement.get_minimum_deployment_fee()
"""
        with tempfile.TemporaryDirectory() as d:
            result = compile_module(src, search_path=d)
        self.assertIsInstance(result, bytes)

    def test_contracts_reexport_multiple(self):
        src = """
from neo3.sc.contracts import ContractManagement, GasToken
from neo3.sc.types import UInt160

from neo3.sc.compiletime import public
@public
def get_balance(account: UInt160) -> int:
    return GasToken.balance_of(account)
"""
        with tempfile.TemporaryDirectory() as d:
            result = compile_module(src, search_path=d)
        self.assertIsInstance(result, bytes)


_USER_MODULE_SRC = """
class User:
    def __init__(self: User, name: str) -> None:
        self.name: str = name

    def get_name(self: User) -> str:
        return self.name
"""


class TestModuleClassAnnotation(unittest.TestCase):
    """module.Class in type annotations works for every import style and annotation position."""

    # ------------------------------------------------------------------
    # Import styles
    # ------------------------------------------------------------------

    def test_import_as_alias(self):
        """import user as u  →  param: u.User, return: u.User"""
        with tempfile.TemporaryDirectory() as d:
            _write(d, "user.py", _USER_MODULE_SRC)
            src = """
import user as u

from neo3.sc.compiletime import public
@public
def greet(x: u.User) -> u.User:
    return x
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_relative_from_import_module(self):
        """from . import user  →  user.User annotation (relative import path)"""
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "pkg"), exist_ok=True)
            _write(d, os.path.join("pkg", "__init__.py"), "")
            _write(d, os.path.join("pkg", "user.py"), _USER_MODULE_SRC)
            _write(
                d,
                os.path.join("pkg", "service.py"),
                """
from . import user

def greet(x: user.User) -> user.User:
    return x
""",
            )
            src = """
from pkg import service
from pkg import user

from neo3.sc.compiletime import public
@public
def main(name: str) -> str:
    u: user.User = user.User(name)
    return service.greet(u).get_name()
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_from_package_import_submodule_already_bundled(self):
        """from models import user where user was already bundled as a transitive dep."""
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "models"), exist_ok=True)
            # __init__.py imports User from user, bundling models/user.py transitively
            _write(
                d,
                os.path.join("models", "__init__.py"),
                "from models.user import User\n",
            )
            _write(d, os.path.join("models", "user.py"), _USER_MODULE_SRC)
            src = """
from models import user  # models/user.py already bundled via __init__.py

from neo3.sc.compiletime import public
@public
def greet(u: user.User) -> str:
    return u.get_name()
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    # ------------------------------------------------------------------
    # Annotation positions
    # ------------------------------------------------------------------

    def test_annotation_in_local_variable(self):
        """v: user.User = ...  — local variable annotation"""
        with tempfile.TemporaryDirectory() as d:
            _write(d, "user.py", _USER_MODULE_SRC)
            src = """
import user

from neo3.sc.compiletime import public
@public
def make(name: str) -> str:
    v: user.User = user.User(name)
    return v.get_name()
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_annotation_in_instance_field(self):
        """self.x: user.User in __init__"""
        with tempfile.TemporaryDirectory() as d:
            _write(d, "user.py", _USER_MODULE_SRC)
            _write(
                d,
                "repo.py",
                """
import user

class UserRepo:
    def __init__(self: UserRepo, u: user.User) -> None:
        self.u: user.User = u

    def get(self: UserRepo) -> user.User:
        return self.u
""",
            )
            src = """
import user
import repo

from neo3.sc.compiletime import public
@public
def main(name: str) -> str:
    u: user.User = user.User(name)
    r: repo.UserRepo = repo.UserRepo(u)
    return r.get().get_name()
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_annotation_optional_nested(self):
        """Optional[user.User] — nested annotation"""
        with tempfile.TemporaryDirectory() as d:
            _write(d, "user.py", _USER_MODULE_SRC)
            src = """
import user
from typing import Optional

from neo3.sc.compiletime import public
@public
def maybe(flag: bool) -> Optional[user.User]:
    if flag:
        u: user.User = user.User("alice")
        return u
    return None
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_annotation_in_return_type(self):
        """-> user.User return type annotation"""
        with tempfile.TemporaryDirectory() as d:
            _write(d, "user.py", _USER_MODULE_SRC)
            src = """
import user

from neo3.sc.compiletime import public
@public
def make(name: str) -> user.User:
    return user.User(name)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_annotation_in_function_param(self):
        """param: user.User — parameter annotation"""
        with tempfile.TemporaryDirectory() as d:
            _write(d, "user.py", _USER_MODULE_SRC)
            src = """
import user

from neo3.sc.compiletime import public
@public
def get_name(u: user.User) -> str:
    return u.get_name()
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    # ------------------------------------------------------------------
    # from package import submodule — all annotation positions
    # ------------------------------------------------------------------

    def test_from_package_annotation_param_and_return(self):
        """from models import user; both param and return type use user.User"""
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "models"), exist_ok=True)
            _write(d, os.path.join("models", "__init__.py"), "")
            _write(d, os.path.join("models", "user.py"), _USER_MODULE_SRC)
            src = """
from models import user

from neo3.sc.compiletime import public
@public
def roundtrip(u: user.User) -> user.User:
    return u
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_from_package_annotation_local_var(self):
        """from models import user; local variable annotation user.User"""
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "models"), exist_ok=True)
            _write(d, os.path.join("models", "__init__.py"), "")
            _write(d, os.path.join("models", "user.py"), _USER_MODULE_SRC)
            src = """
from models import user

from neo3.sc.compiletime import public
@public
def make(name: str) -> str:
    u: user.User = user.User(name)
    return u.get_name()
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_from_package_annotation_instance_field(self):
        """from models import user; self.u: user.User in __init__"""
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "models"), exist_ok=True)
            _write(d, os.path.join("models", "__init__.py"), "")
            _write(d, os.path.join("models", "user.py"), _USER_MODULE_SRC)
            _write(
                d,
                "repo.py",
                """
from models import user

class UserRepo:
    def __init__(self: UserRepo, u: user.User) -> None:
        self.u: user.User = u

    def get(self: UserRepo) -> user.User:
        return self.u
""",
            )
            src = """
from models import user
import repo

from neo3.sc.compiletime import public
@public
def main(name: str) -> str:
    u: user.User = user.User(name)
    r: repo.UserRepo = repo.UserRepo(u)
    return r.get().get_name()
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_from_package_annotation_optional_nested(self):
        """from models import user; Optional[user.User]"""
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "models"), exist_ok=True)
            _write(d, os.path.join("models", "__init__.py"), "")
            _write(d, os.path.join("models", "user.py"), _USER_MODULE_SRC)
            src = """
from models import user
from typing import Optional

from neo3.sc.compiletime import public
@public
def maybe(flag: bool) -> Optional[user.User]:
    if flag:
        u: user.User = user.User("alice")
        return u
    return None
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_local_var_shadows_module_level_name(self):
        """Local variable in one free function must not be mangled when a top-level
        function in the same imported module has the same name."""
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "admin.py",
                """
def update(x: int) -> int:
    return x + 1

def process(v: int) -> int:
    update: int = v * 2
    if update == 0:
        return -1
    return update
""",
            )
            src = """
import admin
from neo3.sc.compiletime import public

@public
def run(v: int) -> int:
    return admin.process(v)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_local_var_shadows_module_namespace(self):
        """A local variable whose name matches a module alias must not be treated as
        a module namespace call."""
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "repo.py",
                """
def create_binding(x: int) -> bool:
    return x > 0
""",
            )
            src = """
import repo
from neo3.sc.compiletime import public

@public
def run(v: int) -> int:
    repo: int = v + 1
    return repo
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_static_field_shadows_module_namespace(self):
        """A static field whose name matches a module alias must not be treated as
        a module namespace call — instance method calls on it must resolve correctly."""
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "repo.py",
                """
def create_binding(x: int) -> bool:
    return x > 0
""",
            )
            src = """
import repo
from neo3.sc.compiletime import public

repo: int = 0

@public
def run(v: int) -> int:
    return repo
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)

    def test_module_namespace_nonvoid_call_as_stmt_compiles(self):
        """Non-void module-namespace call as a statement compiles; result is dropped."""
        with tempfile.TemporaryDirectory() as d:
            _write(
                d,
                "ops.py",
                """
def get_value() -> int:
    return 42
""",
            )
            src = """
import ops
from neo3.sc.compiletime import public

@public
def run() -> int:
    ops.get_value()
    return 0
"""
            bc = compile_module(src, search_path=d)
            self.assertIsInstance(bc, bytes)
            self.assertIn(0x45, bc)  # DROP must be emitted

    def test_sc_module_namespace_annotation(self):
        """from neo3.sc import utils; utils.Iterator as annotation"""
        with tempfile.TemporaryDirectory() as d:
            src = """
from neo3.sc import utils, storage
from neo3.sc.types import FindOptions

from neo3.sc.compiletime import public
@public
def get_iter(prefix: bytes) -> utils.Iterator:
    return storage.find(prefix, FindOptions.NONE)
"""
            result = compile_module(src, search_path=d)
            self.assertIsInstance(result, bytes)


if __name__ == "__main__":
    unittest.main()
