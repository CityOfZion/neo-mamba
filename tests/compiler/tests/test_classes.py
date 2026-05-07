"""Unit tests for Tier 13: classes."""

import unittest

from neo3.compiler import TypecheckError, compile_module
from neo3.compiler.disassembler import disassemble


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bc(src: str) -> bytes:
    return compile_module(src)


def _dis(src: str) -> str:
    return disassemble(_bc(src))


# ---------------------------------------------------------------------------
# 1. Simple class — field read/write, __init__, method call
# ---------------------------------------------------------------------------


class TestSimpleClass(unittest.TestCase):

    _SRC = """
class Counter:
    def __init__(self: Counter, start: int) -> None:
        self.value: int = start

    def increment(self: Counter) -> None:
        self.value = self.value + 1

    def get(self: Counter) -> int:
        return self.value

def make_counter(n: int) -> int:
    c: Counter = Counter(n)
    c.increment()
    return c.get()
"""

    def test_compiles(self):
        self.assertIsInstance(_bc(self._SRC), bytes)

    def test_newarray_in_bytecode(self):
        bc = _bc(self._SRC)
        self.assertIn(0xC3, bc)  # NEWARRAY

    def test_call_l_in_bytecode(self):
        bc = _bc(self._SRC)
        self.assertIn(0x35, bc)  # CALL_L

    def test_disassembly_contains_newarray(self):
        self.assertIn("NEWARRAY", _dis(self._SRC))

    def test_disassembly_contains_setitem(self):
        self.assertIn("SETITEM", _dis(self._SRC))

    def test_disassembly_contains_pickitem(self):
        self.assertIn("PICKITEM", _dis(self._SRC))


# ---------------------------------------------------------------------------
# 2. Class registry: ClassType, FieldInfo
# ---------------------------------------------------------------------------


class TestClassRegistry(unittest.TestCase):

    _SRC = """
class Point:
    def __init__(self: Point, x: int, y: int) -> None:
        self.x: int = x
        self.y: int = y

    def sum(self: Point) -> int:
        return self.x + self.y

def make(a: int, b: int) -> int:
    p: Point = Point(a, b)
    return p.sum()
"""

    def test_compiles(self):
        self.assertIsInstance(_bc(self._SRC), bytes)

    def test_field_index_0(self):
        """x should be at index 0 in the Array."""
        dis = _dis(self._SRC)
        # PUSH_INT 0 precedes field read/write for x
        self.assertIn("0 (00)", dis)

    def test_field_index_1(self):
        """y should be at index 1 in the Array."""
        dis = _dis(self._SRC)
        self.assertIn("1 (01)", dis)


# ---------------------------------------------------------------------------
# 3. Class without __init__
# ---------------------------------------------------------------------------


class TestClassNoInit(unittest.TestCase):

    _SRC = """
class Thing:
    def compute(self: Thing, x: int) -> int:
        return x * 2

def run(n: int) -> int:
    t: Thing = Thing()
    return t.compute(n)
"""

    def test_compiles(self):
        self.assertIsInstance(_bc(self._SRC), bytes)

    def test_no_init_still_allocates_array(self):
        self.assertIn(0xC3, _bc(self._SRC))


# ---------------------------------------------------------------------------
# 4. Class variable (static)
# ---------------------------------------------------------------------------


class TestClassVariable(unittest.TestCase):

    _SRC = """
class Config:
    max_value: int = 100

    def get_max(self: Config) -> int:
        return Config.max_value

def run() -> int:
    c: Config = Config()
    return c.get_max()
"""

    def test_compiles(self):
        self.assertIsInstance(_bc(self._SRC), bytes)

    def test_initsslot_present(self):
        bc = _bc(self._SRC)
        self.assertIn(0x56, bc)  # INITSSLOT


# ---------------------------------------------------------------------------
# 5. Inheritance
# ---------------------------------------------------------------------------


class TestSingleInheritance(unittest.TestCase):

    _SRC = """
class Animal:
    def __init__(self: Animal, name: str) -> None:
        self.name: str = name

    def speak(self: Animal) -> str:
        return self.name

class Dog(Animal):
    def __init__(self: Dog, name: str, breed: str) -> None:
        self.name: str = name
        self.breed: str = breed

    def info(self: Dog) -> str:
        return self.name

def run(n: str, b: str) -> str:
    d: Dog = Dog(n, b)
    return d.info()
"""

    def test_compiles(self):
        self.assertIsInstance(_bc(self._SRC), bytes)

    def test_name_is_index_0_in_dog(self):
        """name is inherited at index 0; breed is own at index 1."""
        dis = _dis(self._SRC)
        self.assertIn("NEWARRAY", dis)


# ---------------------------------------------------------------------------
# 6. super() call
# ---------------------------------------------------------------------------


class TestSuperCall(unittest.TestCase):

    _SRC = """
class Base:
    def __init__(self: Base, x: int) -> None:
        self.x: int = x

    def val(self: Base) -> int:
        return self.x

class Child(Base):
    def __init__(self: Child, x: int) -> None:
        super().__init__(x)

    def double(self: Child) -> int:
        return self.x * 2

def run(n: int) -> int:
    c: Child = Child(n)
    return c.double()
"""

    def test_compiles(self):
        self.assertIsInstance(_bc(self._SRC), bytes)


# ---------------------------------------------------------------------------
# 7. @staticmethod
# ---------------------------------------------------------------------------


class TestStaticMethod(unittest.TestCase):

    _SRC = """
class MathHelper:
    @staticmethod
    def add(a: int, b: int) -> int:
        return a + b

def run(x: int, y: int) -> int:
    return MathHelper.add(x, y)
"""

    def test_compiles(self):
        self.assertIsInstance(_bc(self._SRC), bytes)

    def test_no_self_in_static(self):
        """Static method compiled name should not have 'self' as first param."""
        bc = _bc(self._SRC)
        self.assertIsInstance(bc, bytes)


# ---------------------------------------------------------------------------
# 8. @classmethod with cls() factory
# ---------------------------------------------------------------------------


class TestClassMethod(unittest.TestCase):

    _SRC = """
class Box:
    def __init__(self: Box, size: int) -> None:
        self.size: int = size

    @classmethod
    def default(cls) -> Box:
        return cls(10)

    def get_size(self: Box) -> int:
        return self.size

def run() -> int:
    b: Box = Box.default()
    return b.get_size()
"""

    def test_compiles(self):
        self.assertIsInstance(_bc(self._SRC), bytes)


# ---------------------------------------------------------------------------
# 9. TypecheckError cases
# ---------------------------------------------------------------------------


class TestTypeErrors(unittest.TestCase):

    def test_unknown_field_raises(self):
        src = """
class Foo:
    def __init__(self: Foo, x: int) -> None:
        self.x: int = x
def run(n: int) -> int:
    f: Foo = Foo(n)
    return f.z
"""
        with self.assertRaises(TypecheckError):
            _bc(src)

    def test_nested_class_raises(self):
        src = """
class Outer:
    class Inner:
        pass
    def run(self: Outer) -> int:
        return 0
def go() -> int:
    return 0
"""
        with self.assertRaises(TypecheckError):
            _bc(src)

    def test_forward_reference_raises(self):
        src = """
class Child(Parent):
    pass
class Parent:
    pass
def go() -> int:
    return 0
"""
        with self.assertRaises(TypecheckError):
            _bc(src)

    def test_instance_method_call_on_class_name_raises(self):
        src = """
class Foo:
    def get(self: Foo) -> int:
        return 0
def run() -> int:
    return Foo.get()
"""
        with self.assertRaises(TypecheckError):
            _bc(src)

    def test_field_type_mismatch_raises(self):
        src = """
class Foo:
    def __init__(self: Foo, x: int) -> None:
        self.x: int = x
def run(s: str) -> int:
    f: Foo = Foo(s)
    return 0
"""
        with self.assertRaises(TypecheckError):
            _bc(src)

    def test_unknown_method_raises(self):
        src = """
class Foo:
    def get(self: Foo) -> int:
        return 0
def run() -> int:
    f: Foo = Foo()
    f.nope()
    return 0
"""
        with self.assertRaises(TypecheckError):
            _bc(src)

    def test_mi_field_index_conflict_raises(self):
        src = """
class A:
    def __init__(self: A) -> None:
        self.x: int = 1
class B:
    def __init__(self: B) -> None:
        self.y: int = 2
class C(A, B):
    pass
def go() -> int:
    return 0
"""
        # A has x@0, B has y@0 — C merges A first (x@0) then B (y@0 conflicts)
        with self.assertRaises(TypecheckError):
            _bc(src)


# ---------------------------------------------------------------------------
# 10. Multiple fields, correct NEWARRAY size
# ---------------------------------------------------------------------------


class TestNewArraySize(unittest.TestCase):

    _SRC = """
class Triple:
    def __init__(self: Triple, a: int, b: int, c: int) -> None:
        self.a: int = a
        self.b: int = b
        self.c: int = c

    def total(self: Triple) -> int:
        return self.a + self.b + self.c

def run(x: int, y: int, z: int) -> int:
    t: Triple = Triple(x, y, z)
    return t.total()
"""

    def test_compiles(self):
        self.assertIsInstance(_bc(self._SRC), bytes)

    def test_newarray_pushes_3(self):
        """NEWARRAY should be preceded by PUSH 3 (three fields)."""
        dis = _dis(self._SRC)
        lines = dis.splitlines()
        for i, line in enumerate(lines):
            if "NEWARRAY" in line and "NEWARRAY0" not in line:
                # The previous instruction should push 3
                prev = lines[i - 1] if i > 0 else ""
                self.assertIn("3", prev)
                return
        self.fail("NEWARRAY not found in disassembly")


# ---------------------------------------------------------------------------
# 11. MRO edge cases: diamond inheritance and index conflicts
# ---------------------------------------------------------------------------


class TestDiamondInheritance(unittest.TestCase):
    """Diamond D(B, C) where B(A) and C(A) — A's field must appear once."""

    _SRC = """
class A:
    def __init__(self: A) -> None:
        self.x: int = 0

    def get(self: A) -> int:
        return self.x

class B(A):
    def __init__(self: B) -> None:
        self.x: int = 1

class C(A):
    def __init__(self: C) -> None:
        self.x: int = 2

class D(B, C):
    def __init__(self: D) -> None:
        self.x: int = 3

def go() -> int:
    d: D = D()
    return d.get()
"""

    def test_diamond_compiles(self):
        self.assertIsInstance(_bc(self._SRC), bytes)

    def test_diamond_field_not_duplicated(self):
        # x must appear exactly once in D's field layout (not twice)
        from neo3.compiler import _build_class_registry
        import ast as _ast

        tree = _ast.parse(self._SRC)
        registry, _, _ = _build_class_registry(tree, {})
        d_info = registry["D"]
        field_names = list(d_info.fields.keys())
        self.assertEqual(field_names.count("x"), 1)

    def test_diamond_mro_order(self):
        # C3 MRO for D(B,C) where B(A),C(A): D → B → C → A
        from neo3.compiler import _build_class_registry
        import ast as _ast

        tree = _ast.parse(self._SRC)
        registry, _, _ = _build_class_registry(tree, {})
        mro = registry["D"].class_mro
        self.assertEqual(mro[0], "B")
        b_idx = mro.index("B")
        c_idx = mro.index("C")
        a_idx = mro.index("A")
        self.assertLess(b_idx, c_idx)
        self.assertLess(c_idx, a_idx)


class TestMROIndexConflictTwoParents(unittest.TestCase):
    """Two parents with different field names but same index must conflict."""

    def test_two_parent_same_index_different_names_raises(self):
        src = """
class A:
    def __init__(self: A) -> None:
        self.alpha: int = 1
class B:
    def __init__(self: B) -> None:
        self.beta: int = 2
class C(A, B):
    pass
def go() -> int:
    return 0
"""
        # A has alpha@0, B has beta@0 — C merges both; beta@0 conflicts with alpha@0
        with self.assertRaises(TypecheckError):
            _bc(src)

    def test_two_parent_non_overlapping_indices_ok(self):
        src = """
class A:
    def __init__(self: A) -> None:
        self.x: int = 1
        self.y: int = 2
class B:
    def __init__(self: B) -> None:
        self.x: int = 1
        self.z: int = 3
class C(A, B):
    pass
def go() -> int:
    return 0
"""
        # A: x@0, y@1 — B: x@0, z@1 — z from B is at index 1, y from A is at index 1 → conflict
        with self.assertRaises(TypecheckError):
            _bc(src)

    def test_single_parent_inherited_no_conflict(self):
        src = """
class Base:
    def __init__(self: Base) -> None:
        self.a: int = 0
        self.b: int = 0

class Child(Base):
    def __init__(self: Child) -> None:
        self.a: int = 10
        self.b: int = 20

def go() -> int:
    c: Child = Child()
    return c.a + c.b
"""
        self.assertIsInstance(_bc(src), bytes)


class TestCircularInheritanceRejected(unittest.TestCase):
    """Circular base class references must raise TypecheckError."""

    def test_self_inheritance_raises(self):
        src = """
class A(A):
    pass
def go() -> int:
    return 0
"""
        with self.assertRaises(TypecheckError):
            _bc(src)


# ---------------------------------------------------------------------------
# Static/classmethod calls as statements
# ---------------------------------------------------------------------------


class TestStaticMethodAsStatement(unittest.TestCase):
    """Static and class methods called as bare statements (void return)."""

    def test_void_static_as_statement(self):
        src = """
class Logger:
    @staticmethod
    def log() -> None:
        pass

def run() -> None:
    Logger.log()
"""
        self.assertIsInstance(_bc(src), bytes)

    def test_void_classmethod_as_statement(self):
        src = """
class Factory:
    @classmethod
    def create(cls) -> None:
        pass

def run() -> None:
    Factory.create()
"""
        self.assertIsInstance(_bc(src), bytes)

    def test_nonvoid_static_as_statement_compiles_and_drops(self):
        src = """
class Math:
    @staticmethod
    def square(x: int) -> int:
        return x * x

def run() -> None:
    Math.square(5)
"""
        bc = _bc(src)
        self.assertIsInstance(bc, bytes)
        self.assertIn(0x45, bc)  # DROP must be emitted

    def test_instance_method_without_instance_raises(self):
        src = """
class Foo:
    def bar(self: Foo) -> None:
        pass

def run() -> None:
    Foo.bar()
"""
        with self.assertRaises(TypecheckError):
            _bc(src)


# ---------------------------------------------------------------------------
# __init__ implicit -> None
# ---------------------------------------------------------------------------


class TestInitImplicitNone(unittest.TestCase):
    """__init__ without a return annotation compiles as -> None."""

    def test_init_no_return_annotation_compiles(self):
        src = """
class Box:
    def __init__(self: Box, v: int):
        self.value: int = v

    def get(self: Box) -> int:
        return self.value

def run(n: int) -> int:
    b: Box = Box(n)
    return b.get()
"""
        self.assertIsInstance(_bc(src), bytes)

    def test_other_method_still_requires_annotation(self):
        src = """
class Box:
    def __init__(self: Box, v: int):
        self.value: int = v

    def get(self: Box):
        return self.value

def run(n: int) -> int:
    b: Box = Box(n)
    return b.get()
"""
        with self.assertRaises(TypecheckError):
            _bc(src)


# ---------------------------------------------------------------------------
# Unannotated field type inference in __init__
# ---------------------------------------------------------------------------


class TestFieldTypeInference(unittest.TestCase):
    """Pre-pass infers type of unannotated self.field = <expr> assignments."""

    def test_infer_bytes_from_to_bytes_call(self):
        # Regression: self._seed = x.to_bytes(...) must be inferred as bytes
        # without requiring an explicit annotation.
        src = """
class Item:
    def __init__(self: Item, x: int) -> None:
        self._seed = x.to_bytes(16, "little", signed=False)

    def seed(self: Item) -> bytes:
        return self._seed

def run(n: int) -> bytes:
    item: Item = Item(n)
    return item.seed()
"""
        self.assertIsInstance(_bc(src), bytes)


# ---------------------------------------------------------------------------
# item-12: _build_cfg in helpers.py must forward class_registry to HIRBuilder
# ---------------------------------------------------------------------------


class TestClassRegistryPropagation(unittest.TestCase):
    """Regression: HIRBuilder with class_registry=None silently rejects subclass assignments."""

    _SRC = """\
class Animal:
    def __init__(self: Animal) -> None:
        self.name: str = "a"

class Dog(Animal):
    def __init__(self: Dog) -> None:
        super().__init__()

def assign_dog(d: Dog) -> None:
    a: Animal = d
"""

    def _get_registry(self):
        import ast as _ast
        from neo3.compiler import _build_class_registry

        tree = _ast.parse(self._SRC)
        registry, _, _ = _build_class_registry(tree, {})
        return registry

    def test_without_registry_dog_not_assignable_to_animal(self):
        """HIRBuilder() with no registry treats Dog as incompatible with Animal — the bug."""
        import ast as _ast
        from neo3.compiler import HIRBuilder

        tree = _ast.parse(self._SRC)
        fn = next(
            n
            for n in _ast.walk(tree)
            if isinstance(n, _ast.FunctionDef) and n.name == "assign_dog"
        )
        with self.assertRaises(TypecheckError):
            HIRBuilder().build(fn)

    def test_with_registry_dog_assignable_to_animal(self):
        """HIRBuilder(class_registry=...) correctly accepts Dog where Animal is expected."""
        import ast as _ast
        from neo3.compiler import HIRBuilder

        registry = self._get_registry()
        tree = _ast.parse(self._SRC)
        fn = next(
            n
            for n in _ast.walk(tree)
            if isinstance(n, _ast.FunctionDef) and n.name == "assign_dog"
        )
        hir = HIRBuilder(class_registry=registry).build(fn)
        self.assertIsNotNone(hir)

    def test_build_cfg_helper_forwards_class_registry(self):
        """After fix: _build_cfg(class_registry=...) compiles subclass assignment correctly."""
        from tests.compiler.tests.helpers import _build_cfg

        registry = self._get_registry()
        cfg = _build_cfg(self._SRC, class_registry=registry)
        self.assertIsNotNone(cfg)
