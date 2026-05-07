from neo3.sc.compiletime import public
from utils import add, multiply, MULTIPLIER
from utils import add as plus
import utils as u
from shapes import Rectangle
import shapes


@public
def test_from_import_fn(a: int, b: int) -> int:
    return add(a, b)


@public
def test_module_fn(a: int, b: int) -> int:
    return u.add(a, b)


@public
def test_alias_fn(a: int, b: int) -> int:
    return plus(a, b)


@public
def test_static_direct() -> int:
    return MULTIPLIER


@public
def test_static_via_module() -> int:
    return u.MULTIPLIER


@public
def test_class_from_import(w: int, h: int) -> int:
    r: Rectangle = Rectangle(w, h)
    return r.area()


@public
def test_class_via_module(w: int, h: int) -> int:
    r: Rectangle = shapes.Rectangle(w, h)
    return r.perimeter()


@public
def test_multiply(a: int, b: int) -> int:
    return multiply(a, b)
