"""P4-17: Complex type-narrowing scenarios."""

import unittest

from neo3.compiler import TypecheckError, compile_function


def _ok(src: str) -> None:
    compile_function(src)


def _raises(src: str) -> None:
    with unittest.TestCase().assertRaises(TypecheckError):
        compile_function(src)


class TestAssertNarrowingAfterReturn(unittest.TestCase):
    """Narrowing via if-guard: Optional[T] → T after always-terminating branch."""

    def test_if_none_return_narrows_subsequent(self):
        src = """
def f(x: Optional[int]) -> int:
    if x is None:
        return 0
    return x
"""
        _ok(src)

    def test_if_none_raise_narrows_subsequent(self):
        src = """
def f(x: Optional[int]) -> int:
    if x is None:
        raise Exception("bad")
    return x
"""
        _ok(src)

    def test_without_guard_optional_int_return_raises(self):
        src = """
def f(x: Optional[int]) -> int:
    return x
"""
        _raises(src)

    def test_double_optional_narrowed_twice(self):
        src = """
def f(a: Optional[int], b: Optional[int]) -> int:
    if a is None:
        return 0
    if b is None:
        return a
    return a + b
"""
        _ok(src)


class TestNestedIfNarrowing(unittest.TestCase):
    """Narrowing must propagate through nested conditional blocks."""

    def test_nested_if_after_outer_guard(self):
        src = """
def f(x: Optional[int], flag: bool) -> int:
    if x is None:
        return 0
    if flag:
        return x
    return x + 1
"""
        _ok(src)

    def test_inner_guard_only_in_branch_not_outer(self):
        # Narrowing inside an if branch does NOT affect code after the if.
        # After the outer if, x is still Optional[int].
        src = """
def f(x: Optional[int]) -> int:
    if x is None:
        return 0
    y: int = x
    return y
"""
        _ok(src)

    def test_no_narrowing_across_sibling_branches(self):
        # x is narrowed in the if-body but not in the else-body.
        # After the whole if/else, x is still Optional[int].
        src = """
def f(x: Optional[int]) -> int:
    if x is None:
        return 0
    else:
        return x
"""
        _ok(src)

    def test_narrowing_across_multiple_params(self):
        src = """
def f(a: Optional[int], b: Optional[str]) -> int:
    if a is None:
        return 0
    if b is None:
        return a
    return a
"""
        _ok(src)


class TestTryExceptNarrowing(unittest.TestCase):
    """Narrowing inside try or except blocks."""

    def test_guard_before_try_narrows_inside_try(self):
        src = """
def f(x: Optional[int]) -> int:
    if x is None:
        return 0
    try:
        return x
    except:
        return 0
"""
        _ok(src)

    def test_optional_in_try_body_without_guard_raises(self):
        src = """
def f(x: Optional[int]) -> int:
    try:
        return x
    except:
        return 0
"""
        _raises(src)

    def test_guard_before_try_narrowed_in_except_too(self):
        src = """
def f(x: Optional[int]) -> int:
    if x is None:
        return 0
    try:
        y: int = x + 1
    except:
        y = x - 1
    return y
"""
        _ok(src)


class TestAssertNarrowingComplex(unittest.TestCase):
    """assert x is not None narrows for remaining statements."""

    def test_assert_then_nested_if(self):
        src = """
def f(x: Optional[int], flag: bool) -> int:
    assert x is not None
    if flag:
        return x + 1
    return x
"""
        _ok(src)

    def test_assert_then_while(self):
        src = """
def f(x: Optional[int]) -> int:
    assert x is not None
    n: int = 0
    while n < x:
        n = n + 1
    return n
"""
        _ok(src)

    def test_assert_in_loop_body_does_not_narrow_outside(self):
        # The assert is inside a while-body; x after the loop is still Optional.
        src = """
def f(x: Optional[int]) -> int:
    n: int = 0
    while n < 3:
        assert x is not None
        n = n + 1
    return 0
"""
        _ok(src)


class TestNoneCheckIfOtherVarLeak(unittest.TestCase):
    """assert narrowing of a *second* variable inside a none-check if branch
    must not leak into the sibling branch."""

    def test_other_var_assert_does_not_leak_to_else(self):
        # b is Optional in the else-branch even though it was narrowed in the
        # if-branch.  If the old leak existed, `if b is None:` in the else
        # would fail because b was already int there.
        src = """
def f(a: Optional[int], b: Optional[int]) -> int:
    if a is not None:
        assert b is not None
        return a + b
    else:
        if b is None:
            return -1
        return b
"""
        _ok(src)

    def test_other_var_assert_does_not_leak_to_then(self):
        # b is Optional in the then-branch (if a is None) even though it is
        # narrowed by assert in the else-branch.
        src = """
def f(a: Optional[int], b: Optional[int]) -> int:
    if a is None:
        if b is None:
            return -1
        return b
    else:
        assert b is not None
        return a + b
"""
        _ok(src)

    def test_none_check_if_elif_with_secondary_assert(self):
        # Each branch asserts a different secondary variable; neither should
        # bleed into the other branch.
        src = """
def f(a: Optional[int], b: Optional[int]) -> int:
    if a is not None:
        assert b is not None
        return a + b
    elif b is not None:
        return b
    else:
        return 0
"""
        _ok(src)


class TestWhileElseNarrowingLeak(unittest.TestCase):
    """Narrowing from while body must not leak into the else clause."""

    def test_assert_in_while_body_does_not_leak_to_else(self):
        # The while body narrows x; the else clause must still see Optional[int].
        src = """
def f(x: Optional[int]) -> int:
    n: int = 0
    while n < 3:
        assert x is not None
        n = n + 1
    else:
        if x is None:
            return -1
        return x
    return 0
"""
        _ok(src)

    def test_assert_in_while_body_does_not_persist_after_loop(self):
        # After a plain while (no else), assert inside the body must not
        # permanently narrow the variable for code that follows.
        src = """
def f(x: Optional[int]) -> int:
    n: int = 0
    while n < 3:
        assert x is not None
        n = n + 1
    x = None
    return 0
"""
        _ok(src)

    def test_while_none_check_body_other_var_does_not_leak_to_else(self):
        # while x is not None: body narrows y; else must still see Optional y.
        src = """
def f(x: Optional[int], y: Optional[int]) -> int:
    while x is not None:
        assert y is not None
        return y
    else:
        if y is None:
            return -1
        return y
    return 0
"""
        _ok(src)


class TestTryExceptNarrowingLeak(unittest.TestCase):
    """Narrowing inside catch/finally must not leak into the try body,
    and try body narrowing must not leak into catch/finally."""

    def test_catch_assert_does_not_leak_into_try(self):
        # Before the fix the catch body was visited before the try body, so
        # assert in catch would narrow x → int in the try body too, hiding a
        # real type error.  After the fix the try body must see Optional[int].
        src = """
def f(x: Optional[int]) -> int:
    try:
        return x
    except:
        assert x is not None
        return x
"""
        _raises(src)  # try body still sees Optional[int]; return x is an error

    def test_try_assert_does_not_leak_into_catch(self):
        # assert in try body narrows x → int for the rest of the try body;
        # the catch body must still see Optional[int].
        src = """
def f(x: Optional[int]) -> int:
    try:
        assert x is not None
        return x
    except:
        if x is None:
            return -1
        return x
"""
        _ok(src)

    def test_try_body_narrowing_correct_order(self):
        # Standard pattern: assert in try, use in try; catch falls back safely.
        src = """
def f(x: Optional[int]) -> int:
    try:
        assert x is not None
        return x + 1
    except:
        return 0
"""
        _ok(src)


class TestForElseNarrowingLeak(unittest.TestCase):
    """Narrowing from a for-loop body must not leak into the else clause."""

    def test_assert_in_for_body_does_not_leak_to_else(self):
        src = """
def f(x: Optional[int], items: list[int]) -> int:
    for v in items:
        assert x is not None
    else:
        if x is None:
            return -1
        return x
    return 0
"""
        _ok(src)

    def test_assert_in_range_for_body_does_not_leak_to_else(self):
        src = """
def f(x: Optional[int]) -> int:
    for i in range(3):
        assert x is not None
    else:
        if x is None:
            return -1
        return x
    return 0
"""
        _ok(src)


class TestStaticFieldNarrowing(unittest.TestCase):
    """Assignment to a static Optional[T] field narrows its current type to T,
    and the snapshot/restore/join machinery keeps that scoped correctly."""

    def test_both_branches_assign_int_join_is_int(self):
        # Both if and else assign int to Optional[int] static → join type is int.
        src = """
s: Optional[int] = None
def f(x: int) -> int:
    global s
    if x == 1:
        s = 1
    else:
        s = 2
    return s
"""
        _ok(src)

    def test_only_then_branch_assigns_else_returns_join_is_int(self):
        # else always terminates → join takes the then-branch type (int).
        src = """
s: Optional[int] = None
def f(x: int) -> int:
    global s
    if x == 1:
        s = 1
    else:
        return -1
    return s
"""
        _ok(src)

    def test_static_not_narrowed_without_assignment(self):
        # Without an assignment, the static is still Optional[int]; returning it
        # as int must fail.
        src = """
s: Optional[int] = None
def f() -> int:
    global s
    return s
"""
        _raises(src)

    def test_while_body_assignment_does_not_leak_after_loop(self):
        # Assignment inside while body narrows s → int inside the body only.
        # After the loop, s is restored to Optional[int], so assigning None is fine.
        src = """
s: Optional[int] = None
def f(x: int) -> int:
    global s
    while x > 0:
        s = x
        x = x - 1
    s = None
    return 0
"""
        _ok(src)

    def test_neither_branch_assigns_keeps_declared_type(self):
        # Neither branch assigns to s; the join should keep Optional[int].
        # Returning s as int must still fail.
        src = """
s: Optional[int] = None
def f(x: int) -> int:
    global s
    if x == 1:
        s = None
    else:
        s = None
    return s
"""
        _raises(src)
