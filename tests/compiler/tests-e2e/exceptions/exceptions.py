from neo3.sc.compiletime import public

# ── try/except — no exception ──────────────────────────────────────────────────


@public
def try_except_no_exception() -> int:
    result: int = 0
    try:
        result = 42
    except:
        result = -1
    return result


# ── try/except — exception raised via raise ────────────────────────────────────


@public
def try_except_with_raise() -> int:
    result: int = 0
    try:
        raise Exception("oops")
        result = 42
    except:
        result = -1
    return result


# ── try/except — assert False caught ─────────────────────────────────────────


@public
def try_except_assert_false() -> int:
    result: int = 0
    try:
        assert False
        result = 1
    except:
        result = 99
    return result


@public
def try_except_assertmsg_caught() -> int:
    result: int = 0
    try:
        assert False, "bad"
        result = 1
    except:
        result = 99
    return result


# ── try/finally — no exception ────────────────────────────────────────────────


@public
def try_finally_no_exception() -> int:
    result: int = 0
    try:
        result = 10
    finally:
        result += 5
    return result


# ── try/except/finally — no exception ─────────────────────────────────────────


@public
def try_except_finally_no_exception() -> int:
    result: int = 0
    try:
        result = 10
    except:
        result = -1
    finally:
        result += 100
    return result


# ── try/except/finally — exception path ───────────────────────────────────────


@public
def try_except_finally_with_exception() -> int:
    result: int = 0
    try:
        raise Exception("oops")
        result = 10
    except:
        result = -1
    finally:
        result += 100
    return result


# ── cross-call propagation ────────────────────────────────────────────────────


def _always_raises() -> None:
    raise Exception("from helper")


@public
def cross_call_exception_caught() -> int:
    try:
        _always_raises()
        return 1
    except:
        return -1


# ── nested try ────────────────────────────────────────────────────────────────


@public
def nested_try_inner_caught() -> int:
    result: int = 0
    try:
        try:
            raise Exception("inner")
            result = 1
        except:
            result = 10
        result += 1
    except:
        result = -99
    return result


# ── return inside try / except ────────────────────────────────────────────────


@public
def return_in_try_body() -> int:
    try:
        return 1
    except:
        return 2


@public
def return_in_except_body() -> int:
    try:
        raise Exception("x")
        return 1
    except:
        return 2


# ── code continues after try/except ───────────────────────────────────────────


@public
def code_after_try_continues() -> int:
    result: int = 0
    try:
        result = 5
    except:
        result = -1
    result += 10
    return result
