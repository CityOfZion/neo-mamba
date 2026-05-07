from neo3.sc.compiletime import public

# ── list comprehension / range ────────────────────────────────────────────────


@public
def list_comp_range_basic() -> list[int]:
    return [x for x in range(5)]


@public
def list_comp_range_transform() -> list[int]:
    return [x * x for x in range(5)]


@public
def list_comp_range_filter() -> list[int]:
    return [x for x in range(10) if x % 2 == 0]


@public
def list_comp_range_step() -> list[int]:
    return [x for x in range(0, 10, 3)]


@public
def list_comp_range_negative_step() -> list[int]:
    return [x for x in range(9, -1, -3)]


@public
def list_comp_empty() -> list[int]:
    return [x for x in range(0)]


# ── list comprehension / list iterable ───────────────────────────────────────


@public
def list_comp_list_identity(lst: list[int]) -> list[int]:
    return [x for x in lst]


@public
def list_comp_list_transform(lst: list[int]) -> list[int]:
    return [x * 2 for x in lst]


@public
def list_comp_list_filter(lst: list[int]) -> list[int]:
    return [x for x in lst if x > 0]


# ── list comprehension used in expression ────────────────────────────────────


@public
def list_comp_in_len_expr() -> int:
    return len([x for x in range(7)])


# ── dict comprehension / range ────────────────────────────────────────────────


@public
def dict_comp_range_lookup() -> int:
    d: dict[int, int] = {x: x * x for x in range(5)}
    return d[3]


@public
def dict_comp_range_len() -> int:
    d: dict[int, int] = {x: x * x for x in range(5)}
    return len(d)


@public
def dict_comp_range_filter_len() -> int:
    d: dict[int, int] = {x: x * x for x in range(10) if x % 2 == 0}
    return len(d)


# ── dict comprehension / list iterable ───────────────────────────────────────


@public
def dict_comp_list_lookup(lst: list[int]) -> int:
    d: dict[int, int] = {k: k * 2 for k in lst}
    return d[2]
