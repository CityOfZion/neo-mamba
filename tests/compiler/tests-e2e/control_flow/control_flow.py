from neo3.sc.compiletime import public


@public
def if_positive_negative(x: int) -> int:
    if x > 0:
        return 1
    else:
        return -1


@public
def if_no_else(x: int) -> int:
    result: int = 0
    if x > 0:
        result = 1
    return result


@public
def elif_chain(x: int) -> int:
    if x < 0:
        return -1
    elif x == 0:
        return 0
    else:
        return 1


@public
def nested_if(x: int, y: int) -> int:
    if x > 0:
        if y > 0:
            return 1
        else:
            return 2
    else:
        return 3


@public
def while_sum(n: int) -> int:
    result: int = 0
    i: int = 0
    while i < n:
        result = result + i
        i = i + 1
    return result


@public
def while_break(limit: int) -> int:
    i: int = 0
    while True:
        if i >= limit:
            break
        i = i + 1
    return i


@public
def while_continue_odd_sum(n: int) -> int:
    result: int = 0
    i: int = 0
    while i < n:
        i = i + 1
        if i % 2 == 0:
            continue
        result = result + i
    return result


@public
def while_else_no_break(n: int) -> int:
    i: int = 0
    while i < n:
        i = i + 1
    else:
        return 99
    return 0


@public
def while_else_with_break(n: int, target: int) -> int:
    i: int = 0
    while i < n:
        if i == target:
            break
        i = i + 1
    else:
        return -1
    return i


@public
def for_sum(n: int) -> int:
    result: int = 0
    for i in range(n):
        result = result + i
    return result


@public
def for_range_start_stop(start: int, stop: int) -> int:
    result: int = 0
    for i in range(start, stop):
        result = result + i
    return result


@public
def for_range_step2(start: int, stop: int) -> int:
    result: int = 0
    for i in range(start, stop, 2):
        result = result + i
    return result


@public
def for_range_step3(start: int, stop: int) -> int:
    result: int = 0
    for i in range(start, stop, 3):
        result = result + i
    return result


@public
def for_break_sum(n: int, limit: int) -> int:
    result: int = 0
    for i in range(n):
        if i == limit:
            break
        result = result + i
    return result


@public
def for_continue_sum(n: int) -> int:
    result: int = 0
    for i in range(n):
        if i % 2 == 0:
            continue
        result = result + i
    return result


@public
def for_else_no_break(n: int) -> int:
    total: int = 0
    for i in range(n):
        total = total + i
    else:
        return 99
    return 0


@public
def for_else_with_break(n: int, target: int) -> int:
    for i in range(n):
        if i == target:
            break
    else:
        return -1
    return i
