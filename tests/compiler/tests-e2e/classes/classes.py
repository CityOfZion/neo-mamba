from neo3.sc.compiletime import public

# Tier 13: classes — instance fields, methods, inheritance, super(), statics,
# @staticmethod, @classmethod.


# ---------------------------------------------------------------------------
# Counter — basic __init__, void instance method, field read/write
# ---------------------------------------------------------------------------


class Counter:
    def __init__(self: Counter, start: int) -> None:
        self.value: int = start

    def increment(self: Counter) -> None:
        self.value = self.value + 1

    def add(self: Counter, n: int) -> None:
        self.value = self.value + n

    def get(self: Counter) -> int:
        return self.value


@public
def counter_basic(start: int, steps: int) -> int:
    """Increment `start` by 1 `steps` times and return the result."""
    c: Counter = Counter(start)
    i: int = 0
    while i < steps:
        c.increment()
        i = i + 1
    return c.get()


@public
def counter_add(start: int, delta: int) -> int:
    """Create a Counter at `start`, add `delta`, return the value."""
    c: Counter = Counter(start)
    c.add(delta)
    return c.get()


@public
def two_counters(a: int, b: int) -> int:
    """Two independent Counter instances — mutations must not alias."""
    x: Counter = Counter(a)
    y: Counter = Counter(b)
    x.increment()
    return x.get() + y.get()


# ---------------------------------------------------------------------------
# Point — multiple fields, method using both fields
# ---------------------------------------------------------------------------


class Point:
    def __init__(self: Point, x: int, y: int) -> None:
        self.x: int = x
        self.y: int = y

    def manhattan(self: Point) -> int:
        return self.x + self.y

    def scale(self: Point, factor: int) -> None:
        self.x = self.x * factor
        self.y = self.y * factor


@public
def point_manhattan(x: int, y: int) -> int:
    p: Point = Point(x, y)
    return p.manhattan()


@public
def point_scale(x: int, y: int, factor: int) -> int:
    p: Point = Point(x, y)
    p.scale(factor)
    return p.manhattan()


# ---------------------------------------------------------------------------
# MathHelper — @staticmethod (no self or cls)
# ---------------------------------------------------------------------------


class MathHelper:
    @staticmethod
    def square(n: int) -> int:
        return n * n

    @staticmethod
    def add(a: int, b: int) -> int:
        return a + b


@public
def static_square(n: int) -> int:
    return MathHelper.square(n)


@public
def static_add(a: int, b: int) -> int:
    return MathHelper.add(a, b)


# ---------------------------------------------------------------------------
# Config — class variable (module-level static)
# ---------------------------------------------------------------------------


class Config:
    limit: int = 42

    def get_limit(self: Config) -> int:
        return Config.limit


@public
def class_var_get() -> int:
    c: Config = Config()
    return c.get_limit()


# ---------------------------------------------------------------------------
# Animal / Dog — single inheritance + super().__init__
# ---------------------------------------------------------------------------


class Animal:
    def __init__(self: Animal, weight: int) -> None:
        self.weight: int = weight

    def get_weight(self: Animal) -> int:
        return self.weight


class Dog(Animal):
    def __init__(self: Dog, weight: int, age: int) -> None:
        super().__init__(weight)
        self.age: int = age

    def get_age(self: Dog) -> int:
        return self.age

    def total(self: Dog) -> int:
        return self.weight + self.age


@public
def dog_weight(w: int, a: int) -> int:
    d: Dog = Dog(w, a)
    return d.get_weight()


@public
def dog_age(w: int, a: int) -> int:
    d: Dog = Dog(w, a)
    return d.get_age()


@public
def dog_total(w: int, a: int) -> int:
    d: Dog = Dog(w, a)
    return d.total()


# ---------------------------------------------------------------------------
# Box — @classmethod factory
# ---------------------------------------------------------------------------


class Box:
    def __init__(self: Box, size: int) -> None:
        self.size: int = size

    @classmethod
    def default(cls) -> Box:
        return cls(10)

    def get_size(self: Box) -> int:
        return self.size


@public
def classmethod_default() -> int:
    b: Box = Box.default()
    return b.get_size()


@public
def classmethod_explicit(n: int) -> int:
    b: Box = Box(n)
    return b.get_size()
