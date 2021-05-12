from __future__ import annotations
from enum import IntEnum, auto
from typing import Iterator, List
import json


class JsonPathType(IntEnum):
    ROOT = auto()
    DOT = auto()
    LEFT_BRACKET = auto()
    RIGHT_BRACKET = auto()
    ASTERISK = auto()
    COMMA = auto()
    COLON = auto()
    IDENTIFIER = auto()
    STRING = auto()
    NUMBER = auto()


class FormatException(ValueError):
    pass


class MaxDepthException(Exception):
    pass


class JsonPathToken:
    def __init__(self):
        self.type = None
        self.content: str = ''

    def __len__(self):
        try:
            return len(self.content)
        except TypeError:
            return 0

    def __repr__(self):
        return f"<JsonPathToken @ {hex(id(self))}> {self.type.name}: {self.content}"

    @staticmethod
    def parse(expression: str) -> Iterator[JsonPathToken]:
        i = 0
        while i < len(expression):
            token = JsonPathToken()
            c = expression[i]
            if c == '$':
                token.type = JsonPathType.ROOT
            elif c == '.':
                token.type = JsonPathType.DOT
            elif c == '[':
                token.type = JsonPathType.LEFT_BRACKET
            elif c == ']':
                token.type = JsonPathType.RIGHT_BRACKET
            elif c == '*':
                token.type = JsonPathType.ASTERISK
            elif c == ',':
                token.type = JsonPathType.COMMA
            elif c == ':':
                token.type = JsonPathType.COLON
            elif c == '\'':
                token.type = JsonPathType.STRING
                token.content = JsonPathToken.parse_string(expression, i)
                i += len(token) - 1
            elif c == '_' or c.isalpha():
                token.type = JsonPathType.IDENTIFIER
                token.content = JsonPathToken.parse_identifier(expression, i)
                i += len(token) - 1
            elif c == '-' or c.isdigit():
                token.type = JsonPathType.NUMBER
                token.content = JsonPathToken.parse_number(expression, i)
                i += len(token) - 1
            else:
                raise FormatException("Invalid token")

            yield token
            i += 1

    @staticmethod
    def parse_string(expression: str, start: int) -> str:
        for i, c in enumerate(expression[start:]):
            if c == '\'':
                return expression[start:start + i]
        else:
            raise FormatException("No closing \' found")

    @staticmethod
    def parse_identifier(expression: str, start: int) -> str:
        for i, c in enumerate(expression[start:]):
            if c != '_' and not c.isalpha() and not c.isdigit():
                return expression[start:start + i]
        else:
            return expression[start:]

    @staticmethod
    def parse_number(expression: str, start: int) -> str:
        for i, c in enumerate(expression[start + 1:]):
            if not c.isdigit():
                return expression[start:start + i + 1]
        else:
            return expression[start:]


class JsonPath:
    def __init__(self, json_: dict):
        self.json = json_
        self.max_depth = -1
        self.depth = -1

    def next_token(self):
        return next(self.tokens)

    def parse(self, expression: str, max_depth=6):
        if len(expression) == 0:
            return self.json
        self.max_depth = self.depth = max_depth
        self.tokens = JsonPathToken.parse(expression)
        first = self.next_token()
        if first.type != JsonPathType.ROOT:
            raise FormatException("First token must be ROOT ($)")

        objects: List[object] = [self.json]
        for token in self.tokens:
            if token.type == JsonPathType.DOT:
                objects = self.process_dot(objects)
            elif token.type == JsonPathType.LEFT_BRACKET:
                objects = self.process_left_bracket(objects)
        return objects

    def process_dot(self, objects: List[object]):
        token = self.next_token()
        if token.type == JsonPathType.ASTERISK:
            return self.descent(objects)
        elif token.type == JsonPathType.DOT:
            return self.descent_recursive(objects)
        elif token.type == JsonPathType.IDENTIFIER:
            return self.descent_identifier(objects, [token.content])
        else:
            raise FormatException("Invalid token")

    def descent(self, objects):
        self._check_depth()
        values = []
        for obj in objects:
            if isinstance(obj, list):
                values.extend(obj)
            if isinstance(obj, dict):
                keys = sorted(obj.keys(), reverse=True)
                for k in keys:
                    values.append(obj[k])
        return values

    def descent_recursive(self, objects):
        token = self.next_token()
        if token.type != JsonPathType.IDENTIFIER:
            raise FormatException(f"Expected IDENTIFIER got {token.type.name}")

        values = []
        while len(objects) > 0:
            values.extend(self.descent_identifier(objects, [token.content], check_depth=False))
            objects = self.descent(objects)
        return values

    def descent_identifier(self, objects, names: List[str], check_depth=True):
        if check_depth:
            self._check_depth()
        values = []
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            for name in names:
                if name in obj:
                    values.append(obj[name])
        return values

    def process_left_bracket(self, objects):
        token = self.next_token()
        if token.type == JsonPathType.ASTERISK:
            token = self.next_token()
            if token.type != JsonPathType.RIGHT_BRACKET:
                raise FormatException(f"Only RIGHT_BRACKET is valid after `[*` found {token.type.name}")
            return self.descent(objects)
        elif token.type == JsonPathType.COLON:
            return self.process_slice(objects, 0)
        elif token.type == JsonPathType.NUMBER:
            next = self.next_token()
            if next.type == JsonPathType.COLON:
                return self.process_slice(objects, int(token.content))
            elif next.type == JsonPathType.COMMA:
                return self.process_union(objects, token)
            elif next.type == JsonPathType.RIGHT_BRACKET:
                return self.descent_index(objects, [int(token.content)])
            else:
                raise FormatException("Bracket group parsing failure for bracket with number")
        elif token.type == JsonPathType.STRING:
            next = self.next_token()
            if next.type == JsonPathType.COMMA:
                return self.process_union(objects, token)
            elif next.type == JsonPathType.RIGHT_BRACKET:
                return self.descent_identifier(objects, token.content)
            else:
                raise FormatException("Bracket group parsing failure for bracket with string")
        return objects

    def process_slice(self, objects, start: int):
        token = self.next_token()
        if token.type == JsonPathType.NUMBER:
            next = self.next_token()
            if next.type != JsonPathType.RIGHT_BRACKET:
                raise FormatException()
            return self.descent_range(objects, start, int(token.content))
        elif token.type == JsonPathType.RIGHT_BRACKET:
            return self.descent_range(objects, start, 0)
        else:
            raise FormatException()

    def process_union(self, objects, first_token):
        items = [first_token]
        while True:
            token = self.next_token()
            if token.type != first_token.type:
                raise FormatException()
            items.append(token)

            token = self.next_token()
            if token.type == JsonPathType.RIGHT_BRACKET:
                break
            if token.type != JsonPathType.COMMA:
                raise FormatException()

        if first_token.type == JsonPathType.NUMBER:
            items = list(map(lambda i: int(i.content), items))
            return self.descent_index(objects, items)
        elif first_token.type == JsonPathType.STRING:
            for item in items:
                item.content = item.content.replace("'", "")
            return self.descent_identifier(objects, items)
        else:
            raise FormatException()

    def descent_index(self, objects, indices: List[int]):
        self._check_depth()
        values = []
        for obj in objects:
            if not isinstance(obj, list):
                continue
            for idx in indices:
                if idx < 0:
                    idx += len(obj)
                if 0 <= idx < len(obj):
                    values.append(obj[idx])
        return values

    def descent_range(self, objects, start: int, end: int):
        self._check_depth()
        values = []
        for obj in objects:
            if not isinstance(obj, list):
                continue
            sub_start = start
            if sub_start < 0:
                sub_start += len(obj)

            sub_end = end
            if sub_end <= 0:
                sub_end += len(obj)

            if sub_end > len(obj):
                sub_end = len(obj)

            if sub_end - sub_start < 0:
                raise FormatException()

            values.extend(obj[sub_start:sub_end])

        return values

    def _check_depth(self):
        if self.depth <= 0:
            raise MaxDepthException()
        self.max_depth -= 1
