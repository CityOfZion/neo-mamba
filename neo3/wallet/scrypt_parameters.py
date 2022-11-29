from __future__ import annotations
from jsonschema import validate  # type: ignore
from neo3.core import interfaces


class ScryptParameters(interfaces.IJson):

    json_schema = {
        "type": "object",
        "properties": {
            "n": {"type": "integer"},
            "r": {"type": "integer"},
            "p": {"type": "integer"},
        },
        "required": ["n", "r", "p"],
    }

    def __init__(self, n: int = 16384, r: int = 8, p: int = 8):
        self.n = n
        self.r = r
        self.p = p

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """
        return {"n": self.n, "r": self.r, "p": self.p}

    @classmethod
    def from_json(cls, json: dict) -> ScryptParameters:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary key.
        """
        validate(json, schema=cls.json_schema)

        return cls(n=json["n"], r=json["r"], p=json["p"])
