from __future__ import annotations


class Account:

    json_schema = {
        "type": "object",
        "properties": {
            "address": {"type": "string"},
            "label": {"type": "string"},
            "is_default": {"type": "boolean"},
            "lock": {"type": "boolean"},
            "key": {"type": "string"},
            "contract": {"type": ""},
            "extra": {"type": ["object", "null"],
                      "properties": {},
                      "additionalProperties": True
                      }
        },
        "required": ["address", "label", "is_default", "lock", "key", "contract", "extra"]
    }

    # this is a placeholder to test the accounts, it will be better implemented later

    def __init__(self):
        self.address = ''
        self.label = ''
        self.is_default = True
        self.lock = False
        self.key = ''
        self.contract = {}
        self.extra = None

    def to_json(self) -> dict:
        # placeholder
        return {}

    @classmethod
    def from_json(cls, json: dict) -> Account:
        # placeholder
        return cls()
