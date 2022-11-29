import abc


class IJson(abc.ABC):
    @abc.abstractmethod
    def to_json(self) -> dict:
        """Convert object into JSON representation."""

    @classmethod
    @abc.abstractmethod
    def from_json(cls, json: dict):
        """Create object from JSON"""
