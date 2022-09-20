import abc


class IJson(abc.ABC):
    @abc.abstractmethod
    def to_json(self) -> dict:
        """ convert object into json """

    @classmethod
    @abc.abstractmethod
    def from_json(cls, json: dict):
        """ create object from JSON """
