import json
import binascii
from types import SimpleNamespace
from neo3.core import cryptography


class IndexableNamespace(SimpleNamespace):
    def __len__(self):
        return len(self.__dict__)

    def __getitem__(self, key):
        return self.__dict__[key]

    def __contains__(self, key):
        try:
            self.__dict__[key]
            return True
        except KeyError:
            return False

    def get(self, key, default=None):
        try:
            return self.__dict__[key]
        except KeyError:
            return default


class Settings(IndexableNamespace):
    db = None
    _cached_standby_committee = None
    default_settings = {
        "network": {
            "magic": 5195086,
            "account_version": 53,
            "seedlist": [],
            "validators_count": 1,
            "standby_committee": [
                "02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765"
            ],
        },
    }

    @classmethod
    def from_json(cls, json: dict):
        o = cls(**json)
        o._convert(o.__dict__, o.__dict__)
        return o

    @classmethod
    def from_file(cls, path_to_json: str):
        with open(path_to_json, "r") as f:
            data = json.load(f)
        return cls.from_json(data)

    def register(self, json: dict):
        self.__dict__.update(json)
        self._convert(self.__dict__, self.__dict__)

    def _convert(self, what: dict, where: dict):
        # turn all _dictionary what into IndexableNamespaces
        to_update = []
        for k, v in what.items():
            if isinstance(v, dict):
                to_update.append((k, IndexableNamespace(**v)))

        for k, v in to_update:
            if isinstance(where, dict):
                where.update({k: v})
            else:
                where.__dict__.update({k: v})
            self._convert(where[k].__dict__, where[k].__dict__)

    @property
    def standby_committee(self) -> list[cryptography.ECPoint]:
        if self._cached_standby_committee is None:
            points = []
            for p in self.network.standby_committee:
                points.append(
                    cryptography.ECPoint.deserialize_from_bytes(binascii.unhexlify(p))
                )
            self._cached_standby_committee = points
        return self._cached_standby_committee

    @property
    def standby_validators(self) -> list[cryptography.ECPoint]:
        return self.standby_committee[: self.network.validators_count]

    def reset_settings_to_default(self):
        self.__dict__.clear()
        self.__dict__.update(self.from_json(self.default_settings).__dict__)


settings = Settings.from_json(Settings.default_settings)
