from __future__ import annotations

import base64
from typing import List

from neo3 import contracts


class NEP6Contract(contracts.Contract):

    def __init__(self, script: bytes, parameter_list: List[contracts.ContractParameterType]):
        super().__init__(script, parameter_list)
        self.parameter_names: List[str] = []
        self.deployed: bool = False

    @classmethod
    def from_json(cls, json: dict) -> NEP6Contract:
        parameters = list(map(lambda p: contracts.ContractParameterDefinition.from_json(p),
                              json['parameters']
                              ))
        contract = cls(
            script=base64.b64decode(json['script']),
            parameter_list=[param.type for param in parameters]
        )
        contract.parameter_names = [param.name for param in parameters]
        contract.deployed = json['deployed']

        return contract

    def to_json(self) -> dict:
        return {
            'script': base64.b64encode(self.script).decode('utf-8'),
            'parameters': list(map(lambda index: {'name': self.parameter_names[index],
                                                  'type': self.parameter_list[index].PascalCase()
                                                  },
                                   range(len(self.parameter_list)))),
            'deployed': self.deployed
        }
