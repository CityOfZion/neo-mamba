from typing import Optional

from neo3.sc.compiletime import public
from neo3.sc.contracts.management import ContractManagement
from neo3.sc.types import ContractState, UInt160
from neo3.sc.utils.iterator import Iterator


@public
def query_contract(hash: UInt160) -> Optional[ContractState]:
    return ContractManagement.get_contract(hash)


@public
def get_min_fee() -> int:
    return ContractManagement.get_minimum_deployment_fee()


@public
def query_by_id(contract_id: int) -> Optional[ContractState]:
    return ContractManagement.get_contract_by_id(contract_id)


@public
def count_deployed() -> int:
    it: Iterator = ContractManagement.get_contract_hashes()
    count: int = 0
    while it.next():
        count = count + 1
    return count
