from typing import Any, Optional

from neo3.sc.compiletime import call_flags, contract, display_name
from neo3.sc.types import CallFlags, ContractState, UInt160
from neo3.sc.utils.iterator import Iterator


@contract("0xfffdc93764dbaddd97c48f252a53ea4643faa3fd")
class ContractManagement:
    """
    Represents the ContractManagement native contract.
    """

    hash: UInt160

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("getMinimumDeploymentFee")
    def get_minimum_deployment_fee() -> int:
        """Return the minimum GAS fee required to deploy a contract."""
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("getContract")
    def get_contract(hash: UInt160) -> Optional[ContractState]:
        """Return the deployed contract with the specified hash, or None."""
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("getContractById")
    def get_contract_by_id(contract_id: int) -> Optional[ContractState]:
        """Return the deployed contract with the specified numeric ID, or None."""
        pass

    @staticmethod
    @call_flags(CallFlags.READ_STATES)
    @display_name("getContractHashes")
    def get_contract_hashes() -> Iterator:
        """Return an iterator over (id, hash) pairs for all deployed contracts."""
        pass

    @staticmethod
    def deploy(nef_file: bytes, manifest: bytes, data: Any = None) -> ContractState:
        """Deploy a new smart contract.

        Args:
            nef_file: the compiled NEF bytes.
            manifest: the contract manifest as UTF-8 JSON bytes.
            data: optional data passed to the ``_deploy`` method. Defaults to None.

        Returns:
            ContractState of the newly deployed contract.
        """
        pass

    @staticmethod
    def update(
        nef_file: Optional[bytes], manifest: Optional[bytes], data: Any = None
    ) -> None:
        """Update the executing smart contract.

        Args:
            nef_file: the new compiled NEF (or None to keep current).
            manifest: the new manifest JSON bytes (or None to keep current).
            data: optional data passed to the ``_deploy`` method. Defaults to None.
        """
        pass

    @staticmethod
    def destroy() -> None:
        """Destroy the executing smart contract."""
        pass
