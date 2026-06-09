from typing import Any

from neo3.sc.compiletime import display_name, contract
from neo3.sc.types import ECPoint, UInt160, NeoAccountState
from neo3.sc.utils.iterator import Iterator


@contract("0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5")
class NeoToken:
    """
    Represents the NEO native contract.

    See:
        https://developers.neo.org/docs/n3/reference/scapi/framework/native/Neo
        for more details about this contract.
    """

    hash: UInt160

    @staticmethod
    def symbol() -> str:
        """Get the token symbol"""
        pass

    @staticmethod
    def decimals() -> int:
        """Get the number of supported decimals."""
        pass

    @staticmethod
    @display_name("totalSupply")
    def total_supply() -> int:
        """
        Get the total token supply deployed in the system.
        """
        pass

    @staticmethod
    @display_name("balanceOf")
    def balance_of(account: UInt160) -> int:
        """
        Get the token balance for the given `account`.
        """
        pass

    @staticmethod
    def transfer(
        from_address: UInt160, to_address: UInt160, amount: int, data: Any = None
    ) -> bool:
        """
        Move `amount` of tokens from `from_account` to `to_account`. If successful a `Transfer` event is emitted
        even if the amount is 0 or the sender and receiver are the same.

        Returns:
            `True` if successful.

        Note:
            If `to_account` is a smart contract with a `onNEP17Payment` handler then `data` will be passed to that handler.
        """
        pass

    @staticmethod
    @display_name("getGasPerBlock")
    def get_gas_per_block() -> int:
        """
        Get the amount of GAS generated per block.
        """
        pass

    @staticmethod
    @display_name("unclaimedGas")
    def unclaimed_gas(account: UInt160, end: int) -> int:
        """
        Get the amount of unclaimed GAS for an account.

        Args:
            account: The account to check.
            end: The block index used in the calculation.
        """
        pass

    @staticmethod
    @display_name("registerCandidate")
    def register_candidate(pubkey: ECPoint) -> bool:
        """
        Register an account as a candidate.

        Args:
            pubkey: The public key of the account.

        Returns:
            bool: True if registration succeeded, False otherwise.
        """
        pass

    @staticmethod
    @display_name("unregisterCandidate")
    def unregister_candidate(pubkey: ECPoint) -> bool:
        """
        Unregister an account as a candidate.

        Args:
            pubkey: The public key of the account.

        Returns:
            bool: True if unregistration succeeded, False otherwise.
        """
        pass

    @staticmethod
    def vote(account: UInt160, vote_to: ECPoint) -> bool:
        """
        Vote for a candidate.

        Args:
            account: The voting account.
            vote_to: The candidate's public key.

        Returns:
            bool: True if the vote succeeded, False otherwise.

        Note:
            Set `vote_to` to `None` to remove a vote.
        """
        pass

    @staticmethod
    @display_name("getAllCandidates")
    def get_all_candidates() -> Iterator:
        """
        Get all registered candidates.

        Returns:
            An iterator of candidates.
        """
        pass

    @staticmethod
    @display_name("getCandidates")
    def get_candidates() -> list[tuple[ECPoint, int]]:
        """
        Get all registered candidates and their vote counts.

        Returns:
            A list of (public key, votes).
        """
        pass

    @staticmethod
    @display_name("getCandidateVote")
    def get_candidate_vote(pubkey: ECPoint) -> int:
        """
        Get the vote count for a specific candidate.

        Args:
            pubkey: The candidate's public key.

        Returns:
            int: The number of votes, or -1 if not found.
        """
        pass

    @staticmethod
    @display_name("getCommittee")
    def get_committee() -> list[ECPoint]:
        """
        Get the list of committee members.

        Returns:
            The committee members' public keys.
        """
        pass

    @staticmethod
    @display_name("getCommitteeAddress")
    def get_committee_address() -> UInt160:
        """
        Get the committee address.

        Returns:
            The committee address.
        """
        pass

    @staticmethod
    @display_name("getRegisterPrice")
    def get_register_price() -> int:
        """
        Get the fee required to register as a candidate.

        Returns:
            The registration fee.
        """
        pass

    @staticmethod
    @display_name("getNextBlockValidators")
    def get_next_block_validators() -> list[ECPoint]:
        """
        Gets the validators for the next block.

        Returns:
            The validators' public keys.
        """
        pass

    @staticmethod
    @display_name("getAccountState")
    def get_account_state(account: UInt160) -> NeoAccountState:
        """
        Get the latest state of an account.

        Args:
            account: The account to query.

        Returns:
            The account state.
        """
        pass
