v3.0 introduces breaking changes to streamline APIs or based on lessons learned. This document describes those changes and how to migrate

# Account/wallet password handling

## signing functions
- renamed `sign_insecure_with_account` -> `sign_with_account`.
   - also removed `password` argument.
- renamed `sign_insecure_with_multisig_account` -> `sign_with_multisig_account`.
   - also removed `password` argument.
- removed `sign_secure_with_account`.

## Account
- removed `password` argument from `sign`, `sign_tx`, `sign_multisig_tx`, `create_new`, `from_encrypted_key`, `from_private_key`, `from_wif`.
- added `password` argument to `to_json` & `from_json`.

## Wallet
- removed `password` argument from `account_new`.
- added `password` argument to `save`, `to_json`.
- removed context manager.

# NEP17Token `transfer_friendly` additional parameter
In order to fix the `transfer_friendly` function an additional `decimals` parameter is added to the function signature,
indicating the number of decimals the token has.

# test_invoke* return type change
Relevant if you make use of the `ChainFacade` related classes.
- all `test_invoke*` now return an `InvokeReceipt` just like regular `invoke*` calls.
- `invoke_multi` and `invoke_multi_raw` return `InvokeReceipt[Sequence]` instead of `Sequence`.

# test_invoke* `signer` parameter type change
Relevant if you make use of the `ChainFacade` related classes.
The old `signers` parameter changed from `Optional[Sequence[verification.Signer]] = None` to `Optional[Sequence[SigningPair]] = None`.
This streamlines the parameter with the persisting `invoke` variants, allowing for easy switching.

# removal of deprecated functions and parameters
- the `end` argument of `NeoToken.get_unclaimed_gas()` is removed.
- the `balance_of` function of `_NEP11Contract` is renamed to `total_owned_by`.
- the `balance_of_friendly` function of `_NEP11Contract` is renamed to `total_owned_by_friendly`.
- the `candidate_unregister` of `NeoToken` is renamed to `candidate_deregister`.
