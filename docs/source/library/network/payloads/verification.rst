:mod:`verification` --- Validation of objects and smart contract invokers
=========================================================================

.. classoverview::
   :class:`~neo3.network.payloads.verification.Signer`
   :class:`~neo3.network.payloads.verification.Witness`
   :class:`~neo3.network.payloads.verification.WitnessScope`

This module describes two validation forms found in the NEO chain. 

First we have validation of three verifiable objects, namely: :class:`~neo3.network.payloads.block.Block`, :class:`~neo3.network.payloads.consensus.ConsensusPayload` and :class:`~neo3.network.payloads.transaction.Transaction`. These are digitally signed using ECDSA. Validation of these objects is done using a so called witness. 

A :class:`~neo3.network.payloads.verification.Witness` is a verification script executed by the virtual machine to validate the verifiable object. Validation failure prevents for example that a transaction is included in a block and broad casted to the network. Taking the transaction example further, the witness carries a set of virtual machine opcodes (in its :attr:`~neo3.network.payloads.verification.Witness.invocation_script`) that load the transaction signatures into the internal data structures of the VM. Next, the :attr:`~neo3.network.payloads.verification.Witness.verification_script`, which are also virtual machine opcodes, performs the actual verification and operates on the data previously setup by the invocation script.

A second form of validation can be performed inside a smart contract using the `CheckWitness() <https://docs.neo.org/tutorial/en-us/9-smartContract/cgas/6_signature_and_verification.html#checkwitness-and-additional-witness>`__ system call. This can be used to limit certain smart contract functions to a specific user, other smart contract or group.

To give this fine grained control NEO created so called `signers` and a set of verification scopes. Signers are attached to a transaction in its aptly named :attr:`~neo3.network.payloads.transaction.Transaction.signers` attribute and are matched according to the rules set by the verification scope. The various verification scopes can be configured using a :class:`~neo3.network.payloads.verification.WitnessScope` and are set in the :attr:`~neo3.network.payloads.verification.Signer.scope` attribute of a signer.

.. Note::
   
   While multiple signer's can be attached to a transaction and thus multiple scopes can be set, only the first signer is looked at to determine the scope to use for :func:`CheckWitness()`.

.. autoclass:: neo3.network.payloads.verification.Witness
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.payloads.verification.WitnessScope
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:

.. autoclass:: neo3.network.payloads.verification.Signer
   :members:
   :undoc-members:
   :show-inheritance:
   :inherited-members:
