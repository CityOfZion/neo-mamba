:mod:`ecc` --- ECDSA implementation supporting secp256r1
========================================================

This is pure python implementation of ECDSA with secp256r1 curve support as used by NEO.

This module has been transferred from the 2.x `neo-python <https://github.com/CityOfZion/neo-python/blob/master/neo/Core/Cryptography/ECCurve.py>`_ project with minimal adjustments to make it functional again. Ideally, overtime this should be replaced with a C-based extension with proper documentation on how to use. For now it's just present.

.. autoclass:: neo3.core.cryptography.ecc.ECDSA
   :members:
   :undoc-members:
   :show-inheritance:
   
.. autoclass:: neo3.core.cryptography.ecc.EllipticCurve
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: neo3.core.cryptography.ecc.EllipticCurve.ECPoint
   :members:
   :undoc-members:
   :show-inheritance:
