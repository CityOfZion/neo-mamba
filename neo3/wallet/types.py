from typing import TypeAlias

# Note that a NeoAddress is just a base58check encoded (address version + script hash).
# * The address version is a fixed value since the inception of the chain.
# * The script hash is the public key of an account (ECPair) wrapped with some extra data and hashed
#   with ripemd160. It is represented in the code with the UInt160 type from the `core` package
NeoAddress: TypeAlias = str
