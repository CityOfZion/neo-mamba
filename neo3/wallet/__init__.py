import base58
import hashlib
import unicodedata

from .utils import address_to_script_hash, to_address
from .scrypt_parameters import ScryptParameters
from .account import Account
from .nep6contract import NEP6Contract

from neo3.core import to_script_hash
from .. import settings, contracts




def wif_to_nep2(wif: str, passphrase: str):
    return None


