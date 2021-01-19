from .nativecontract import (CallFlags, NativeContract, PolicyContract, NeoToken, GasToken)
from .oracle import OracleContract
from .designate import DesignateRole, DesignateContract

__all__ = ['NativeContract',
           'CallFlags',
           'PolicyContract',
           'NeoToken',
           'GasToken',
           'OracleContract'
           ]
