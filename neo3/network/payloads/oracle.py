from __future__ import annotations
import base64
from typing import TYPE_CHECKING
from enum import IntEnum
from neo3.network import payloads
from neo3.core import Size as s, utils, serialization, IJson
from neo3 import vm, contracts

if TYPE_CHECKING:
    from neo3 import storage


class OracleReponseCode(IntEnum):
    SUCCESS = 0x00
    PROTOCOL_NOT_SUPPORTED = 0x10
    CONSENSUS_UNREACHABLE = 0x12
    NOT_FOUND = 0x14
    TIMEOUT = 0x16
    FORBIDDEN = 0x18
    RESPONSE_TOO_LARGE = 0x1a
    INSUFFICIENT_FUNDS = 0x1c
    ERROR = 0xFF


class OracleResponse(payloads.TransactionAttribute, IJson):
    _MAX_RESULT_SIZE = 0xFFFF
    _FIXED_ORACLE_SCRIPT = None

    def __init__(self, id: int, code: OracleReponseCode, result: bytes):
        super(OracleResponse, self).__init__()
        self.type_ = payloads.TransactionAttributeType.ORACLE_RESPONSE
        #: Only one OracleResponse attribute can be attached per transaction
        self.allow_multiple = False
        #: The OracleRequest id to which this is a response
        self.id = id
        #: The evaluation result code
        self.code = code
        #: The actual result
        self.result = result
        if self._FIXED_ORACLE_SCRIPT is None:
            sb = vm.ScriptBuilder()
            sb.emit_dynamic_call(contracts.OracleContract().hash, "finish")  # type: ignore
            self._FIXED_ORACLE_SCRIPT = sb.to_array()

    def __len__(self):
        return super(OracleResponse, self).__len__() + s.uint64 + s.uint8 + utils.get_var_size(self.result)

    def _deserialize_without_type(self, reader: serialization.BinaryReader) -> None:
        self.id = reader.read_uint64()
        self.code = OracleReponseCode(reader.read_uint8())
        self.result = reader.read_var_bytes(self._MAX_RESULT_SIZE)
        if self.code != OracleReponseCode.SUCCESS and len(self.result) > 0:
            raise ValueError(f"Deserialization error - oracle response: {self.code}")

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        writer.write_uint64(self.id)
        writer.write_uint8(self.code)
        writer.write_var_bytes(self.result)

    def to_json(self) -> dict:
        """ Convert object into json """
        json = super(OracleResponse, self).to_json()
        json.update({"id": id,
                     "code": self.code,
                     "result": base64.b64encode(self.result)}
                    )
        return json

    @classmethod
    def from_json(cls, json: dict):
        """ Create object from JSON """
        return cls(json['id'], json['code'], base64.b64decode(json['result']))

    def verify(self, snapshot: storage.Snapshot, tx: payloads.Transaction) -> bool:
        """
        Verifies the attribute with the transaction

        Returns:
            True if verification passes. False otherwise.
        """
        if any(map(lambda signer: signer.scope != payloads.WitnessScope.NONE, tx.signers)):
            return False

        if tx.script != self._FIXED_ORACLE_SCRIPT:
            return False

        oracle = contracts.native.OracleContract()
        request = oracle.get_request(snapshot, self.id)
        if request is None:
            return False
        if tx.network_fee + tx.system_fee != request.gas_for_response:
            return False
        oracle_account = contracts.Contract.get_consensus_address(
            contracts.DesignationContract().get_designated_by_role(snapshot,
                                                                   contracts.DesignateRole.ORACLE,
                                                                   snapshot.best_block_height + 1)
        )
        return any(map(lambda signer: signer.account == oracle_account, tx.signers))

    @classmethod
    def _serializable_init(cls):
        return cls(0, OracleReponseCode.ERROR, b'')
