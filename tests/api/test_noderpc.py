import unittest
import base64
from typing import Optional, Any
import neo3crypto
from aioresponses import aioresponses
from neo3 import api
from neo3.network.payloads import transaction, block, verification
from neo3.core import types, cryptography
from neo3.wallet import utils

JSON = Any


class TestNeoRpcClient(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.client = api.NeoRpcClient("localhost")
        self.helper = aioresponses()
        self.helper.start()

    async def asyncTearDown(self) -> None:
        self.helper.stop()
        await self.client.close()

    def mock_response(
        self, payload: Optional[JSON] = None, exc: Optional[Exception] = None
    ):
        """
        Either payload or exc should be provided
        """
        if payload is not None and exc is not None:
            raise ValueError("Arguments are mutual exclusive")

        if payload is not None:
            json = {"jsonrpc": "2.0", "id": 1, "result": payload}
            self.helper.post("localhost", payload=json)
        else:
            self.helper.post("localhost", exception=exc)

    async def test_calculate_network_fee(self):
        self.mock_response({"networkfee": "123"})
        response = await self.client.calculate_network_fee(
            transaction.Transaction._serializable_init()
        )
        self.assertEqual(123, response)

    async def test_get_application_log_transaction(self):
        captured = {
            "txid": "0x7da6ae7ff9d0b7af3d32f3a2feb2aa96c2a27ef8b651f9a132cfaad6ef20724c",
            "executions": [
                {
                    "trigger": "Application",
                    "vmstate": "HALT",
                    "exception": None,
                    "gasconsumed": "9999540",
                    "stack": [],
                    "notifications": [
                        {
                            "contract": "0x70e2301955bf1e74cbb31d18c2f96972abadb328",
                            "eventname": "Transfer",
                            "state": {
                                "type": "Array",
                                "value": [
                                    {
                                        "type": "ByteString",
                                        "value": "4rZTInKT6ZxPKQbVNVOrtKZy34Y=",
                                    },
                                    {
                                        "type": "ByteString",
                                        "value": "+on7LBTfD1nd3wT25WUX8rNKrus=",
                                    },
                                    {"type": "Integer", "value": "10000000000"},
                                ],
                            },
                        }
                    ],
                }
            ],
        }
        self.mock_response(captured)
        tx_hash = types.UInt256.from_string(
            "0x7da6ae7ff9d0b7af3d32f3a2feb2aa96c2a27ef8b651f9a132cfaad6ef20724c"[2:]
        )
        response = await self.client.get_application_log_transaction(tx_hash)
        self.assertEqual(0, len(response.execution.stack))
        self.assertEqual("HALT", response.execution.state)
        self.assertEqual(1, len(response.execution.notifications))
        self.assertEqual("Transfer", response.execution.notifications[0].event_name)

    async def test_get_application_log_block(self):
        captured = {
            "blockhash": "0x577ee5cf7c589f608937287f11da965c0462a8fae77f29959c834cbce38cacac",
            "executions": [
                {
                    "trigger": "OnPersist",
                    "vmstate": "HALT",
                    "gasconsumed": "0",
                    "stack": [],
                    "notifications": [],
                },
                {
                    "trigger": "PostPersist",
                    "vmstate": "HALT",
                    "gasconsumed": "0",
                    "stack": [],
                    "notifications": [
                        {
                            "contract": "0xd2a4cff31913016155e38e474a2c06d08be276cf",
                            "eventname": "Transfer",
                            "state": {
                                "type": "Array",
                                "value": [
                                    {"type": "Any"},
                                    {
                                        "type": "ByteString",
                                        "value": "gSvnpwgsmEL8Ks76QRi4vFpbkYs=",
                                    },
                                    {"type": "Integer", "value": "50000000"},
                                ],
                            },
                        }
                    ],
                },
            ],
        }
        self.mock_response(captured)
        block_hash = types.UInt256.from_string(
            "0x577ee5cf7c589f608937287f11da965c0462a8fae77f29959c834cbce38cacac"[2:]
        )
        response = await self.client.get_application_log_block(block_hash)
        self.assertEqual(2, len(response.executions))
        self.assertEqual(0, len(response.executions[0].stack))
        self.assertEqual("HALT", response.executions[0].state)

        self.assertEqual(0, len(response.executions[1].stack))
        self.assertEqual("HALT", response.executions[1].state)
        self.assertEqual(1, len(response.executions[1].notifications))
        self.assertEqual("Transfer", response.executions[1].notifications[0].event_name)

    async def test_get_best_block_hash(self):
        hash_ = "0xbee7a65279d6b31cc45445a7579d4c4a4e52d1edc13cc7ec7a41f7b1affdf0ab"
        self.mock_response(hash_)
        response = await self.client.get_best_block_hash()
        self.assertEqual(types.UInt256.from_string(hash_[2:]), response)

    async def test_get_block(self):
        block_ = block.Block._serializable_init()
        self.mock_response(base64.b64encode(block_.to_array()).decode())
        response_block = await self.client.get_block(1)
        self.assertEqual(block_, response_block)

    async def test_get_block_count(self):
        count = 1
        self.mock_response(count)
        response = await self.client.get_block_count()
        self.assertEqual(count, response)

    async def test_get_block_hash(self):
        hash_ = "0xbee7a65279d6b31cc45445a7579d4c4a4e52d1edc13cc7ec7a41f7b1affdf0ab"
        self.mock_response(hash_)
        response = await self.client.get_block_hash(1)
        self.assertEqual(types.UInt256.from_string(hash_[2:]), response)

    async def test_get_block_header(self):
        block_ = block.Block._serializable_init()
        self.mock_response(base64.b64encode(block_.to_array()).decode())
        response_header = await self.client.get_block_header(1)
        self.assertEqual(block_.header, response_header)

    async def test_get_committee(self):
        points = [
            "02237309a0633ff930d51856db01d17c829a5b2e5cc2638e9c03b4cfa8e9c9f971",
            "022f1beae94cf0d266d7d26691b431958c8d13768103ab20aed817b57568da293f",
            "0239a37436652f41b3b802ca44cbcb7d65d3aa0b88c9a0380243bdbe1aaa5cb35b",
        ]
        self.mock_response(points)
        expected = tuple(
            map(
                lambda p: cryptography.ECPoint.deserialize_from_bytes(bytes.fromhex(p)),
                points,
            )
        )
        committee = await self.client.get_committee()
        self.assertEqual(expected, committee)

    async def test_get_connection_count(self):
        count = 1
        self.mock_response(count)
        response = await self.client.get_connection_count()
        self.assertEqual(count, response)

    async def test_get_contract_state(self):
        contract_hash_str = "0xb776afb6ad0c11565e70f8ee1dd898da43e51be1"
        contract_hash = types.UInt160.from_string(contract_hash_str[2:])
        captured = {
            "id": 1,
            "updatecounter": 0,
            "hash": contract_hash_str,
            "nef": {
                "magic": 860243278,
                "compiler": "Neo.Compiler.CSharp 3.0.0",
                "source": "",
                "tokens": [
                    {
                        "hash": "0xfffdc93764dbaddd97c48f252a53ea4643faa3fd",
                        "method": "update",
                        "paramcount": 3,
                        "hasreturnvalue": False,
                        "callflags": "All",
                    },
                    {
                        "hash": "0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5",
                        "method": "getCandidates",
                        "paramcount": 0,
                        "hasreturnvalue": True,
                        "callflags": "All",
                    },
                    {
                        "hash": "0x726cb6e0cd8628a1350a611384688911ab75f51b",
                        "method": "ripemd160",
                        "paramcount": 1,
                        "hasreturnvalue": True,
                        "callflags": "All",
                    },
                    {
                        "hash": "0x726cb6e0cd8628a1350a611384688911ab75f51b",
                        "method": "sha256",
                        "paramcount": 1,
                        "hasreturnvalue": True,
                        "callflags": "All",
                    },
                    {
                        "hash": "0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0",
                        "method": "serialize",
                        "paramcount": 1,
                        "hasreturnvalue": True,
                        "callflags": "All",
                    },
                    {
                        "hash": "0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0",
                        "method": "deserialize",
                        "paramcount": 1,
                        "hasreturnvalue": True,
                        "callflags": "All",
                    },
                ],
                "script": "NA5B+CfsjEBB+CfsjEBXAQAMCnN1cGVyQWRtaW40IHBoStgkA8oAFJcmEGhK2CQJSsoAFCgDOiIDWCICQFcAAXhBm/ZnzkGSXegxIgJAQZJd6DFAQZv2Z85AykBXAAEMCUZvcmJpZGRlbjSkQfgn7Iw0F3gMCnN1cGVyQWRtaW40EhHbICICQFcAAniqJgR5OkBXAAJ5eEGb9mfOQeY/GIRAQeY/GIRAVwADNVX///+qJhYMEU5vIGF1dGhvcml6YXRpb24uOnp5eDcAAEA3AABAVwABWXjbMItAi0DbMEBXCAoMCUZvcmJpZGRlbnhB+CfsjDSUNwEAcBDbIHFoSnLKcxB0Ih9qbM7BRXV2bTRhdwd4bweXJgoR2yBKcUUiCWycdGxrMOEMF1NlbmRlciBpcyBub3QgQ2FuZGlkYXRlaTVG////fwl/CH8Hfn18e3p5eBrASjRLcmo3BAB4NXP///80QhHbICICQDcBAEBXAgFaeNswi1uLcGjbKDcDADcCAHFpStgkCUrKABQoAzoiAkDbMEA3AgBANwMAQNsoQFcAAUBXAAJ5eEGb9mfOQeY/GIRAQeY/GIRANwQAQFcBAXg1Dv///zQXcGhK2CQDyhC3JghoNwUAIgULIgJAVwABeEGb9mfOQZJd6DEiAkBBkl3oMUA3BQBAVwMAWTQocBDEAHFoQZwI7ZwmF2hB81S/HXJqEc4LmCYHaWoRzs8i5WkiAkBXAAEaeEGb9mfOQd8wuJoiAkBB3zC4mkBBnAjtnEBB81S/HUDPQFcCAQwJRm9yYmlkZGVueEH4J+yMJgcR2yAiBzWY/f//NRv+//94NV/+//9weDVY/v//NWH///9xaUrYJAPKELcmCmg0DRHbICIHENsgIgJAVwABeNsoQZv2Z85BL1jF7UBBL1jF7UDPQFYEDBTARUMMYSJWDL3Fhow6TOAvAt28wWAMAgwh2zBiDAVBVuezJ9swYwwBd9swYUA=",
                "checksum": 3038242458,
            },
            "manifest": {
                "name": "CommitteeInfoContract",
                "groups": [],
                "features": {},
                "supportedstandards": [],
                "abi": {
                    "methods": [
                        {
                            "name": "verify",
                            "parameters": [],
                            "returntype": "Boolean",
                            "offset": 0,
                            "safe": False,
                        },
                        {
                            "name": "getAdmin",
                            "parameters": [],
                            "returntype": "Hash160",
                            "offset": 14,
                            "safe": False,
                        },
                        {
                            "name": "setAdmin",
                            "parameters": [{"name": "admin", "type": "Hash160"}],
                            "returntype": "Boolean",
                            "offset": 92,
                            "safe": False,
                        },
                        {
                            "name": "update",
                            "parameters": [
                                {"name": "nefFile", "type": "ByteArray"},
                                {"name": "manifest", "type": "String"},
                                {"name": "data", "type": "Any"},
                            ],
                            "returntype": "Void",
                            "offset": 168,
                            "safe": False,
                        },
                        {
                            "name": "setInfo",
                            "parameters": [
                                {"name": "sender", "type": "Hash160"},
                                {"name": "name", "type": "String"},
                                {"name": "location", "type": "String"},
                                {"name": "website", "type": "String"},
                                {"name": "email", "type": "String"},
                                {"name": "github", "type": "String"},
                                {"name": "telegram", "type": "String"},
                                {"name": "twitter", "type": "String"},
                                {"name": "description", "type": "String"},
                                {"name": "logo", "type": "String"},
                            ],
                            "returntype": "Boolean",
                            "offset": 224,
                            "safe": False,
                        },
                        {
                            "name": "getInfo",
                            "parameters": [{"name": "candidate", "type": "Hash160"}],
                            "returntype": "Any",
                            "offset": 448,
                            "safe": False,
                        },
                        {
                            "name": "getAllInfo",
                            "parameters": [],
                            "returntype": "Array",
                            "offset": 507,
                            "safe": False,
                        },
                        {
                            "name": "deleteInfo",
                            "parameters": [{"name": "candidate", "type": "Hash160"}],
                            "returntype": "Boolean",
                            "offset": 589,
                            "safe": False,
                        },
                        {
                            "name": "_initialize",
                            "parameters": [],
                            "returntype": "Void",
                            "offset": 694,
                            "safe": False,
                        },
                    ],
                    "events": [],
                },
                "permissions": [
                    {
                        "contract": "0x726cb6e0cd8628a1350a611384688911ab75f51b",
                        "methods": ["ripemd160", "sha256"],
                    },
                    {
                        "contract": "0xacce6fd80d44e1796aa0c2c625e9e4e0ce39efc0",
                        "methods": ["deserialize", "serialize"],
                    },
                    {
                        "contract": "0xef4073a0f2b305a38ec4050e4d3d28bc40ea63f5",
                        "methods": ["getCandidates"],
                    },
                    {
                        "contract": "0xfffdc93764dbaddd97c48f252a53ea4643faa3fd",
                        "methods": ["update"],
                    },
                ],
                "trusts": [],
                "extra": {
                    "Author": "NEO",
                    "Email": "developer@neo.org",
                    "Description": "This is a Neo3 Contract",
                },
            },
        }
        self.mock_response(captured)

        response_state = await self.client.get_contract_state(contract_hash)
        self.assertEqual(contract_hash, response_state.hash)
        self.assertEqual("CommitteeInfoContract", response_state.manifest.name)

    async def test_get_nep17_balances(self):
        captured = {
            "balance": [
                {
                    "assethash": "0x70e2301955bf1e74cbb31d18c2f96972abadb328",
                    "amount": "3000000100000000",
                    "lastupdatedblock": 2,
                },
                {
                    "assethash": "0xf61eebf573ea36593fd43aa150c055ad7906ab83",
                    "amount": "99999900",
                    "lastupdatedblock": 2,
                },
            ],
            "address": "NgaiKFjurmNmiRzDRQGs44yzByXuSkdGPF",
        }
        self.mock_response(captured)

        response = await self.client.get_nep17_balances("bogus_addr")
        self.assertEqual(2, len(response.balances))
        self.assertEqual(99999900, response.balances[1].amount)

    async def test_get_nep17_transfers(self):
        captured = {
            "sent": [],
            "received": [
                {
                    "timestamp": 1612690497725,
                    "assethash": "0xf61eebf573ea36593fd43aa150c055ad7906ab83",
                    "transferaddress": "NgaiKFjurmNmiRzDRQGs44yzByXuSkdGPF",
                    "amount": "100",
                    "blockindex": 2,
                    "transfernotifyindex": 1,
                    "txhash": "0x5f957960a782514d6587c445288ee1cca7d6b0f952edc204f14d9be83b8152ff",
                },
                {
                    "timestamp": 1612690513541,
                    "assethash": "0x70e2301955bf1e74cbb31d18c2f96972abadb328",
                    "transferaddress": "NgaiKFjurmNmiRzDRQGs44yzByXuSkdGPF",
                    "amount": "10000000000",
                    "blockindex": 3,
                    "transfernotifyindex": 0,
                    "txhash": "0xe42108b343626035cb51fbcb54949bb38aac50c8ba278841d304e9fdce0807ac",
                },
            ],
            "address": "NikhQp1aAD1YFCiwknhM5LQQebj4464bCJ",
        }

        self.mock_response(captured)

        response = await self.client.get_nep17_transfers("bogus_addr")
        self.assertEqual(2, len(response.received))
        self.assertEqual(100, response.received[0].amount)

    async def test_get_raw_mempool(self):
        tx1_hash = "0x0c65fbfd2598aee5f30cd18f1264b458f1db137c4a460f4a174facb3f2d59d06"
        tx2_hash = "0xc8040c285aa495f5b5e5b3761fd9333899f4ed902951c46d86c3bbb1cb12f2c0"

        resp = {"height": 5882071, "verified": [tx1_hash, tx2_hash], "unverified": []}
        self.mock_response(resp)

        expected_verified = [
            types.UInt256.from_string(tx1_hash[2:]),
            types.UInt256.from_string(tx2_hash[2:]),
        ]
        response = await self.client.get_raw_mempool()
        self.assertEqual(expected_verified, response.verified)

    async def test_get_next_block_validators(self):
        votes = 660174
        pub_key_raw = (
            "02237309a0633ff930d51856db01d17c829a5b2e5cc2638e9c03b4cfa8e9c9f971"
        )
        public_key = cryptography.ECPoint.deserialize_from_bytes(
            bytes.fromhex(pub_key_raw)
        )

        resp = [{"publickey": pub_key_raw, "votes": str(votes), "active": False}]
        self.mock_response(resp)

        response = await self.client.get_next_blockvalidators()
        self.assertEqual(1, len(response.validators))
        self.assertEqual(votes, response.validators[0].votes)
        self.assertEqual(public_key, response.validators[0].public_key)

    async def test_get_peers(self):
        peer1 = {"address": "47.90.28.99", "port": 21333}
        peer2 = {"address": "47.91.28.99", "port": 22333}

        resp = {"unconnected": [], "bad": [], "connected": [peer1, peer2]}
        self.mock_response(resp)

        response = await self.client.get_peers()
        self.assertEqual(2, len(response.connected))
        self.assertEqual(peer1["address"], response.connected[0].address)
        self.assertEqual(peer1["port"], response.connected[0].port)
        self.assertEqual(peer2["address"], response.connected[1].address)
        self.assertEqual(peer2["port"], response.connected[1].port)

    async def test_get_storage(self):
        storage_value = b"\x01\x02\x03"

        self.mock_response(base64.b64encode(storage_value).decode())

        dummy_contract_hash = types.UInt160.from_string(
            "0x99042d380f2b754175717bb932a911bc0bb0ad7d"[2:]
        )
        response = await self.client.get_storage(dummy_contract_hash, key=b"\x11")
        self.assertEqual(storage_value, response)

    async def test_get_transaction(self):
        tx = transaction.Transaction._serializable_init()
        # set some properties to ensure the TX will pass the deserialization checks
        tx.signers.append(verification.Signer._serializable_init())
        tx.script = b"\x01"
        tx.witnesses = [verification.Witness._serializable_init()]

        self.mock_response(base64.b64encode(tx.to_array()).decode())

        response_tx = await self.client.get_transaction(tx.hash())
        self.assertEqual(tx, response_tx)

    async def test_get_tx_height(self):
        height = 1
        tx_hash = "0c65fbfd2598aee5f30cd18f1264b458f1db137c4a460f4a174facb3f2d59d06"
        self.mock_response(height)
        response = await self.client.get_transaction_height(tx_hash)
        self.assertEqual(height, response)

    async def test_get_unclaimed_gas_(self):
        addr = "NgaiKFjurmNmiRzDRQGs44yzByXuSkdGPF"
        value = 100
        self.mock_response({"unclaimed": str(value)})
        response_value = await self.client.get_unclaimed_gas(addr)
        self.assertEqual(value, response_value)

    async def test_get_version(self):
        user_agent = "/Neo:3.0.3/"
        captured = {
            "tcpport": 10333,
            "wsport": 10334,
            "nonce": 1930156121,
            "useragent": user_agent,
            "protocol": {
                "addressversion": 53,
                "network": 860833102,
                "validatorscount": 7,
                "msperblock": 15000,
                "maxtraceableblocks": 2102400,
                "maxvaliduntilblockincrement": 5760,
                "maxtransactionsperblock": 512,
                "memorypoolmaxtransactions": 50000,
                "initialgasdistribution": 5200000000000000,
            },
        }
        self.mock_response(captured)
        response = await self.client.get_version()
        self.assertEqual(captured["tcpport"], response.tcp_port)
        self.assertEqual(user_agent, response.user_agent)
        self.assertEqual(captured["protocol"]["network"], response.protocol.network)

    async def test_invoke_contract_verify(self):
        captured = {
            "script": "VgEMFFbIjRQK0swPKQN90Qp/AGCitShcYEBXAANAQZv2Z84MBWhlbGxvDAV3b3JsZFNB5j8YhEBXAQAMFFbIjRQK0swPKQN90Qp/AGCitShcQfgn7IxwaEA=",
            "state": "HALT",
            "gasconsumed": "1017810",
            "exception": None,
            "stack": [{"type": "Boolean", "value": True}],
        }

        self.mock_response(captured)

        contract_hash = "92f5c79b88560584a900cfec15b0e00dc4d58b59"
        response = await self.client.invoke_contract_verify(contract_hash)
        self.assertEqual(1, len(response.stack))
        self.assertTrue(response.stack[0].value)

    async def test_invoke_function(self):
        captured = {
            "script": "VgEMFFbIjRQK0swPKQN90Qp/AGCitShcYEBXAANAQZv2Z84MBWhlbGxvDAV3b3JsZFNB5j8YhEBXAQAMFFbIjRQK0swPKQN90Qp/AGCitShcQfgn7IxwaEA=",
            "state": "HALT",
            "gasconsumed": "1017810",
            "exception": None,
            "stack": [
                {"type": "Boolean", "value": True},
                {
                    "type": "Map",
                    "value": [
                        {
                            "key": {"type": "ByteString", "value": "bmFtZQ=="},
                            "value": {
                                "type": "ByteString",
                                "value": "TyAjOTU3IEludGVyb3BlcmFiaWxpdHk=",
                            },
                        },
                        {
                            "key": {"type": "ByteString", "value": "b3duZXI="},
                            "value": {
                                "type": "ByteString",
                                "value": "/d5rikUuvYmC6NRzIP3I3ETAoOw=",
                            },
                        },
                        {
                            "key": {"type": "ByteString", "value": "bnVtYmVy"},
                            "value": {"type": "Integer", "value": "957"},
                        },
                        {
                            "key": {"type": "ByteString", "value": "aW1hZ2U="},
                            "value": {
                                "type": "ByteString",
                                "value": "aHR0cHM6Ly9uZW8ub3JnL0ludGVyb3BlcmFiaWxpdHkucG5n",
                            },
                        },
                        {
                            "key": {"type": "ByteString", "value": "dmlkZW8="},
                            "value": {"type": "Any"},
                        },
                    ],
                },
            ],
        }

        self.mock_response(captured)

        contract_hash = "92f5c79b88560584a900cfec15b0e00dc4d58b59"
        response = await self.client.invoke_function(contract_hash, "dummy_func")
        self.assertEqual(2, len(response.stack))
        self.assertTrue(response.stack[0].value)
        self.assertEqual(api.StackItemType.MAP, response.stack[1].type)
        self.assertEqual(5, len(response.stack[1].value))

    async def test_invoke_script(self):
        captured = {
            "script": "VgEMFFbIjRQK0swPKQN90Qp/AGCitShcYEBXAANAQZv2Z84MBWhlbGxvDAV3b3JsZFNB5j8YhEBXAQAMFFbIjRQK0swPKQN90Qp/AGCitShcQfgn7IxwaEA=",
            "state": "HALT",
            "gasconsumed": "1017810",
            "exception": None,
            "stack": [{"type": "Boolean", "value": True}],
        }

        self.mock_response(captured)

        bogus_script = b"\x01"
        response = await self.client.invoke_script(bogus_script)
        self.assertEqual(1, len(response.stack))
        self.assertTrue(response.stack[0].value)

    async def test_send_tx(self):
        tx = transaction.Transaction._serializable_init()
        hash_ = "0x13ccdb9f7eda95a24aa5a4841b24fed957fe7f1b944996cbc2e92a4fa4f1fa73"
        hash_type = types.UInt256.from_string(hash_[2:])
        bogus_response = {"hash": hash_}
        self.mock_response(bogus_response)
        response_tx_id = await self.client.send_transaction(tx)
        self.assertEqual(hash_type, response_tx_id)

    async def test_send_block(self):
        block_ = block.Block._serializable_init()
        hash_ = "0x13ccdb9f7eda95a24aa5a4841b24fed957fe7f1b944996cbc2e92a4fa4f1fa73"
        hash_type = types.UInt256.from_string(hash_[2:])
        bogus_response = {"hash": hash_}
        self.mock_response(bogus_response)
        response_block_id = await self.client.send_block(block_)
        self.assertEqual(hash_type, response_block_id)

    async def test_validate_address(self):
        addr = "NPvKVTGZapmFWABLsyvfreuqn73jCjJtN1"
        resp = {"address": addr, "isvalid": True}
        self.mock_response(resp)
        response = await self.client.validate_address(addr)
        self.assertTrue(response)

    async def test_exception(self):
        with self.assertRaises(api.JsonRpcError) as context:
            error_response = {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": -2146233086,
                    "message": "bogus_message",
                    "data": "bogus_data",
                },
            }
            self.helper.post("localhost", payload=error_response)
            await self.client.validate_address("abc")
        self.assertIn("-2146233086", str(context.exception))
        self.assertIn("bogus_message", str(context.exception))
        self.assertIn("bogus_data", str(context.exception))


class TestStackItem(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.si_int = api.StackItem(api.StackItemType.INTEGER, 1)
        cls.si_bool = api.StackItem(api.StackItemType.BOOL, False)

    def test_as_bool(self):
        si = api.StackItem(api.StackItemType.BOOL, True)
        value = si.as_bool()

        self.assertIsInstance(value, bool)
        self.assertTrue(value)

        with self.assertRaises(ValueError) as context:
            self.si_int.as_bool()
        self.assertEqual(
            "item is not of type 'StackItemType.BOOL' but of type 'StackItemType.INTEGER'",
            str(context.exception),
        )

    def test_as_int(self):
        si = api.StackItem(api.StackItemType.INTEGER, 123)
        value = si.as_int()

        self.assertIsInstance(value, int)
        self.assertTrue(value)

        with self.assertRaises(ValueError) as context:
            self.si_bool.as_int()
        self.assertEqual(
            "item is not of type 'StackItemType.INTEGER' but of type 'StackItemType.BOOL'",
            str(context.exception),
        )

    def test_as_str(self):
        si = api.StackItem(api.StackItemType.BYTE_STRING, b"NEO")
        value = si.as_str()

        self.assertIsInstance(value, str)
        self.assertEqual("NEO", value)

        with self.assertRaises(ValueError) as context:
            self.si_int.as_str()
        self.assertEqual(
            "item is not of type 'StackItemType.BYTE_STRING' but of type 'StackItemType.INTEGER'",
            str(context.exception),
        )

    def test_as_uint160(self):
        si = api.StackItem(api.StackItemType.BYTE_STRING, b"\x01" * 20)
        value = si.as_uint160()

        self.assertIsInstance(value, types.UInt160)

        with self.assertRaises(ValueError) as context:
            self.si_int.as_uint160()
        self.assertEqual(
            "item is not of type 'StackItemType.BYTE_STRING' or 'StackItemType.BUFFER' but of type 'StackItemType.INTEGER'",
            str(context.exception),
        )

    def test_as_uint256(self):
        si = api.StackItem(api.StackItemType.BYTE_STRING, b"\x01" * 32)
        value = si.as_uint256()

        self.assertIsInstance(value, types.UInt256)

        with self.assertRaises(ValueError) as context:
            self.si_int.as_uint256()
        self.assertEqual(
            "item is not of type 'StackItemType.BYTE_STRING' or 'StackItemType.BUFFER' but of type 'StackItemType.INTEGER'",
            str(context.exception),
        )

    def test_as_address(self):
        addr = "NSEB78A7DYhPG7cFT7x4YFhSKumBBm7RYk"
        script_hash = utils.address_to_script_hash(addr)

        si = api.StackItem(api.StackItemType.BYTE_STRING, script_hash.to_array())
        value = si.as_uint160()

        self.assertIsInstance(value, types.UInt160)
        self.assertEqual(script_hash, value)

        with self.assertRaises(ValueError) as context:
            self.si_int.as_address()
        self.assertEqual(
            "item is not of type 'StackItemType.BYTE_STRING' or 'StackItemType.BUFFER' but of type 'StackItemType.INTEGER'",
            str(context.exception),
        )

    def test_as_public_key(self):
        si = api.StackItem(
            api.StackItemType.BYTE_STRING,
            bytes.fromhex(
                "03b209fd4f53a7170ea4444e0cb0a6bb6a53c2bd016926989cf85f9b0fba17a70c"
            ),
        )
        value = si.as_public_key()

        self.assertIsInstance(value, cryptography.ECPoint)

        with self.assertRaises(ValueError) as context:
            self.si_int.as_public_key()
        self.assertEqual(
            "item is not of type 'StackItemType.BYTE_STRING' or 'StackItemType.BUFFER' but of type 'StackItemType.INTEGER'",
            str(context.exception),
        )

        # invalid public key
        si = api.StackItem(api.StackItemType.BYTE_STRING, b"\x01" * 64)
        with self.assertRaises(neo3crypto.ECCException) as context:
            value = si.as_public_key()
        self.assertEqual("Failed public key validation", str(context.exception))
