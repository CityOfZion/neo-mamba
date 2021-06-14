import unittest
import binascii
import base58
import enum
from copy import deepcopy
from bitarray import bitarray
from neo3.network import payloads, capabilities
from neo3.core import types, serialization
from neo3.core import cryptography as crypto
from neo3 import settings


class AddrTestCase(unittest.TestCase):
    """
    Tests both Network addresses and the AddrPayload
    """
    @classmethod
    def setUpClass(cls) -> None:
        """
        var capability = new FullNodeCapability(123);

        var ip = IPAddress.Parse("127.0.0.1");
        var network_addr = NetworkAddressWithTime.Create(ip, 0, capability);
        Console.WriteLine($"len: {network_addr.Size}");
        Console.WriteLine($"b\'{BitConverter.ToString(network_addr.ToArray()).Replace("-", "")}\'");
        """
        cls.network_addr = payloads.NetworkAddress(address='127.0.0.1:0', timestamp=0,
                                capabilities=[capabilities.FullNodeCapability(start_height=123)])

        cls.addr_payload = payloads.AddrPayload([cls.network_addr])

    def test_network_addr_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 26
        self.assertEqual(expected_len, len(self.network_addr))

    def test_network_addr_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'0000000000000000000000000000FFFF7F00000101107B000000')
        self.assertEqual(expected_data, self.network_addr.to_array())

    def test_network_addr_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_addr = payloads.NetworkAddress.deserialize_from_bytes(self.network_addr.to_array())
        self.assertEqual(self.network_addr.timestamp, deserialized_addr.timestamp)
        self.assertEqual(self.network_addr.address, deserialized_addr.address)
        self.assertEqual(self.network_addr.capabilities[0].start_height, deserialized_addr.capabilities[0].start_height)

    def test_addrpayload_len(self):
        expected_len = 27
        self.assertEqual(expected_len, len(self.addr_payload))

    def test_addrpayload_serialization(self):
        expected_data = binascii.unhexlify(b'010000000000000000000000000000FFFF7F00000101107B000000')
        self.assertEqual(expected_data, self.addr_payload.to_array())

    def test_addrpayload_deserialization(self):
        deserialized_addr_payload = payloads.AddrPayload.deserialize_from_bytes(self.addr_payload.to_array())
        self.assertEqual(len(self.addr_payload.addresses), len(deserialized_addr_payload.addresses))
        self.assertEqual(self.addr_payload.addresses[0].capabilities[0].start_height,
                         deserialized_addr_payload.addresses[0].capabilities[0].start_height)

    def test_addrpayload_deserialization2(self):
        capa = capabilities.ServerCapability(n_type=capabilities.NodeCapabilityType.TCPSERVER, port=123)
        network_addr = payloads.NetworkAddress(address='127.0.0.1:0', timestamp=0, capabilities=[capa])
        addr_payload = payloads.AddrPayload([network_addr])

        deserialized_addr_payload = payloads.AddrPayload.deserialize_from_bytes(addr_payload.to_array())
        self.assertEqual(123, deserialized_addr_payload.addresses[0].capabilities[0].port)

    def test_equality(self):
        addr1 = payloads.NetworkAddress(address="127.0.0.1:0")
        addr2 = payloads.NetworkAddress(address="127.0.0.1:0")
        addr3 = payloads.NetworkAddress(address="127.0.0.2:0")
        self.assertTrue(addr1 == addr2)
        self.assertFalse(addr1 == addr3)
        self.assertFalse(addr1 == object())

    def test_various_dunder(self):
        addr1 = payloads.NetworkAddress(address="127.0.0.1:0")
        self.assertEqual("127.0.0.1:0", str(addr1))
        self.assertNotEqual("127.0.0.1", str(addr1))

        formatted = f"{addr1:>12}"
        self.assertEqual(" 127.0.0.1:0", formatted)

        # an object has to be hashable in order for it to be acceptable as a _dictionary key
        # this tests the __hash__ dunder
        try:
            x = {addr1: 123}
        except Exception as e:
            self.fail(f"Failed to add NetworkAddress to dictionary. Can't hash?: {e}")

        # test __repr__
        self.assertIn("127.0.0.1", repr(addr1))
        self.assertIn("(NEW)", repr(addr1))

    def test_properties(self):
        addr1 = payloads.NetworkAddress(address="127.0.0.1:30333")

        self.assertEqual("127.0.0.1", addr1.ip)
        self.assertEqual(30333, addr1.port)

        self.assertTrue(addr1.is_state_new)
        addr1.set_state_connected()
        self.assertFalse(addr1.is_state_new)

        self.assertTrue(addr1.is_state_connected)
        addr1.set_state_poor()
        self.assertFalse(addr1.is_state_connected)

        self.assertTrue(addr1.is_state_poor)
        addr1.set_state_dead()
        self.assertFalse(addr1.is_state_poor)

        self.assertTrue(addr1.is_state_dead)
        addr1.set_state_new()
        self.assertFalse(addr1.is_state_dead)


class BlockTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
            Transaction tx = new Transaction();
            tx.Nonce = 123;
            tx.SystemFee = 456;
            tx.NetworkFee = 789;
            tx.ValidUntilBlock = 1;
            tx.Attributes = new TransactionAttribute[0];
            tx.Signers = new Signer[] { new Signer() { Account = UInt160.Parse("0xe239c7228fa6b46cc0cf43623b2f934301d0b4f7")}};
            tx.Script = new byte[] { 0x1 };
            tx.Witnesses = new Witness[] {new Witness { InvocationScript = new byte[0], VerificationScript = new byte[] { 0x55 } }};

            Block b = new Block
            {
                Header = new Header
                {
                    Version = 0,
                    PrevHash = UInt256.Parse("0xf782c7fbb2eef6afe629b96c0d53fb525eda64ce5345057caf975ac3c2b9ae0a"),
                    Timestamp = 123,
                    Index = 1,
                    PrimaryIndex = 0,
                    NextConsensus = UInt160.Parse("0xd7678dd97c000be3f33e9362e673101bac4ca654"),
                    Witness = new Witness { InvocationScript = new byte[0], VerificationScript = new byte[] { 0x55 } },
                    MerkleRoot = UInt256.Zero
                },
                Transactions = new Transaction[] { tx }
            };
            b.Header.MerkleRoot = MerkleTree.ComputeRoot(b.Transactions.Select(p => p.Hash).ToArray());
            Console.WriteLine($"{b.Size}");
            Console.WriteLine($"{BitConverter.ToString(b.ToArray()).Replace("-", "")}");

            var trimmedBlock = new TrimmedBlock
            {
                Header = b.Header,
                Hashes = b.Transactions.Select(p => p.Hash).ToArray()
            };
            Console.WriteLine($"{trimmedBlock.Size}");
            Console.WriteLine($"{BitConverter.ToString(trimmedBlock.ToArray()).Replace("-", "")}");

        """
        cls.tx = payloads.Transaction(version=0,
                                      nonce=123,
                                      system_fee=456,
                                      network_fee=789,
                                      valid_until_block=1,
                                      attributes=[],
                                      signers=[payloads.Signer(types.UInt160.from_string("e239c7228fa6b46cc0cf43623b2f934301d0b4f7"))],
                                      script=b'\x01',
                                      witnesses=[payloads.Witness(invocation_script=b'', verification_script=b'\x55')])

        cls.header = payloads.Header(version=0,
                                     prev_hash=types.UInt256.from_string("f782c7fbb2eef6afe629b96c0d53fb525eda64ce5345057caf975ac3c2b9ae0a"),
                                     timestamp=123,
                                     index=1,
                                     primary_index=0,
                                     next_consensus=types.UInt160.from_string("d7678dd97c000be3f33e9362e673101bac4ca654"),
                                     witness=payloads.Witness(invocation_script=b'', verification_script=b'\x55'))
        cls.block = payloads.Block(cls.header,
                                   transactions=[cls.tx])
        cls.block.rebuild_merkle_root()

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 160
        self.assertEqual(expected_len, len(self.block))

    def test_equals(self):
        self.assertFalse(None == self.block)
        self.assertFalse(self.block == object())

        # test different hashes
        modified_block = deepcopy(self.block)
        modified_block.header.timestamp = 1
        self.assertFalse(self.block == modified_block)
        self.assertTrue(self.block == self.block)

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify("000000000AAEB9C2C35A97AF7C054553CE64DA5E52FB530D6CB929E6AFF6EEB2FBC782F75618ADD6F91FAD691D6A4D430DB27CE5CA607296863E73A23FC3622A415CDD407B00000000000000010000000054A64CAC1B1073E662933EF3E30B007CD98D67D70100015501007B000000C80100000000000015030000000000000100000001F7B4D00143932F3B6243CFC06CB4A68F22C739E20000010101000155")
        self.assertEqual(expected_data, self.block.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_block = payloads.Block.deserialize_from_bytes(self.block.to_array())
        self.assertEqual(self.block.version, deserialized_block.version)
        self.assertEqual(self.block.prev_hash, deserialized_block.prev_hash)
        self.assertEqual(self.block.timestamp, deserialized_block.timestamp)
        self.assertEqual(self.block.index, deserialized_block.index)
        self.assertEqual(self.block.primary_index, deserialized_block.primary_index)
        self.assertEqual(self.block.next_consensus, deserialized_block.next_consensus)
        self.assertEqual(self.block.witness.invocation_script, deserialized_block.witness.invocation_script)
        self.assertEqual(self.block.witness.verification_script, deserialized_block.witness.verification_script)
        self.assertEqual(1, len(deserialized_block.transactions))

    def test_deserialization_no_duplicate_transactions(self):
        # A block should not have duplicate transactions
        block_copy = deepcopy(self.block)
        block_copy.transactions.append(block_copy.transactions[0])
        with self.assertRaises(ValueError) as context:
            payloads.Block.deserialize_from_bytes(block_copy.to_array())
        self.assertIn("Deserialization error - block contains duplicate transaction", str(context.exception))

    def test_deserialization_wrong_merkle_root(self):
        block_copy = deepcopy(self.block)
        block_copy.header.merkle_root = types.UInt256.zero()
        with self.assertRaises(ValueError) as context:
            payloads.Block.deserialize_from_bytes(block_copy.to_array())
        self.assertIn("Deserialization error - merkle root mismatch", str(context.exception))

    def test_inventory_type(self):
        self.assertEqual(payloads.InventoryType.BLOCK, self.block.inventory_type)

    def test_trim(self):
        trimmed_block = self.block.trim()
        self.assertIsInstance(trimmed_block, payloads.TrimmedBlock)
        # captured from C#, see setUpClass() for the capture code
        expected_len = 138
        self.assertEqual(expected_len, len(trimmed_block))

        expected_data = binascii.unhexlify('000000000AAEB9C2C35A97AF7C054553CE64DA5E52FB530D6CB929E6AFF6EEB2FBC782F75618ADD6F91FAD691D6A4D430DB27CE5CA607296863E73A23FC3622A415CDD407B00000000000000010000000054A64CAC1B1073E662933EF3E30B007CD98D67D701000155015618ADD6F91FAD691D6A4D430DB27CE5CA607296863E73A23FC3622A415CDD40')
        self.assertEqual(expected_data, trimmed_block.to_array())

        deserialized_trimmed_block = payloads.TrimmedBlock.deserialize_from_bytes(trimmed_block.to_array())
        self.assertEqual(trimmed_block.header, deserialized_trimmed_block.header)
        self.assertEqual(trimmed_block.hashes, deserialized_trimmed_block.hashes)
        self.assertEqual(1, len(deserialized_trimmed_block.hashes))


class SignerTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        Signer co = new Signer();
        co.Account = UInt160.Parse("0xd7678dd97c000be3f33e9362e673101bac4ca654");
        co.Scopes = WitnessScope.CustomContracts | WitnessScope.CustomGroups;
        co.AllowedContracts = new UInt160[] { UInt160.Parse("5b7074e873973a6ed3708862f219a6fbf4d1c411") };

        ECPoint p = ECPoint.Parse("026241e7e26b38bb7154b8ad49458b97fb1c4797443dc921c5ca5774f511a2bbfc", ECCurve.Secp256r1);
        co.AllowedGroups = new ECPoint[] { p };

        Console.WriteLine($"{co.Size}");
        Console.WriteLine($"{BitConverter.ToString(co.ToArray()).Replace("-","")}");
        Console.Write(co.ToJson());
        """
        cls.signer = payloads.Signer(types.UInt160.from_string("d7678dd97c000be3f33e9362e673101bac4ca654"))
        cls.signer.scope = payloads.WitnessScope.CUSTOM_CONTRACTS | payloads.WitnessScope.CUSTOM_GROUPS
        cls.signer.allowed_contracts = [types.UInt160.from_string("5b7074e873973a6ed3708862f219a6fbf4d1c411")]
        point = crypto.ECPoint(binascii.unhexlify("026241e7e26b38bb7154b8ad49458b97fb1c4797443dc921c5ca5774f511a2bbfc"), crypto.ECCCurve.SECP256R1, True)
        cls.signer.allowed_groups = [point]

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 76
        self.assertEqual(expected_len, len(self.signer))

    def test_equals(self):
        self.assertFalse(self.signer == None)
        self.assertFalse(self.signer == object())
        signer2 = payloads.Signer._serializable_init()
        self.assertFalse(self.signer == signer2)
        self.assertTrue(self.signer == self.signer)

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'54A64CAC1B1073E662933EF3E30B007CD98D67D7300111C4D1F4FBA619F2628870D36E3A9773E874705B01026241E7E26B38BB7154B8AD49458B97FB1C4797443DC921C5CA5774F511A2BBFC')
        self.assertEqual(expected_data, self.signer.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_signer = payloads.Signer.deserialize_from_bytes(self.signer.to_array())
        self.assertEqual(self.signer.account, deserialized_signer.account)
        self.assertEqual(self.signer.scope, deserialized_signer.scope)
        self.assertEqual(self.signer.allowed_contracts, deserialized_signer.allowed_contracts)
        self.assertEqual(self.signer.allowed_groups, deserialized_signer.allowed_groups)

    def test_deserialization_invalid_scope(self):
        data = bytearray(self.signer.to_array())
        # the scope is serialized after the UInt160 `account` attribute
        # we modify that byte to an invalid scope type
        data[20] = 0xFF

        with self.assertRaises(ValueError) as context:
            payloads.Signer.deserialize_from_bytes(data)
        self.assertEqual("Deserialization error - invalid scope. GLOBAL scope not allowed with other scope types", str(context.exception))

    def test_to_json(self):
        # captured from C#, see setUpClass() for the capture code
        expected = {"account":"0xd7678dd97c000be3f33e9362e673101bac4ca654","scopes":"CustomContracts, CustomGroups","allowedcontracts":["0x5b7074e873973a6ed3708862f219a6fbf4d1c411"],"allowedgroups":["026241e7e26b38bb7154b8ad49458b97fb1c4797443dc921c5ca5774f511a2bbfc"]}
        self.assertEqual(expected, self.signer.to_json())

    def test_from_json(self):
        captured = {"account": "0xd7678dd97c000be3f33e9362e673101bac4ca654", "scopes": "CustomContracts, CustomGroups",
                    "allowedcontracts": ["0x5b7074e873973a6ed3708862f219a6fbf4d1c411"],
                    "allowedgroups": ["026241e7e26b38bb7154b8ad49458b97fb1c4797443dc921c5ca5774f511a2bbfc"]}
        signer = payloads.Signer.from_json(captured)
        # relies on test_to_json() to pass
        self.assertEqual(captured, signer.to_json())


class FilterAddTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        FilterAddPayload fa = new FilterAddPayload { Data = new byte[] { 0x1, 0x2 } };
        Console.WriteLine($"{fa.Size}");
        Console.WriteLine($"{BitConverter.ToString(fa.ToArray()).Replace("-", "")}");
        """
        cls.filter = payloads.FilterAddPayload(b'\x01\x02')

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 3
        self.assertEqual(expected_len, len(self.filter))

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'020102')
        self.assertEqual(expected_data, self.filter.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_filter = payloads.FilterAddPayload.deserialize_from_bytes(self.filter.to_array())
        self.assertEqual(self.filter.data, deserialized_filter.data)


class FilterLoadTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        BloomFilter bf = new BloomFilter(8, 2, 345, new byte[] { 0x1, 0x2 });
        FilterLoadPayload fl = FilterLoadPayload.Create(bf);
        Console.WriteLine($"{fl.Size}");
        Console.WriteLine($"{BitConverter.ToString(fl.ToArray()).Replace("-", "")}");
        """
        bloom = crypto.BloomFilter(8, 2, 345, b'\x01\x02')
        cls.filter = payloads.FilterLoadPayload(bloom)

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 7
        self.assertEqual(expected_len, len(self.filter))

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'01010259010000')
        self.assertEqual(expected_data, self.filter.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_filter = payloads.FilterLoadPayload.deserialize_from_bytes(self.filter.to_array())
        self.assertEqual(self.filter.filter, deserialized_filter.filter)
        self.assertEqual(self.filter.K, deserialized_filter.K)
        self.assertEqual(self.filter.tweak, deserialized_filter.tweak)

    def test_deserialization_with_invalid_K_value(self):
        invalid_K = 51
        bloom = crypto.BloomFilter(8, invalid_K, 345, b'\x01\x02')
        filter = payloads.FilterLoadPayload(bloom)

        with self.assertRaises(ValueError) as context:
            payloads.FilterLoadPayload.deserialize_from_bytes(filter.to_array())
        self.assertIn("Deserialization error - K exceeds limit of 50", str(context.exception))


class GetBlocksPayloadTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        UInt256 hash_start = UInt256.Parse("0xa400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff01");
        GetBlocksPayload payload = GetBlocksPayload.Create(hash_start, 2);
        Console.WriteLine($"len: {payload.Size}");
        Console.WriteLine($"b\'{BitConverter.ToString(payload.ToArray()).Replace("-", "")}\'");
        """
        cls.hash_start = types.UInt256.from_string("a400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff01")
        cls.payload = payloads.GetBlocksPayload(hash_start=cls.hash_start, count=2)

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 34
        self.assertEqual(expected_len, len(self.payload))

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'01FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A40200')
        self.assertEqual(expected_data, self.payload.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_payload = payloads.GetBlocksPayload.deserialize_from_bytes(self.payload.to_array())
        self.assertEqual(self.payload.hash_start, deserialized_payload.hash_start)
        self.assertEqual(2, deserialized_payload.count)


class GetBlockByIndexPayloadTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        GetBlockByIndexPayload payload = GetBlockByIndexPayload.Create(1, 2);
        Console.WriteLine($"len: {payload.Size}");
        Console.WriteLine($"b\'{BitConverter.ToString(payload.ToArray()).Replace("-", "")}\'");
        """
        cls.payload = payloads.GetBlockByIndexPayload(index_start=1, count=2)

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 6
        self.assertEqual(expected_len, len(self.payload))

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'010000000200')
        self.assertEqual(expected_data, self.payload.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_payload = payloads.GetBlockByIndexPayload.deserialize_from_bytes(self.payload.to_array())
        self.assertEqual(self.payload.index_start, deserialized_payload.index_start)
        self.assertEqual(2, deserialized_payload.count)

    def test_deserialization_error(self):
        # test exceed max count
        payload = payloads.GetBlockByIndexPayload(index_start=1, count=payloads.HeadersPayload.MAX_HEADERS_COUNT + 1)
        with self.assertRaises(ValueError) as context:
            payloads.GetBlockByIndexPayload.deserialize_from_bytes(payload.to_array())
        self.assertIn("Deserialization error - invalid count", str(context.exception))

        # test 0 count
        payload = payloads.GetBlockByIndexPayload(index_start=1, count=0)
        with self.assertRaises(ValueError) as context:
            payloads.GetBlockByIndexPayload.deserialize_from_bytes(payload.to_array())
        self.assertIn("Deserialization error - invalid count", str(context.exception))

        # test negative count
        payload = payloads.GetBlockByIndexPayload(index_start=1, count=-10)
        with self.assertRaises(ValueError) as context:
            payloads.GetBlockByIndexPayload.deserialize_from_bytes(payload.to_array())
        self.assertIn("Deserialization error - invalid count", str(context.exception))


class HeaderTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        Header h = new Header
        {
            Version = 0,
            PrevHash = UInt256.Parse("a400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff01"),
            MerkleRoot = UInt256.Parse("a400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff02"),
            Timestamp = 0,
            Index = 123,
            PrimaryIndex = 0,
            NextConsensus = UInt160.Parse("0xe239c7228fa6b46cc0cf43623b2f934301d0b4f7"),
            Witness = new Witness
            {
                InvocationScript = new byte[] { 0x1, 0x2},
                VerificationScript = new byte[] { 0x3, 0x4}
            }
        };
        Console.WriteLine(h.Hash);
        Console.WriteLine(h.Size);
        Console.WriteLine($"b\'{BitConverter.ToString(h.ToArray()).Replace("-", "")}\'");
        """
        version = 0
        previous_hash = types.UInt256.from_string("a400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff01")
        merkleroot = types.UInt256.from_string("a400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff02")
        timestamp = 0
        index = 123
        primary_index = 0
        next_consensus = types.UInt160.from_string("e239c7228fa6b46cc0cf43623b2f934301d0b4f7")
        witness = payloads.Witness(invocation_script=b'\x01\x02', verification_script=b'\x03\x04')

        cls.header = payloads.Header(version, previous_hash, timestamp, index, primary_index, next_consensus, witness, merkleroot)

    def test_len_and_hash(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 108
        expected_hash = types.UInt256.from_string('47a455f322441b6c3b4dffd039df34ca724fac222686e515043f01c494687868')
        self.assertEqual(expected_len, len(self.header))
        self.assertEqual(expected_hash, self.header.hash())

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'0000000001FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A402FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A400000000000000007B00000000F7B4D00143932F3B6243CFC06CB4A68F22C739E201020102020304')
        self.assertEqual(expected_data, self.header.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_header = payloads.Header.deserialize_from_bytes(self.header.to_array())
        self.assertEqual(self.header.hash(), deserialized_header.hash())
        self.assertEqual(self.header.version, deserialized_header.version)
        self.assertEqual(self.header.prev_hash, deserialized_header.prev_hash)
        self.assertEqual(self.header.merkle_root, deserialized_header.merkle_root)
        self.assertEqual(self.header.timestamp, deserialized_header.timestamp)
        self.assertEqual(self.header.index, deserialized_header.index)
        self.assertEqual(self.header.next_consensus, deserialized_header.next_consensus)
        self.assertEqual(self.header.witness.invocation_script, deserialized_header.witness.invocation_script)
        self.assertEqual(self.header.witness.verification_script, deserialized_header.witness.verification_script)

    def test_deserialization_failure1(self):
        # there should be a 1 byte witness object count (fixed to value 1) before the actual witness object.
        # see https://github.com/neo-project/neo/issues/1128
        raw_data = binascii.unhexlify(b'0000000001FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A402FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A400000000000000007B00000000F7B4D00143932F3B6243CFC06CB4A68F22C739E200020102020304')
        deserialized_header = payloads.Header._serializable_init()

        with self.assertRaises(ValueError) as context:
            with serialization.BinaryReader(raw_data) as br:
                    deserialized_header.deserialize(br)
        self.assertIn("Deserialization error", str(context.exception))
        self.assertIn("Witness object count is 0 must be 1", str(context.exception))

    def test_equals(self):
        self.assertFalse(None == self.header)
        self.assertFalse(self.header == object())

        # test different hashes
        modified_header = deepcopy(self.header)
        modified_header.timestamp = 1
        self.assertFalse(self.header == modified_header)
        self.assertTrue(self.header == self.header)


class HeadersPayloadTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        Header h1 = new Header
        {
            Version = 0,
            PrevHash = UInt256.Parse("a400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff01"),
            MerkleRoot = UInt256.Parse("a400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff02"),
            Timestamp = 0,
            Index = 123,
            PrimaryIndex = 0,
            NextConsensus = UInt160.Parse("8a2b438eaca8b4b2ab6b4524b5a69a45d920c351"),
            Witness = new Witness
            {
                InvocationScript = new byte[] {0x1, 0x2},
                VerificationScript = new byte[] {0x3, 0x4}
            }
        };
        Header h2;
        using (BinaryReader reader = new BinaryReader(new MemoryStream(h1.ToArray())))
        {
            h2 = reader.ReadSerializable<Header>();
        }

        HeadersPayload hp = HeadersPayload.Create(new Header[] { h1, h2 });
        Console.WriteLine(hp.Size);
        Console.WriteLine($"b\'{BitConverter.ToString(hp.ToArray()).Replace("-", "")}\'");
        """
        version = 0
        previous_hash = types.UInt256.from_string("a400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff01")
        merkleroot = types.UInt256.from_string("a400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff02")
        timestamp = 0
        index = 123
        primary_index = 0
        next_consensus = types.UInt160.from_string("8a2b438eaca8b4b2ab6b4524b5a69a45d920c351")
        witness = payloads.Witness(invocation_script=b'\x01\x02', verification_script=b'\x03\x04')

        h1 = payloads.Header(version, previous_hash, timestamp, index, primary_index, next_consensus, witness, merkleroot)
        h2 = payloads.Header(version, previous_hash, timestamp, index, primary_index, next_consensus, witness, merkleroot)
        cls.payload = payloads.HeadersPayload([h1, h2])

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 217
        self.assertEqual(expected_len, len(self.payload))

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'020000000001FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A402FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A400000000000000007B0000000051C320D9459AA6B524456BABB2B4A8AC8E432B8A010201020203040000000001FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A402FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A400000000000000007B0000000051C320D9459AA6B524456BABB2B4A8AC8E432B8A01020102020304')
        self.assertEqual(expected_data, self.payload.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_payload = payloads.HeadersPayload.deserialize_from_bytes(self.payload.to_array())
        self.assertEqual(len(self.payload.headers), len(deserialized_payload.headers))
        self.assertEqual(2, len(self.payload.headers))
        self.assertIsInstance(deserialized_payload.headers[0], payloads.Header)
        self.assertIsInstance(deserialized_payload.headers[1], payloads.Header)


class InventoryPayloadTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        var u1 = UInt256.Parse("a400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff01");
        var u2 = UInt256.Parse("a400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff02");
        var payload = InvPayload.Create(InventoryType.Block, new UInt256[] { u1, u2 });
        Console.WriteLine(payload.Size);
        Console.WriteLine($"b\'{BitConverter.ToString(payload.ToArray()).Replace("-", "")}\'");
        """
        cls.u1 = types.UInt256.from_string("a400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff01")
        cls.u2 = types.UInt256.from_string("a400ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff02")
        cls.inv = payloads.InventoryPayload(payloads.InventoryType.BLOCK, [cls.u1, cls.u2])

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 66
        self.assertEqual(expected_len, len(self.inv))

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'2C0201FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A402FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00A4')
        self.assertEqual(expected_data, self.inv.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_inv_payload = payloads.InventoryPayload.deserialize_from_bytes(self.inv.to_array())
        self.assertEqual(self.inv.type, deserialized_inv_payload.type)
        self.assertEqual(len(self.inv.hashes), len(deserialized_inv_payload.hashes))
        self.assertEqual(self.inv.hashes[0], deserialized_inv_payload.hashes[0])


class MerkleBlockPayloadTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        Transaction tx = new Transaction();
        tx.Nonce = 123;
        tx.SystemFee = 456;
        tx.NetworkFee = 789;
        tx.ValidUntilBlock = 1;
        tx.Attributes = new TransactionAttribute[0];
        tx.Signers = new Signer[] { new Signer() { Account = UInt160.Parse("0xe239c7228fa6b46cc0cf43623b2f934301d0b4f7")}};
        tx.Script = new byte[] { 0x1 };
        tx.Witnesses = new Witness[0];

        Block b = new Block
        {
            Header = new Header
            {
                Version = 0,
                PrevHash = UInt256.Parse("0xf782c7fbb2eef6afe629b96c0d53fb525eda64ce5345057caf975ac3c2b9ae0a"),
                Timestamp = 123,
                Index = 1,
                PrimaryIndex = 0,
                NextConsensus = UInt160.Parse("0xd7678dd97c000be3f33e9362e673101bac4ca654"),
                Witness = new Witness { InvocationScript = new byte[0], VerificationScript = new byte[] { 0x55 } },
                MerkleRoot = UInt256.Zero
            },
            Transactions = new Transaction[] { tx }
        };
        b.Header.MerkleRoot = MerkleTree.ComputeRoot(b.Transactions.Select(p => p.Hash).ToArray());

        byte[] bytes = { 0x1 };
        BitArray flags = new BitArray(bytes);
        MerkleBlockPayload mbp = MerkleBlockPayload.Create(b, flags);
        Console.WriteLine($"b\'{BitConverter.ToString(mbp.ToArray()).Replace("-", "")}\'");
        """

        cls.tx = payloads.Transaction(version=0,
                                      nonce=123,
                                      system_fee=456,
                                      network_fee=789,
                                      valid_until_block=1,
                                      attributes=[],
                                      signers=[payloads.Signer(types.UInt160.from_string("e239c7228fa6b46cc0cf43623b2f934301d0b4f7"))],
                                      script=b'\x01',
                                      witnesses=[payloads.Witness(invocation_script=b'', verification_script=b'\x55')])

        cls.header = payloads.Header(version=0,
                                     prev_hash=types.UInt256.from_string("f782c7fbb2eef6afe629b96c0d53fb525eda64ce5345057caf975ac3c2b9ae0a"),
                                     timestamp=123,
                                     index=1,
                                     primary_index=0,
                                     next_consensus=types.UInt160.from_string("d7678dd97c000be3f33e9362e673101bac4ca654"),
                                     witness=payloads.Witness(invocation_script=b'', verification_script=b'\x55'))
        cls.block = payloads.Block(cls.header,
                                   transactions=[cls.tx])
        cls.block.rebuild_merkle_root()
        flags = bitarray()
        flags.frombytes(b'\x01')
        cls.merkle_payload = payloads.MerkleBlockPayload(cls.block, flags)

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 144
        self.assertEqual(expected_len, len(self.merkle_payload))

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'000000000AAEB9C2C35A97AF7C054553CE64DA5E52FB530D6CB929E6AFF6EEB2FBC782F75618ADD6F91FAD691D6A4D430DB27CE5CA607296863E73A23FC3622A415CDD407B00000000000000010000000054A64CAC1B1073E662933EF3E30B007CD98D67D70100015501015618ADD6F91FAD691D6A4D430DB27CE5CA607296863E73A23FC3622A415CDD400101')
        self.assertEqual(expected_data, self.merkle_payload.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_merkle_payload = payloads.MerkleBlockPayload.deserialize_from_bytes(self.merkle_payload.to_array())
        # not testing all properties again. It re-uses the same block as created in the Block test case
        # only testing new properties
        self.assertEqual(self.merkle_payload.tx_count, deserialized_merkle_payload.tx_count)
        self.assertEqual(len(self.merkle_payload.hashes), len(deserialized_merkle_payload.hashes))
        self.assertEqual(self.merkle_payload.hashes[0], deserialized_merkle_payload.hashes[0])
        self.assertEqual(self.merkle_payload.flags, deserialized_merkle_payload.flags)


class PingTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        var payload = PingPayload.Create(123, 456);
        payload.Timestamp = 888;
        Console.WriteLine(payload.Size);
        Console.WriteLine($"b\'{BitConverter.ToString(payload.ToArray()).Replace("-", "")}\'");
        """
        cls.ping = payloads.PingPayload(123)
        cls.ping.nonce = 456
        cls.ping.timestamp = 888

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 12
        self.assertEqual(expected_len, len(self.ping))

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'7B00000078030000C8010000')
        self.assertEqual(expected_data, self.ping.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_ping = payloads.PingPayload.deserialize_from_bytes(self.ping.to_array())
        self.assertEqual(self.ping.timestamp, deserialized_ping.timestamp)
        self.assertEqual(self.ping.nonce, deserialized_ping.nonce)
        self.assertEqual(self.ping.current_height, deserialized_ping.current_height)


class TestAttributeTypeEnum(enum.IntEnum):
    TYPE_ZERO = 0x00


class TestTXAttribute(payloads.TransactionAttribute):

    def __init__(self):
        super(TestTXAttribute, self).__init__()

        self.type_ = TestAttributeTypeEnum.TYPE_ZERO
        self.test_member = True

    def __len__(self):
        size_bool = 1
        return super(TestTXAttribute, self).__len__() + size_bool

    def _deserialize_without_type(self, reader: serialization.BinaryReader) -> None:
        self.test_member = reader.read_bool()

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        writer.write_bool(self.test_member)


class TransactionAttributeTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        Requires a custom attribute

        class TestTXAttribute : TransactionAttribute
        {
            public override TransactionAttributeType Type { get; }
            public override bool AllowMultiple { get => true; }

            public bool test_member = true;

            public override int Size { get => base.Size + sizeof(bool); }

            protected override void DeserializeWithoutType(BinaryReader reader)
            {
                test_member = reader.ReadBoolean();
            }

            protected override void SerializeWithoutType(BinaryWriter writer)
            {
                writer.Write(test_member);
            }
        }

        TransactionAttribute ta = new TestTXAttribute();
        Console.WriteLine($"{ta.Size}");
        Console.WriteLine($"{BitConverter.ToString(ta.ToArray()).Replace("-", "")}");
        """
        cls.attribute = TestTXAttribute()

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 2
        self.assertEqual(expected_len, len(self.attribute))

    def test_equals(self):
        self.assertFalse(self.attribute == None)
        self.assertFalse(self.attribute == object())
        self.assertTrue(self.attribute == TestTXAttribute())

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'0001')
        self.assertEqual(expected_data, self.attribute.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_attribute = self.attribute.deserialize_from_bytes(self.attribute.to_array())
        self.assertEqual(self.attribute.type_, deserialized_attribute.type_)
        self.assertEqual(self.attribute.test_member, deserialized_attribute.test_member)

    def test_deserialization_wrong_type(self):
        stream_with_type_one = b'\x01'
        attribute = TestTXAttribute()
        with self.assertRaises(ValueError) as context:
            attribute.deserialize_from_bytes(stream_with_type_one)
        self.assertEqual("Deserialization error - transaction attribute type mismatch", str(context.exception))

    def test_deserialization_from(self):
        stream_with_type_zero = b'\x00\x01'
        with serialization.BinaryReader(stream_with_type_zero) as reader:
            ta = payloads.TransactionAttribute.deserialize_from(reader)
        self.assertIsInstance(ta, TestTXAttribute)

    def test_deserialization_from_failure(self):
        stream_with_invalid_type = b'\xFF'
        with serialization.BinaryReader(stream_with_invalid_type) as reader:
            with self.assertRaises(ValueError) as context:
                payloads.TransactionAttribute.deserialize_from(reader)
            self.assertEqual("Deserialization error - unknown transaction attribute type", str(context.exception))


class TransactionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        Transaction tx = new Transaction();
        tx.Nonce = 123;
        tx.SystemFee = 456;
        tx.NetworkFee = 789;
        tx.ValidUntilBlock = 1;
        tx.Attributes = new TransactionAttribute[] { };

        Signer co = new Signer();
        co.Account = UInt160.Parse("0xd7678dd97c000be3f33e9362e673101bac4ca654");
        co.Scopes = WitnessScope.None;
        tx.Signers = new Signer[] { co };

        tx.Script = new byte[] { 0x1, 0x2 };
        tx.Witnesses = new Witness[] { new Witness { InvocationScript=new byte[0], VerificationScript = new byte[] { 0x55 } } };

        Console.WriteLine($"{tx.Size}");
        Console.WriteLine($"{BitConverter.ToString(tx.ToArray()).Replace("-", "")}");
        Console.WriteLine(tx.Hash);
        Console.WriteLine(tx.FeePerByte);
        """
        signer = payloads.Signer(account=types.UInt160.from_string("d7678dd97c000be3f33e9362e673101bac4ca654"),
                                 scope=payloads.WitnessScope.NONE)

        witness = payloads.Witness(invocation_script=b'', verification_script=b'\x55')

        cls.tx = payloads.Transaction(version=0,
                                      nonce=123,
                                      system_fee=456,
                                      network_fee=789,
                                      valid_until_block=1,
                                      attributes=[],
                                      signers=[signer],
                                      script=b'\x01\x02',
                                      witnesses=[witness])

    def tearDown(cls) -> None:
        settings.reset_settings_to_default()

    def test_len_and_hash(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 55
        expected_hash = types.UInt256.from_string('da0343daadf88f95ece657fed6c20e05256d37f0d68757034da1d34f534d2c2c')
        self.assertEqual(expected_len, len(self.tx))
        self.assertEqual(expected_hash, self.tx.hash())

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'007B000000C8010000000000001503000000000000010000000154A64CAC1B1073E662933EF3E30B007CD98D67D7000002010201000155')
        self.assertEqual(expected_data, self.tx.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_tx = payloads.Transaction.deserialize_from_bytes(self.tx.to_array())
        self.assertEqual(self.tx.version, deserialized_tx.version)
        self.assertEqual(self.tx.nonce, deserialized_tx.nonce)
        self.assertEqual(self.tx.system_fee, deserialized_tx.system_fee)
        self.assertEqual(self.tx.network_fee, deserialized_tx.network_fee)
        self.assertEqual(self.tx.valid_until_block, deserialized_tx.valid_until_block)
        self.assertEqual(len(self.tx.attributes), len(deserialized_tx.attributes))
        self.assertEqual(len(self.tx.signers), len(deserialized_tx.signers))
        self.assertEqual(self.tx.signers[0].account, deserialized_tx.signers[0].account)
        self.assertEqual(self.tx.signers[0].scope, deserialized_tx.signers[0].scope)
        self.assertEqual(self.tx.script, deserialized_tx.script)
        self.assertEqual(len(self.tx.witnesses), len(deserialized_tx.witnesses))
        self.assertEqual(self.tx.witnesses[0].invocation_script, deserialized_tx.witnesses[0].invocation_script)
        self.assertEqual(self.tx.witnesses[0].verification_script, deserialized_tx.witnesses[0].verification_script)

    def test_deserialization_version_error(self):
        tx = deepcopy(self.tx)
        tx.version = 1
        with self.assertRaises(ValueError) as context:
            payloads.Transaction.deserialize_from_bytes(tx.to_array())
        self.assertEqual("Deserialization error - invalid version", str(context.exception))

    def test_deserialization_system_fee_error(self):
        tx = deepcopy(self.tx)
        tx.system_fee = -1
        with self.assertRaises(ValueError) as context:
            payloads.Transaction.deserialize_from_bytes(tx.to_array())
        self.assertEqual("Deserialization error - negative system fee", str(context.exception))

    def test_deserialization_network_fee_error(self):
        tx = deepcopy(self.tx)
        tx.network_fee = -1
        with self.assertRaises(ValueError) as context:
            payloads.Transaction.deserialize_from_bytes(tx.to_array())
        self.assertEqual("Deserialization error - negative network fee", str(context.exception))

    def test_deserialization_script_length_error(self):
        tx = deepcopy(self.tx)
        tx.script = b''
        with self.assertRaises(ValueError) as context:
            payloads.Transaction.deserialize_from_bytes(tx.to_array())
        self.assertEqual("Deserialization error - invalid script length 0", str(context.exception))

    def test_deserialization_duplicate_attribute_error(self):
        tx = deepcopy(self.tx)
        tx.attributes = [TestTXAttribute(), TestTXAttribute()]
        with self.assertRaises(ValueError) as context:
            payloads.Transaction.deserialize_from_bytes(tx.to_array())
        self.assertEqual("Deserialization error - duplicate transaction attribute", str(context.exception))

    def test_deserialization_empty_signers_error(self):
        tx = deepcopy(self.tx)
        tx.signers = []
        with self.assertRaises(ValueError) as context:
            payloads.Transaction.deserialize_from_bytes(tx.to_array())
        self.assertEqual("Deserialization error - signers can't be empty", str(context.exception))

    def test_deserialization_duplicate_signer(self):
        tx = deepcopy(self.tx)
        tx.signers[0].scope = payloads.WitnessScope.GLOBAL
        tx.signers.append(deepcopy(tx.signers[0]))
        with self.assertRaises(ValueError) as context:
            payloads.Transaction.deserialize_from_bytes(tx.to_array())
        self.assertEqual("Deserialization error - duplicate signer", str(context.exception))

    def test_fee_per_byte(self):
        # captured from C#, see setUpClass() for the capture code
        expected_fee = 14
        self.assertEqual(expected_fee, self.tx.fee_per_byte())

    def test_equals(self):
        self.assertFalse(None == self.tx)
        self.assertFalse(self.tx == object())

        # test different hashes
        modified_tx = deepcopy(self.tx)
        modified_tx.version = 1
        self.assertFalse(self.tx == modified_tx)
        self.assertTrue(self.tx == self.tx)

    def test_inventory_type(self):
        self.assertEqual(payloads.InventoryType.TX, self.tx.inventory_type)

    def test_from_replica(self):
        t = payloads.Transaction._serializable_init()
        t.from_replica(self.tx)
        self.assertEqual(self.tx.version, t.version)
        self.assertEqual(self.tx.nonce, t.nonce)
        self.assertEqual(self.tx.system_fee, t.system_fee)
        self.assertEqual(self.tx.network_fee, t.network_fee)
        self.assertEqual(self.tx.valid_until_block, t.valid_until_block)
        self.assertEqual(len(self.tx.attributes), len(t.attributes))
        self.assertEqual(len(self.tx.signers), len(t.signers))
        self.assertEqual(self.tx.signers[0].account, t.signers[0].account)
        self.assertEqual(self.tx.signers[0].scope, t.signers[0].scope)
        self.assertEqual(self.tx.script, t.script)
        self.assertEqual(len(self.tx.witnesses), len(t.witnesses))
        self.assertEqual(self.tx.witnesses[0].invocation_script, t.witnesses[0].invocation_script)

    def test_special_serialization(self):
        tx_special = deepcopy(self.tx)
        tx_special.block_height = 1
        with serialization.BinaryWriter() as bw:
            tx_special.serialize_special(bw)
            tx_special_bytes = bw.to_array()

        with serialization.BinaryReader(tx_special_bytes) as br:
            tx_from_bytes = payloads.Transaction._serializable_init()
            tx_from_bytes.deserialize_special(br)
        self.assertEqual(tx_special.block_height, tx_from_bytes.block_height)

    def test_sender(self):
        self.assertEqual(self.tx.signers[0].account, self.tx.sender)

        tx = deepcopy(self.tx)
        tx.signers = []
        self.assertEqual(types.UInt160.zero(), tx.sender)

    def test_protocol_magic(self):
        # test proper initialization
        tx = payloads.Transaction._serializable_init()
        # test default
        self.assertEqual(0x4F454E, tx.protocol_magic)
        # test init supplied
        tx = payloads.Transaction(0, 0, 0, 0, 0, protocol_magic=123)
        self.assertEqual(123, tx.protocol_magic)
        # test settings supplied
        settings.network.magic = 456
        tx = payloads.Transaction._serializable_init()
        self.assertEqual(456, tx.protocol_magic)

    def test_scripthashes_for_verifying(self):
        tx = payloads.Transaction._serializable_init()

        account1 = types.UInt160.from_string("d7678dd97c000be3f33e9362e673101bac4ca654")
        account2 = types.UInt160.zero()
        signer1 = payloads.Signer(account=account1, scope=payloads.WitnessScope.NONE)
        signer2 = payloads.Signer(account=account2, scope=payloads.WitnessScope.NONE)

        tx.signers = [signer1, signer2]

        hashes = tx.get_script_hashes_for_verifying(None)
        self.assertEqual([account1, account2], hashes)

    def test_to_json(self):
        tx = deepcopy(self.tx)
        tx.attributes = [payloads.HighPriorityAttribute()]

        expected = {"hash":"0x61a72c37793ea32b9181105931e7a935eb57c915e9dbeb84dc37068c21df2b20","size":56,"version":0,"nonce":123,"sender":"NTdZAZXWiMSDUTkEFU3nHpT7FEEwwtjwfC","sysfee":"456","netfee":"789","validuntilblock":1,"signers":[{"account":"0xd7678dd97c000be3f33e9362e673101bac4ca654","scopes":"None"}],"attributes":[{"type":"HighPriority"}],"script":"AQI=","witnesses":[{"invocation":"","verification":"VQ=="}]}
        self.assertEqual(expected, tx.to_json())

    def test_from_json(self):
        expected = expected = {"hash":"0x61a72c37793ea32b9181105931e7a935eb57c915e9dbeb84dc37068c21df2b20","size":56,"version":0,"nonce":123,"sender":"NTdZAZXWiMSDUTkEFU3nHpT7FEEwwtjwfC","sysfee":"456","netfee":"789","validuntilblock":1,"signers":[{"account":"0xd7678dd97c000be3f33e9362e673101bac4ca654","scopes":"None"}],"attributes":[{"type":"HighPriority"}],"script":"AQI=","witnesses":[{"invocation":"","verification":"VQ=="}]}
        tx = payloads.Transaction.from_json(expected)
        self.assertEqual(expected, tx.to_json())

class VersionTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        var capabilities = new List<NodeCapability>
        {
            new FullNodeCapability(123)
        };

        capabilities.Add(new ServerCapability(NodeCapabilityType.TcpServer, (ushort)456));
        NodeCapability[] caps = capabilities.ToArray();
        ISerializable message = VersionPayload.Create(888, "my-user-agent", capabilities.ToArray());
        ((VersionPayload)message).Magic = 769;
        ((VersionPayload)message).Timestamp = 0;
        Console.WriteLine($"b\'{BitConverter.ToString(message.ToArray()).Replace("-", "")}\'");
        """
        settings.network.magic = 769
        capa = [
            capabilities.FullNodeCapability(start_height=123),
            capabilities.ServerCapability(capabilities.NodeCapabilityType.TCPSERVER, port=456)
        ]
        cls.vp = payloads.VersionPayload(nonce=888, user_agent="my-user-agent", capabilities=capa)
        cls.vp.timestamp = 0

    @classmethod
    def tearDownClass(cls) -> None:
        settings.reset_settings_to_default()

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 39
        self.assertEqual(expected_len, len(self.vp))

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'010300000000000000000000780300000D6D792D757365722D6167656E7402107B00000001C801')
        self.assertEqual(expected_data, self.vp.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_vp = payloads.VersionPayload.deserialize_from_bytes(self.vp.to_array())
        self.assertEqual(len(self.vp.capabilities), len(deserialized_vp.capabilities))
        self.assertIsInstance(deserialized_vp.capabilities[0], capabilities.FullNodeCapability)
        self.assertEqual(self.vp.capabilities[0].start_height, deserialized_vp.capabilities[0].start_height)
        self.assertIsInstance(deserialized_vp.capabilities[1], capabilities.ServerCapability)
        self.assertEqual(self.vp.capabilities[1].port, deserialized_vp.capabilities[1].port)


class WitnessTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        Witness witness = new Witness();
        witness.VerificationScript = new byte[] { 0x01, 0x02 };
        witness.InvocationScript = new byte[] { 0x03, 0x04 };
        Console.WriteLine($"b\'{BitConverter.ToString(witness.ToArray()).Replace("-","")}\'");
        Console.Write(witness.ToJson());
        """
        cls.witness = payloads.Witness(verification_script=b'\x01\x02', invocation_script=b'\x03\x04')

    def test_len(self):
        # captured from C#, see setUpClass() for the capture code
        expected_len = 6
        self.assertEqual(expected_len, len(self.witness))

    def test_script_hash(self):
        # captured from C#, see setUpClass() for the capture code
        expected_script_hash = types.UInt160.from_string('9132aaf67ab75c0a604419d920c5cb91e149cc15')
        h = self.witness.script_hash()
        self.assertIsInstance(h, types.UInt160)
        self.assertEqual(expected_script_hash, h)

    def test_serialization(self):
        # captured from C#, see setUpClass() for the capture code
        expected_data = binascii.unhexlify(b'020304020102')
        self.assertEqual(expected_data, self.witness.to_array())

    def test_deserialization(self):
        # if the serialization() test for this class passes, we can use that as a reference to test deserialization against
        deserialized_witness = payloads.Witness.deserialize_from_bytes(self.witness.to_array())
        self.assertEqual(self.witness.verification_script, deserialized_witness.verification_script)
        self.assertEqual(self.witness.invocation_script, deserialized_witness.invocation_script)

    def test_to_json(self):
        # captured from C#, see setUpClass() for the capture code
        expected = {"invocation":"AwQ=","verification":"AQI="}
        self.assertEqual(expected, self.witness.to_json())

        expected_empty = {"invocation":"","verification":""}
        empty_witness = payloads.Witness(b'', b'')
        self.assertEqual(expected_empty, empty_witness.to_json())

    def test_from_json(self):
        witness_json = {"invocation": "AwQ=", "verification": "AQI="}
        witness = payloads.Witness.from_json(witness_json)
        self.assertEqual(witness_json, witness.to_json())


class EmptyPayloadTestCase(unittest.TestCase):
    def test_empty(self):
        e = payloads.EmptyPayload()
        self.assertEqual(0, len(e))
        self.assertEqual(0, len(e.to_array()))
        bogus_data = b'\x01\x02\x03'
        self.assertIsInstance(payloads.EmptyPayload.deserialize_from_bytes(bogus_data), payloads.EmptyPayload)
