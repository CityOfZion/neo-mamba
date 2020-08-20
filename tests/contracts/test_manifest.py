import unittest
import json
from copy import deepcopy
from unittest import mock
from neo3 import contracts
from neo3.core import cryptography, types, utils, serialization


class ContractGroupTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        private_key = b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
        cls.keypair = cryptography.KeyPair(private_key)

        # capture from C#
        cls.expected_json = {'pubKey': '033d523f36a732974c0f7dbdfafb5206ecd087211366a274190f05b86d357f4bad', 'signature': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='}

    def test_is_valid(self):
        """
        var private_key = new byte[]
        {
            0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1
        };
        var bad_signature = new byte[]
        {
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
        };
        var kp = new KeyPair(private_key);
        var cg = new ContractGroup() { PubKey = kp.PublicKey, Signature = bad_signature};
        Console.Write(cg.ToJson());
        """
        bad_signature = b'\x00' * 32
        cg = contracts.ContractGroup(self.keypair.public_key, bad_signature)
        self.assertFalse(cg.is_valid(types.UInt160.zero()))

        # finally test is_valid() with a keypair we know the private key off
        contract_hash = b'\x01' * 20
        signature = cryptography.sign(contract_hash, self.keypair.private_key)

        cg2 = contracts.ContractGroup(self.keypair.public_key, signature)
        self.assertTrue(cg2.is_valid(types.UInt160(contract_hash)))

    def test_json(self):
        bad_signature = b'\x00' * 32
        cg = contracts.ContractGroup(self.keypair.public_key, bad_signature)
        self.assertEqual(self.expected_json, cg.to_json())

        # if the test_to_json() passes then we know our manually created ControlGroup (cg) is valid,
        # we can now use that to validate our `from_json` object
        cg2 = contracts.ContractGroup.from_json(self.expected_json)
        self.assertEqual(cg.public_key, cg2.public_key)
        self.assertEqual(cg.signature, cg2.signature)

    def test_eq(self):
        cg = contracts.ContractGroup.from_json(self.expected_json)
        cg2 = contracts.ContractGroup.from_json(self.expected_json)
        self.assertFalse(cg == object())
        self.assertTrue(cg == cg2)


class ContractPermissionTestCase(unittest.TestCase):
    def test_default(self):
        cp = contracts.ContractPermission.default_permissions()
        self.assertTrue(cp.contract.is_wildcard)
        self.assertTrue(cp.methods.is_wildcard)

    def test_is_allowed_based_on_hash(self):
        # We test the group permissions where all methods are allowed to be called
        # if contract_hash is valid.
        mock_manifest = mock.MagicMock()
        mock_manifest.contract_hash = types.UInt160.zero()

        # setup an allowed permission for a contract with UInt160.zero hash for all methods
        cpd = contracts.ContractPermissionDescriptor(contract_hash=types.UInt160.zero())
        cp = contracts.ContractPermission(contract=cpd, methods=contracts.WildcardContainer.create_wildcard())
        self.assertTrue(cp.is_allowed(mock_manifest, "dummy_method"))

        # now create a different contract hash and verify it does not give permission
        mock_manifest.contract_hash = types.UInt160.from_string("01" * 20)
        self.assertFalse(cp.is_allowed(mock_manifest, "dummy_method"))

    def test_is_allowed_based_on_group(self):
        # We test the group permissions where all methods are allowed to be called
        # if the 'groups' member is valid.

        private_key = b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
        keypair = cryptography.KeyPair(private_key)

        mock_manifest = mock.MagicMock()
        mock_manifest.contract_hash = types.UInt160.from_string("01" * 20)
        signature = cryptography.sign(mock_manifest.contract_hash.to_array(), keypair.private_key)
        mock_manifest.groups = [contracts.ContractGroup(keypair.public_key, signature)]

        cpd = contracts.ContractPermissionDescriptor(group=keypair.public_key)
        cp = contracts.ContractPermission(contract=cpd, methods=contracts.WildcardContainer.create_wildcard())
        self.assertTrue(cp.is_allowed(mock_manifest, "dummy_method"))

        # now modify the manifest to have a different `groups` attribute such that validation fails
        public_key = cryptography.EllipticCurve.ECPoint.deserialize_from_bytes(b'\x00')  # ECPoint.Infinity
        mock_manifest.groups = [contracts.ContractGroup(public_key, signature)]
        self.assertFalse(cp.is_allowed(mock_manifest, "dummy_method"))

    def test_is_allowed_invalid_method(self):
        # in the above tests we validated the 'group' and 'contract_hash' matching logic
        # now we validate 'method' matching
        mock_manifest = mock.MagicMock()
        mock_manifest.contract_hash = types.UInt160.zero()

        # setup an allowed permission for a contract with UInt160.zero hash for 2 methods
        cpd = contracts.ContractPermissionDescriptor(contract_hash=types.UInt160.zero())
        cp = contracts.ContractPermission(contract=cpd, methods=contracts.WildcardContainer(data=['method1','method2']))
        self.assertTrue(cp.is_allowed(mock_manifest, "method1"))
        self.assertTrue(cp.is_allowed(mock_manifest, "method2"))
        self.assertFalse(cp.is_allowed(mock_manifest, "method3"))

    def test_to_json(self):
        # var cg = ContractPermission.DefaultPermission;
        # Console.WriteLine(cg.ToJson());
        cp = contracts.ContractPermission.default_permissions()
        expected = {"contract": "*", "methods": "*"}
        self.assertDictEqual(expected, cp.to_json())

    def test_from_json(self):
        # we use data from 'test_to_json'
        # we only test parsing basic data, as the detailed parsing is covered
        # by the tests for specific object classes
        json = {"contract": "*", "methods": "*"}
        from_json = contracts.ContractPermission.from_json(json)
        self.assertTrue(from_json.methods.is_wildcard)
        self.assertTrue(from_json.contract.is_wildcard)

    def test_eq(self):
        json = {"contract": "*", "methods": "*"}
        from_json = contracts.ContractPermission.from_json(json)
        from_json2 = contracts.ContractPermission.from_json(json)
        self.assertFalse(from_json == object())
        self.assertTrue(from_json == from_json2)


class WildcardContainerTestCase(unittest.TestCase):
    def test_dunders(self):
        wc = contracts.WildcardContainer(data=['method1', 'method2'])
        wc2 = contracts.WildcardContainer(data=['method1', 'method2'])
        self.assertIn('method1', wc)
        self.assertIn('method2', wc)
        self.assertNotIn('method3', wc)
        self.assertEqual('method2', wc[1])
        self.assertEqual(2, len(wc))
        self.assertNotEqual(wc, object())
        self.assertEqual(wc, wc2)

    def test_wildcard(self):
        wc = contracts.WildcardContainer.create_wildcard()
        self.assertTrue(wc.is_wildcard)

        wc = contracts.WildcardContainer(['method1'])
        self.assertFalse(wc.is_wildcard)

    def test_to_json(self):
        wc = contracts.WildcardContainer.create_wildcard()
        self.assertDictEqual({'wildcard': '*'}, wc.to_json())

        wc = contracts.WildcardContainer(data=['method1', 'method2'])
        self.assertDictEqual({'wildcard': ['method1', 'method2']}, wc.to_json())

    def test_from_json_default(self):
        wc = contracts.WildcardContainer.from_json({'wildcard': '*'})
        self.assertTrue(wc.is_wildcard)

        wc = contracts.WildcardContainer.from_json({'wildcard': ['method1', 'method2']})
        self.assertFalse(wc.is_wildcard)
        self.assertIn('method1', wc)
        self.assertIn('method2', wc)

        with self.assertRaises(ValueError) as context:
            contracts.WildcardContainer.from_json({})
        self.assertEqual("Invalid JSON - Cannot recreate wildcard from None", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.WildcardContainer.from_json({'wildcard': 'abc'})
        self.assertEqual("Invalid JSON - Cannot deduce WildcardContainer type from: abc", str(context.exception))

    def test_from_json_as_type(self):
        wc = contracts.WildcardContainer.from_json_as_type({'wildcard': '*'}, lambda: None)
        self.assertTrue(wc.is_wildcard)

        t1 = types.UInt160.zero()
        t2 = types.UInt160.from_string("11" * 20)
        t3 = types.UInt160.from_string("22" * 20)
        wc = contracts.WildcardContainer.from_json_as_type({'wildcard': [str(t1), str(t2)]},
                                                           lambda t: types.UInt160.from_string(t))
        self.assertFalse(wc.is_wildcard)
        self.assertIn(t1, wc)
        self.assertIn(t2, wc)
        self.assertNotIn(t3, wc)

        with self.assertRaises(ValueError) as context:
            contracts.WildcardContainer.from_json_as_type({}, lambda: None)
        self.assertEqual("Invalid JSON - Cannot recreate wildcard from None", str(context.exception))

        with self.assertRaises(ValueError) as context:
            contracts.WildcardContainer.from_json_as_type({'wildcard': 'abc'}, lambda: None)
        self.assertEqual("Invalid JSON - Cannot deduce WildcardContainer type from: abc", str(context.exception))


class ManifestTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        var cm = ContractManifest.CreateDefault(UInt160.Zero);
        Console.WriteLine(cm.ToJson());
        Console.WriteLine(cm.Size);
        """
        cls.expected_json = {"groups":[],"features":{"storage":False,"payable":False},"abi":{"hash":"0x0000000000000000000000000000000000000000","entryPoint":{"name":"Main","parameters":[{"name":"operation","type":"String"},{"name":"args","type":"Array"}],"returnType":"Any"},"methods":[],"events":[]},"permissions":[{"contract":"*","methods":"*"}],"trusts":[],"safeMethods":[],"extra":None}

    def test_create_default(self):
        cm = contracts.ContractManifest(types.UInt160.zero())
        self.assertEqual(self.expected_json, cm.to_json())
        # see setupClass for C# reference code
        self.assertEqual(366, len(cm))

    def test_serialize(self):
        # if test_create_default() passes, then we know `to_json()` is ok, which serialize internally uses
        cm = contracts.ContractManifest(types.UInt160.zero())
        with serialization.BinaryReader(cm.to_array()) as br:
            data = br.read_var_string()
        self.assertDictEqual(self.expected_json, json.loads(data))

    def test_to_json_with_trusts_safemethods_extra(self):
        # create a default manifest
        m = contracts.ContractManifest(types.UInt160.zero())
        t1 = types.UInt160.from_string("01" * 20)
        t2 = types.UInt160.from_string("02" * 20)
        m.trusts = contracts.WildcardContainer(data=[t1, t2])
        m.safe_methods = contracts.WildcardContainer(data=["safe1"])
        m.extra = False
        json_out = m.to_json()

        self.assertIn("0x" + str(t1), json_out['trusts'])
        self.assertIn("0x" + str(t2), json_out['trusts'])
        self.assertIn("safe1", json_out['safeMethods'])
        self.assertFalse(json_out['extra'])

    def test_from_json(self):
        expected_json = deepcopy(self.expected_json)
        # we update the defaults to also test the features
        new_features = {'storage': True, 'payable':True}
        expected_json['features'] = new_features
        cm = contracts.ContractManifest.from_json(expected_json)
        default = contracts.ContractManifest(types.UInt160.zero())
        self.assertEqual(default.groups, cm.groups)
        self.assertIn(contracts.ContractFeatures.HAS_STORAGE, cm.features)
        self.assertIn(contracts.ContractFeatures.PAYABLE, cm.features)
        self.assertEqual(default.permissions, cm.permissions)
        self.assertEqual(default.trusts, cm.trusts)
        self.assertEqual(default.safe_methods, cm.safe_methods)
        self.assertEqual(default.extra, cm.extra)

    def test_deserialization(self):
        # this assumes test_serialization() passes
        cm = contracts.ContractManifest(types.UInt160.zero())
        cm_deserialized = contracts.ContractManifest.deserialize_from_bytes(cm.to_array())
        self.assertEqual(cm, cm_deserialized)

    def test_is_valid(self):
        # create a default contract
        cm = contracts.ContractManifest()
        # a default contract uses a UInt160.zero as contract hash
        self.assertTrue(cm.is_valid(types.UInt160.zero()))
        self.assertFalse(cm.is_valid(types.UInt160.from_string("11"*20)))

        # now try to add a malicious group member (meaning; the member did not actually sign the ABI)
        private_key = b'\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
        keypair = cryptography.KeyPair(private_key)
        bad_signature = bytearray(32)
        cm.groups = [contracts.ContractGroup(keypair.public_key,bad_signature)]
        # this time validation should fail
        self.assertFalse(cm.is_valid(types.UInt160.zero()))

        # Finally test with a group member that did sign the ABI
        good_signature = cryptography.sign(cm.abi.contract_hash.to_array(), keypair.private_key)
        cm.groups = [contracts.ContractGroup(keypair.public_key, good_signature)]
        self.assertTrue(cm.is_valid(types.UInt160.zero()))

    def test_can_call(self):
        # create a default contract, which is allowed to call any other contract and any other method
        cm = contracts.ContractManifest()
        target_manifest = contracts.ContractManifest()
        target_manifest.abi.contract_hash = types.UInt160.from_string("11" * 20)
        self.assertTrue(cm.can_call(target_manifest, "some_method"))

        # now add a permission that allows all methods, but for a different contract hash
        contract_hash = types.UInt160.from_string("22" * 20)
        cpd = contracts.ContractPermissionDescriptor(contract_hash=contract_hash)
        cp = contracts.ContractPermission(contract=cpd, methods=contracts.WildcardContainer.create_wildcard())
        cm.permissions = [cp]
        self.assertFalse(cm.can_call(target_manifest, "some_method"))

        # now change the permissions (specifically the contract_hash) to allow calling
        new_contract_hash = types.UInt160.zero()
        cpd = contracts.ContractPermissionDescriptor(contract_hash=new_contract_hash)
        cp = contracts.ContractPermission(contract=cpd, methods=contracts.WildcardContainer.create_wildcard())
        cm.permissions = [cp]
        self.assertTrue(cm.can_call(target_manifest, "some_method"))

    def test_eq(self):
        cm = contracts.ContractManifest.from_json(self.expected_json)
        cm2 = contracts.ContractManifest.from_json(self.expected_json)
        self.assertFalse(cm == object())
        self.assertTrue(cm == cm2)
