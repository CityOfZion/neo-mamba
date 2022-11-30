import unittest
import json
from copy import deepcopy
from neo3.contracts import abi, manifest, nef, contract
from neo3.core import cryptography, types, serialization


class ContractGroupTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        private_key = b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        cls.keypair = cryptography.KeyPair(private_key)

        # capture from C#
        cls.expected_json = {
            "pubkey": "033d523f36a732974c0f7dbdfafb5206ecd087211366a274190f05b86d357f4bad",
            "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
        }

    def shortDescription(self) -> str | None:
        # disable comment printing
        return None

    def test_is_valid(self):
        """
        var private_key = new byte[]
        {
            0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1
        };
        var bad_signature = new byte[]
        {
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
        };
        var kp = new KeyPair(private_key);
        var cg = new ContractGroup() { PubKey = kp.PublicKey, Signature = bad_signature};
        Console.Write(cg.ToJson());
        """
        bad_signature = b"\x00" * 64
        cg = manifest.ContractGroup(self.keypair.public_key, bad_signature)
        self.assertFalse(cg.is_valid(types.UInt160.zero()))

        # finally test is_valid() with a keypair we know the private key off
        contract_hash = b"\x01" * 20
        signature = cryptography.sign(contract_hash, self.keypair.private_key)

        cg2 = manifest.ContractGroup(self.keypair.public_key, signature)
        self.assertTrue(cg2.is_valid(types.UInt160(contract_hash)))

    def test_json(self):
        bad_signature = b"\x00" * 64
        cg = manifest.ContractGroup(self.keypair.public_key, bad_signature)
        self.assertEqual(self.expected_json, cg.to_json())

        # if the test_to_json() passes then we know our manually created ControlGroup (cg) is valid,
        # we can now use that to validate our `from_json` object
        cg2 = manifest.ContractGroup.from_json(self.expected_json)
        self.assertEqual(cg.public_key, cg2.public_key)
        self.assertEqual(cg.signature, cg2.signature)

    def test_eq(self):
        cg = manifest.ContractGroup.from_json(self.expected_json)
        cg2 = manifest.ContractGroup.from_json(self.expected_json)
        self.assertFalse(cg == object())
        self.assertTrue(cg == cg2)


class ContractPermissionTestCase(unittest.TestCase):
    def test_default(self):
        cp = manifest.ContractPermission.default_permissions()
        self.assertTrue(cp.contract.is_wildcard)
        self.assertTrue(cp.methods.is_wildcard)

    def test_is_allowed_based_on_hash(self):
        # We test the group permissions where all methods are allowed to be called
        # if contract_hash is valid.
        dummy_contract_hash = types.UInt160.zero()
        contract_state = contract.ContractState(
            1, nef.NEF(), manifest.ContractManifest(), 0, dummy_contract_hash
        )

        # setup an allowed permission for a contract with UInt160.zero hash for all methods
        cpd = manifest.ContractPermissionDescriptor(contract_hash=dummy_contract_hash)
        cp = manifest.ContractPermission(
            contract=cpd, methods=manifest.WildcardContainer.create_wildcard()
        )
        self.assertTrue(
            cp.is_allowed(contract_state.hash, contract_state.manifest, "dummy_method")
        )

        # now create a different contract hash and verify it does not give permission
        contract_state.hash = types.UInt160(b"\x01" * 20)
        self.assertFalse(
            cp.is_allowed(contract_state.hash, contract_state.manifest, "dummy_method")
        )

    def test_is_allowed_based_on_group(self):
        # We test the group permissions where all methods are allowed to be called
        # if the 'groups' member is valid.

        private_key = b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        keypair = cryptography.KeyPair(private_key)

        dummy_contract_hash = types.UInt160.from_string("01" * 20)
        contract_state = contract.ContractState(
            1, nef.NEF(), manifest.ContractManifest(), 0, dummy_contract_hash
        )

        signature = cryptography.sign(
            contract_state.hash.to_array(), keypair.private_key
        )
        contract_state.manifest.groups = [
            manifest.ContractGroup(keypair.public_key, signature)
        ]

        cpd = manifest.ContractPermissionDescriptor(group=keypair.public_key)
        cp = manifest.ContractPermission(
            contract=cpd, methods=manifest.WildcardContainer.create_wildcard()
        )
        self.assertTrue(
            cp.is_allowed(contract_state.hash, contract_state.manifest, "dummy_method")
        )

        # now modify the manifest to have a different `groups` attribute such that validation fails
        public_key = cryptography.ECPoint.deserialize_from_bytes(
            b"\x00"
        )  # ECPoint.Infinity
        contract_state.manifest.groups = [manifest.ContractGroup(public_key, signature)]
        self.assertFalse(
            cp.is_allowed(contract_state.hash, contract_state.manifest, "dummy_method")
        )

    def test_is_allowed_invalid_method(self):
        # in the above tests we validated the 'group' and 'contract_hash' matching logic
        # now we validate 'method' matching
        dummy_contract_hash = types.UInt160.from_string("01" * 20)
        contract_state = contract.ContractState(
            1, nef.NEF(), manifest.ContractManifest(), 0, dummy_contract_hash
        )

        # setup an allowed permission for a contract with UInt160.zero hash for 2 methods
        cpd = manifest.ContractPermissionDescriptor(contract_hash=dummy_contract_hash)
        cp = manifest.ContractPermission(
            contract=cpd,
            methods=manifest.WildcardContainer(data=["method1", "method2"]),
        )
        self.assertTrue(
            cp.is_allowed(contract_state.hash, contract_state.manifest, "method1")
        )
        self.assertTrue(
            cp.is_allowed(contract_state.hash, contract_state.manifest, "method2")
        )
        self.assertFalse(
            cp.is_allowed(contract_state.hash, contract_state.manifest, "method3")
        )

    def test_to_json(self):
        # var cg = ContractPermission.DefaultPermission;
        # Console.WriteLine(cg.ToJson());
        cp = manifest.ContractPermission.default_permissions()
        expected = {"contract": "*", "methods": "*"}
        self.assertDictEqual(expected, cp.to_json())

    def test_from_json(self):
        # we use data from 'test_to_json'
        # we only test parsing basic data, as the detailed parsing is covered
        # by the tests for specific object classes
        json = {"contract": "*", "methods": "*"}
        from_json = manifest.ContractPermission.from_json(json)
        self.assertTrue(from_json.methods.is_wildcard)
        self.assertTrue(from_json.contract.is_wildcard)

    def test_eq(self):
        json = {"contract": "*", "methods": "*"}
        from_json = manifest.ContractPermission.from_json(json)
        from_json2 = manifest.ContractPermission.from_json(json)
        self.assertFalse(from_json == object())
        self.assertTrue(from_json == from_json2)


class WildcardContainerTestCase(unittest.TestCase):
    def test_dunders(self):
        wc = manifest.WildcardContainer(data=["method1", "method2"])
        wc2 = manifest.WildcardContainer(data=["method1", "method2"])
        self.assertIn("method1", wc)
        self.assertIn("method2", wc)
        self.assertNotIn("method3", wc)
        self.assertEqual("method2", wc[1])
        self.assertEqual(2, len(wc))
        self.assertNotEqual(wc, object())
        self.assertEqual(wc, wc2)

    def test_wildcard(self):
        wc = manifest.WildcardContainer.create_wildcard()
        self.assertTrue(wc.is_wildcard)

        wc = manifest.WildcardContainer(["method1"])
        self.assertFalse(wc.is_wildcard)

    def test_to_json(self):
        wc = manifest.WildcardContainer.create_wildcard()
        self.assertDictEqual({"wildcard": "*"}, wc.to_json())

        wc = manifest.WildcardContainer(data=["method1", "method2"])
        self.assertDictEqual({"wildcard": ["method1", "method2"]}, wc.to_json())

    def test_from_json_default(self):
        wc = manifest.WildcardContainer.from_json({"wildcard": "*"})
        self.assertTrue(wc.is_wildcard)

        wc = manifest.WildcardContainer.from_json({"wildcard": ["method1", "method2"]})
        self.assertFalse(wc.is_wildcard)
        self.assertIn("method1", wc)
        self.assertIn("method2", wc)

        with self.assertRaises(ValueError) as context:
            manifest.WildcardContainer.from_json({})
        self.assertEqual(
            "Invalid JSON - Cannot recreate wildcard from None", str(context.exception)
        )

        with self.assertRaises(ValueError) as context:
            manifest.WildcardContainer.from_json({"wildcard": "abc"})
        self.assertEqual(
            "Invalid JSON - Cannot deduce WildcardContainer type from: abc",
            str(context.exception),
        )

    def test_from_json_as_type(self):
        wc = manifest.WildcardContainer.from_json_as_type(
            {"wildcard": "*"}, lambda: None
        )
        self.assertTrue(wc.is_wildcard)

        t1 = types.UInt160.zero()
        t2 = types.UInt160.from_string("11" * 20)
        t3 = types.UInt160.from_string("22" * 20)
        wc = manifest.WildcardContainer.from_json_as_type(
            {"wildcard": [str(t1), str(t2)]}, lambda t: types.UInt160.from_string(t)
        )
        self.assertFalse(wc.is_wildcard)
        self.assertIn(t1, wc)
        self.assertIn(t2, wc)
        self.assertNotIn(t3, wc)

        with self.assertRaises(ValueError) as context:
            manifest.WildcardContainer.from_json_as_type({}, lambda: None)
        self.assertEqual(
            "Invalid JSON - Cannot recreate wildcard from None", str(context.exception)
        )

        with self.assertRaises(ValueError) as context:
            manifest.WildcardContainer.from_json_as_type(
                {"wildcard": "abc"}, lambda: None
            )
        self.assertEqual(
            "Invalid JSON - Cannot deduce WildcardContainer type from: abc",
            str(context.exception),
        )


class ManifestTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        """
        var manifest = new ContractManifest()
        {
            Name = "test_contract",
            Groups = new ContractGroup[0],
            SupportedStandards = Array.Empty<string>(),
            Abi = new ContractAbi()
            {
                Events = new ContractEventDescriptor[0],
                Methods = new ContractMethodDescriptor[]
                {
                    new ContractMethodDescriptor {
                        Name = "main_entry",
                        Offset = 0,
                        Parameters = new ContractParameterDefinition[0],
                        ReturnType = ContractParameterType.Integer,
                        Safe = true
                    }
                }
            },
            Permissions = new[] { ContractPermission.DefaultPermission },
            Trusts = WildcardContainer<ContractPermissionDescriptor>.Create(),
            Extra = null
        };
        Console.WriteLine($"{manifest.ToJson()}");
        """
        cls.expected_json = {
            "name": "test_contract",
            "groups": [],
            "features": {},
            "supportedstandards": [],
            "abi": {
                "methods": [
                    {
                        "name": "main_entry",
                        "parameters": [],
                        "returntype": "Integer",
                        "offset": 0,
                        "safe": True,
                    }
                ],
                "events": [],
            },
            "permissions": [{"contract": "*", "methods": "*"}],
            "trusts": [],
            "extra": None,
        }

    def test_create(self):
        cm = manifest.ContractManifest("test_contract")
        method1 = abi.ContractMethodDescriptor(
            name="main_entry",
            offset=0,
            parameters=[],
            return_type=abi.ContractParameterType.INTEGER,
            safe=True,
        )
        cm.abi.methods = [method1]
        self.assertEqual(self.expected_json, cm.to_json())

    def test_serialize(self):
        # if test_create() passes, then we know `to_json()` is ok, which serialize internally uses
        cm = manifest.ContractManifest("test_contract")
        method1 = abi.ContractMethodDescriptor(
            name="main_entry",
            offset=0,
            parameters=[],
            return_type=abi.ContractParameterType.INTEGER,
            safe=True,
        )
        cm.abi.methods = [method1]
        with serialization.BinaryReader(cm.to_array()) as br:
            data = br.read_var_string()
        self.assertDictEqual(self.expected_json, json.loads(data))

    def test_to_json_with_trusts_extra(self):
        # create a default manifest
        m = manifest.ContractManifest("test_contract")
        method1 = abi.ContractMethodDescriptor(
            name="main_entry",
            offset=0,
            parameters=[],
            return_type=abi.ContractParameterType.INTEGER,
            safe=True,
        )
        m.abi.methods = [method1]

        t1 = manifest.ContractPermissionDescriptor(
            contract_hash=types.UInt160.from_string("01" * 20)
        )
        t2 = manifest.ContractPermissionDescriptor(
            contract_hash=types.UInt160.from_string("02" * 20)
        )
        m.trusts = manifest.WildcardContainer(data=[t1, t2])
        m.extra = False
        json_out = m.to_json()
        self.assertIn(t1.to_json()["contract"], json_out["trusts"])
        self.assertIn(t2.to_json()["contract"], json_out["trusts"])
        self.assertFalse(json_out["extra"])

    def test_from_json(self):
        expected_json = deepcopy(self.expected_json)
        cm = manifest.ContractManifest.from_json(expected_json)
        default = manifest.ContractManifest()
        self.assertEqual(default.groups, cm.groups)
        self.assertEqual(default.permissions, cm.permissions)
        self.assertEqual(default.trusts, cm.trusts)
        self.assertEqual(default.extra, cm.extra)

    def test_deserialization(self):
        # this assumes test_serialization() passes
        cm = manifest.ContractManifest("test_contract")
        method1 = abi.ContractMethodDescriptor(
            name="main_entry",
            offset=0,
            parameters=[],
            return_type=abi.ContractParameterType.INTEGER,
            safe=True,
        )
        cm.abi.methods = [method1]
        cm_deserialized = manifest.ContractManifest.deserialize_from_bytes(
            cm.to_array()
        )
        self.assertEqual(cm, cm_deserialized)

    def test_is_valid(self):
        # create a contract
        cm = manifest.ContractManifest("test_contract")
        method1 = abi.ContractMethodDescriptor(
            name="main_entry",
            offset=0,
            parameters=[],
            return_type=abi.ContractParameterType.INTEGER,
            safe=True,
        )
        cm.abi.methods = [method1]

        # A contract hash is normally created from a combination of transaction sender (UInt160), NEF checksum and manifest.name
        # For this test we'll keep it simple and pretend that hash is all zeros
        dummy_contract_hash = types.UInt160.zero()

        # a "default" contract has no groups data, which is the same as always allow
        self.assertTrue(cm.is_valid(dummy_contract_hash))

        # now try to add a malicious group member (meaning; the member did not actually sign the ABI)
        private_key = b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        keypair = cryptography.KeyPair(private_key)
        bad_signature = bytes(64)
        cm.groups = [manifest.ContractGroup(keypair.public_key, bad_signature)]
        # this time validation should fail
        self.assertFalse(cm.is_valid(dummy_contract_hash))

        # Finally test with a group member that did sign the ABI
        good_signature = cryptography.sign(
            dummy_contract_hash.to_array(), keypair.private_key
        )
        cm.groups = [manifest.ContractGroup(keypair.public_key, good_signature)]
        self.assertTrue(cm.is_valid(dummy_contract_hash))

    def test_eq(self):
        cm = manifest.ContractManifest.from_json(self.expected_json)
        cm2 = manifest.ContractManifest.from_json(self.expected_json)
        self.assertFalse(cm == object())
        self.assertTrue(cm == cm2)


class ContractPermissionDescriptorTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        private_key = b"\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        cls.keypair = cryptography.KeyPair(private_key)

    def test_wildcard(self):
        cpd = manifest.ContractPermissionDescriptor()
        self.assertTrue(cpd.is_wildcard)
        self.assertDictEqual({"contract": "*"}, cpd.to_json())
        cpd_from_json = manifest.ContractPermissionDescriptor.from_json(cpd.to_json())
        self.assertEqual(cpd.contract_hash, cpd_from_json.contract_hash)
        self.assertEqual(cpd.group, cpd_from_json.group)

    def test_group(self):
        cpd = manifest.ContractPermissionDescriptor(contract_hash=types.UInt160.zero())
        self.assertTrue(cpd.is_hash)
        self.assertFalse(cpd.is_group)
        self.assertFalse(cpd.is_wildcard)
        self.assertDictEqual(
            {"contract": "0x0000000000000000000000000000000000000000"}, cpd.to_json()
        )
        cpd_from_json = manifest.ContractPermissionDescriptor.from_json(cpd.to_json())
        self.assertEqual(cpd.contract_hash, cpd_from_json.contract_hash)
        self.assertEqual(cpd.group, cpd_from_json.group)

    def test_contract_hash(self):
        cpd = manifest.ContractPermissionDescriptor(group=self.keypair.public_key)
        self.assertFalse(cpd.is_hash)
        self.assertTrue(cpd.is_group)
        self.assertFalse(cpd.is_wildcard)
        self.assertDictEqual(
            {
                "contract": "033d523f36a732974c0f7dbdfafb5206ecd087211366a274190f05b86d357f4bad"
            },
            cpd.to_json(),
        )
        cpd_from_json = manifest.ContractPermissionDescriptor.from_json(cpd.to_json())

        self.assertEqual(cpd.contract_hash, cpd_from_json.contract_hash)
        self.assertEqual(cpd.group, cpd_from_json.group)

    def test_exceptions(self):
        # test construction with too many arguments given
        with self.assertRaises(ValueError) as context:
            cpd = manifest.ContractPermissionDescriptor(
                contract_hash=types.UInt160.zero(), group=self.keypair.public_key
            )
        self.assertIn("Maximum 1 argument", str(context.exception))

        # test from_json with invalid json
        with self.assertRaises(ValueError) as context:
            manifest.ContractPermissionDescriptor.from_json({"contract": None})
        self.assertEqual(
            "Invalid JSON - Cannot deduce permission type from None",
            str(context.exception),
        )

        with self.assertRaises(ValueError) as context:
            manifest.ContractPermissionDescriptor.from_json({"contract": "abc"})
        self.assertEqual(
            "Invalid JSON - Cannot deduce permission type from: abc",
            str(context.exception),
        )
