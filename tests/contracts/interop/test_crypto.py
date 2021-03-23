import unittest
import binascii
from typing import List
from neo3.network import payloads
from neo3 import vm, storage, settings
from neo3.core import types, serialization, cryptography
from neo3.core.serialization import BinaryReader, BinaryWriter
from tests.contracts.interop.utils import test_engine, syscall_name_to_int
from neo3.contracts.interop.crypto import _check_multisig


class TestVerifiable(payloads.IVerifiable):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.teststr = "testStr"

    def serialize_unsigned(self, writer: serialization.BinaryWriter) -> None:
        writer.write_uint8(len(self.teststr))
        writer.write_bytes(self.teststr.encode())

    def deserialize_unsigned(self, reader: serialization.BinaryReader) -> None:
        raise NotImplementedError()

    def get_script_hashes_for_verifying(self, snapshot: storage.Snapshot) -> List[types.UInt160]:
        raise NotImplementedError()

    def serialize(self, writer: BinaryWriter) -> None:
        raise NotImplementedError()

    def deserialize(self, reader: BinaryReader) -> None:
        raise NotImplementedError()

    def __len__(self):
        pass


class CryptoInteropTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_ripemd160_interop_type(self):
        """
        using var script = new ScriptBuilder();
        script.EmitSysCall(ApplicationEngine.Neo_Crypto_RIPEMD160); // Syscall
        var engine = ApplicationEngine.Create(TriggerType.Application, null, null, 100_000_000, false);
        engine.LoadScript(script.ToArray());
        engine.Push(new InteropInterface(new TestVerifiable()));
        Assert.AreEqual(engine.Execute(), VMState.HALT);
        Assert.AreEqual(1, engine.ResultStack.Count);
        var item = engine.ResultStack.Pop<ByteString>();
        Console.WriteLine($"{item.GetSpan().ToHexString()}");
        """
        # we have to set the network magic number, because that is serialized as part of the "get_hash_data()" call
        settings.network.magic = 0x4F454E

        sb = vm.ScriptBuilder()
        sb.emit_syscall(syscall_name_to_int("Neo.Crypto.RIPEMD160"))

        engine = test_engine()
        script = vm.Script(sb.to_array())
        engine.load_script(script)

        # first test with an invalid interop item. They must be IVerifiable
        engine.push(vm.InteropStackItem(object()))
        engine.execute()
        self.assertEqual(vm.VMState.FAULT, engine.state)
        self.assertIn("Invalid type", engine.exception_message)

        engine = test_engine()
        engine.load_script(script)
        engine.push(vm.InteropStackItem(TestVerifiable()))
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        # captured from C#
        expected = '72543eb0fa0ca623a95647f15dd55f52a327c77e'
        self.assertEqual(expected, str(engine.result_stack.pop()))

    def test_ripemd160_null(self):
        """
        var tx = new Neo.Network.P2P.Payloads.Transaction
        {
            Version = 0,
            Nonce = 0,
            SystemFee = 0,
            NetworkFee = 0,
            ValidUntilBlock = 99999,
            Attributes = new TransactionAttribute[0],
            Script = new byte[0],
            Signers = new Signer[] { new Signer { Account = UInt160.Zero, Scopes = WitnessScope.FeeOnly}}
        };
        using var script = new ScriptBuilder();
        script.EmitSysCall(ApplicationEngine.Neo_Crypto_RIPEMD160); // Syscall
        var engine = ApplicationEngine.Create(TriggerType.Application, tx, null, 100_000_000, false);
        engine.LoadScript(script.ToArray());
        engine.Push(StackItem.Null);
        Assert.AreEqual(engine.Execute(), VMState.HALT);
        Assert.AreEqual(1, engine.ResultStack.Count);
        var item = engine.ResultStack.Pop<ByteString>();
        Console.WriteLine($"{item.GetSpan().ToHexString()}");
        """
        # we have to set the network magic number, because that is serialized as part of the "get_hash_data()" call
        settings.network.magic = 0x4F454E

        sb = vm.ScriptBuilder()
        sb.emit_syscall(syscall_name_to_int("Neo.Crypto.RIPEMD160"))

        engine = test_engine(has_container=True)
        engine.script_container.signers = [payloads.Signer(types.UInt160.zero())]
        script = vm.Script(sb.to_array())
        engine.load_script(script)

        engine.push(vm.NullStackItem())
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        # captured from C#
        expected = '0892b2402eb78d878a4c60fc799d879b672a5aa5'
        self.assertEqual(expected, str(engine.result_stack.pop()))

    def test_ripemd160_other_types(self):
        """
        using var script = new ScriptBuilder();
        script.EmitPush(new byte[] {0x1, 0x2, 0x3, 0x4});
        script.EmitSysCall(ApplicationEngine.Neo_Crypto_RIPEMD160); // Syscall
        var engine = ApplicationEngine.Create(TriggerType.Application, null, null, 100_000_000, false);
        engine.LoadScript(script.ToArray());
        Assert.AreEqual(engine.Execute(), VMState.HALT);
        Assert.AreEqual(1, engine.ResultStack.Count);
        var item = engine.ResultStack.Pop<ByteString>();
        Console.WriteLine($"{item.GetSpan().ToHexString()}");
        """
        sb = vm.ScriptBuilder()
        sb.emit_push(b'\x01\x02\x03\x04')
        sb.emit_syscall(syscall_name_to_int("Neo.Crypto.RIPEMD160"))

        engine = test_engine()
        script = vm.Script(sb.to_array())
        engine.load_script(script)
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        # captured from C#
        expected = '179bb366e5e224b8bf4ce302cefc5744961839c5'
        self.assertEqual(expected, str(engine.result_stack.pop()))

    def test_sha256(self):
        """
        using var script = new ScriptBuilder();
        script.EmitPush(new byte[] {0x1, 0x2, 0x3, 0x4});
        script.EmitSysCall(ApplicationEngine.Neo_Crypto_SHA256); // Syscall
        var engine = ApplicationEngine.Create(TriggerType.Application, null, null, 100_000_000, false);
        engine.LoadScript(script.ToArray());
        Assert.AreEqual(engine.Execute(), VMState.HALT);
        Assert.AreEqual(1, engine.ResultStack.Count);
        var item = engine.ResultStack.Pop<ByteString>();
        Console.WriteLine($"{item.GetSpan().ToHexString()}");
        """
        sb = vm.ScriptBuilder()
        sb.emit_push(b'\x01\x02\x03\x04')
        sb.emit_syscall(syscall_name_to_int("Neo.Crypto.SHA256"))

        engine = test_engine()
        script = vm.Script(sb.to_array())
        engine.load_script(script)
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        # captured from C#
        expected = '9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a'
        self.assertEqual(expected, str(engine.result_stack.pop()))

    def test_verify_secp256r1(self):
        """
        var privkey = new byte[]
        {
            2, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1
        };
        var message = new byte[]
        {
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1
        };
        var signature = new byte[] { 56,70,104,22,234,182,23,161,111,25,71,188,12,5,54,28,99,189,8,47,4,82,62,150,57,216,25,130,217,25,123,118,89,149,217,130,12,109,34,125,176,189,142,119,154,140,116,16,32,209,214,87,178,248,214,39,248,29,214,10,205,153,146,111};
        var kp = new KeyPair(privkey);
        Console.WriteLine(Crypto.VerifySignature(message, signature, kp.PublicKey.EncodePoint(false), ECCurve.Secp256r1));
        """
        message = b'\x01' * 32
        priv_key = b'\x02' + b'\x00' * 30 + b'\x01'
        sig = cryptography.sign(message, priv_key)

        # from ecdsa import VerifyingKey, SigningKey, curves as ecdsa_curves
        # import hashlib
        # sk = SigningKey.from_string(priv_key, curve=ecdsa_curves.NIST256p, hashfunc=hashlib.sha256)
        # sig = sk.sign(message, hashfunc=hashlib.sha256)

        kp = cryptography.KeyPair(priv_key)

        sb = vm.ScriptBuilder()
        sb.emit_push(sig)
        sb.emit_push(kp.public_key.encode_point(False))
        sb.emit_push(message)
        sb.emit_syscall(syscall_name_to_int("Neo.Crypto.VerifyWithECDsaSecp256r1"))

        engine = test_engine()
        script = vm.Script(sb.to_array())
        engine.load_script(script)

        # first test with an invalid interop item. They must be IVerifiable
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        self.assertEqual(vm.BooleanStackItem(True), engine.result_stack.pop())

    def test_verify_secp256k1(self):
        """
        byte[] message = System.Text.Encoding.Default.GetBytes("hello");
        byte[] signature = "5331be791532d157df5b5620620d938bcb622ad02c81cfc184c460efdad18e695480d77440c511e9ad02ea30d773cb54e88f8cbb069644aefa283957085f38b5".HexToBytes();
        byte[] pubKey = "03ea01cb94bdaf0cd1c01b159d474f9604f4af35a3e2196f6bdfdb33b2aa4961fa".HexToBytes();

        Crypto.VerifySignature(message, signature, pubKey, Neo.Cryptography.ECC.ECCurve.Secp256k1).Should().BeTrue();
        """
        message = b'hello'
        signature = binascii.unhexlify(b'5331be791532d157df5b5620620d938bcb622ad02c81cfc184c460efdad18e695480d77440c511e9ad02ea30d773cb54e88f8cbb069644aefa283957085f38b5')
        public_key = binascii.unhexlify(b'03ea01cb94bdaf0cd1c01b159d474f9604f4af35a3e2196f6bdfdb33b2aa4961fa')
        self.assertTrue(cryptography.verify_signature(message, signature, public_key, cryptography.ECCCurve.SECP256K1))

        sb = vm.ScriptBuilder()
        sb.emit_push(signature)
        sb.emit_push(public_key)
        sb.emit_push(message)
        sb.emit_syscall(syscall_name_to_int("Neo.Crypto.VerifyWithECDsaSecp256k1"))

        engine = test_engine()
        script = vm.Script(sb.to_array())
        engine.load_script(script)

        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        self.assertEqual(vm.BooleanStackItem(True), engine.result_stack.pop())

        # again with bad signature
        bad_signature = b'\xFF' + signature[1:]
        sb = vm.ScriptBuilder()
        sb.emit_push(bad_signature)
        sb.emit_push(public_key)
        sb.emit_push(message)
        sb.emit_syscall(syscall_name_to_int("Neo.Crypto.VerifyWithECDsaSecp256k1"))

        engine = test_engine()
        script = vm.Script(sb.to_array())
        engine.load_script(script)

        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        self.assertEqual(vm.BooleanStackItem(False), engine.result_stack.pop())

    def test_multisig_verify_helper_bounds(self):
        engine = None
        message = vm.ByteStringStackItem(b'')
        public_keys = [object()]
        signatures = []

        with self.assertRaises(ValueError) as context:
            _check_multisig(engine, message, public_keys, signatures, cryptography.ECCCurve.SECP256R1)
        self.assertEqual("No signatures supplied", str(context.exception))

        public_keys = []
        signatures = [object()]
        with self.assertRaises(ValueError) as context:
            _check_multisig(engine, message, public_keys, signatures, cryptography.ECCCurve.SECP256R1)
        self.assertEqual("No public keys supplied", str(context.exception))

        public_keys = [object()]
        signatures = [object(), object()]
        with self.assertRaises(ValueError) as context:
            _check_multisig(engine, message, public_keys, signatures, cryptography.ECCCurve.SECP256R1)
        self.assertEqual("Verification requires 2 public keys, got only 1", str(context.exception))

    def test_multisig_verify_helper_verification(self):
        engine = test_engine()
        message = vm.ByteStringStackItem(b'hello')
        kp1 = cryptography.KeyPair(private_key=b'\x01' * 32)
        kp2 = cryptography.KeyPair(private_key=b'\x02' * 32)
        sig1 = cryptography.sign(message.to_array(), kp1.private_key)
        sig2 = cryptography.sign(message.to_array(), kp2.private_key)

        # quick pre-check the verify_signature function actually passes
        self.assertTrue(cryptography.verify_signature(message.to_array(),
                                                      sig1,
                                                      kp1.public_key.encode_point(False),
                                                      cryptography.ECCCurve.SECP256R1))
        self.assertTrue(cryptography.verify_signature(message.to_array(),
                                                      sig2,
                                                      kp2.public_key.encode_point(False),
                                                      cryptography.ECCCurve.SECP256R1))

        # first do a check on regular data (meaning; check sig1 with pub_key1, sig2 with pub_key2)
        public_keys = [kp1.public_key.encode_point(False), kp2.public_key.encode_point(False)]
        signatures = [sig1, sig2]
        self.assertTrue(_check_multisig(engine, message, public_keys, signatures, cryptography.ECCCurve.SECP256R1))

        # same as previous, but supplying the keys out of order
        public_keys = [kp2.public_key.encode_point(False), kp1.public_key.encode_point(False)]
        signatures = [sig1, sig2]
        self.assertFalse(_check_multisig(engine, message, public_keys, signatures, cryptography.ECCCurve.SECP256R1))

        # now validate it will try all available public keys for a given signature (for 1-of-2, 3-of-5 like contracts)
        public_keys = [kp2.public_key.encode_point(False), kp1.public_key.encode_point(False)]
        signatures = [sig1]
        self.assertTrue(_check_multisig(engine, message, public_keys, signatures, cryptography.ECCCurve.SECP256R1))

        # test handling an exception caused by an invalid public key
        public_keys = [b'']
        signatures = [sig1]
        self.assertFalse(_check_multisig(engine, message, public_keys, signatures, cryptography.ECCCurve.SECP256R1))

    def test_check_multisig_with_ECDSA_Secp256r1_valid(self):
        engine = test_engine()
        message = vm.ByteStringStackItem(b'hello')
        kp1 = cryptography.KeyPair(private_key=b'\x01' * 32)
        sig1 = cryptography.sign(message.to_array(), kp1.private_key)

        signatures = vm.ArrayStackItem(engine.reference_counter)
        signatures.append(vm.ByteStringStackItem(sig1))

        public_keys = vm.ArrayStackItem(engine.reference_counter)
        public_keys.append(vm.ByteStringStackItem(kp1.public_key.encode_point(False)))

        sb = vm.ScriptBuilder()
        sb.emit_syscall(syscall_name_to_int("Neo.Crypto.CheckMultisigWithECDsaSecp256r1"))
        script = vm.Script(sb.to_array())
        engine.load_script(script)

        # setup the stack for the syscall
        engine.push(signatures)
        engine.push(public_keys)
        engine.push(message)
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        self.assertEqual(vm.BooleanStackItem(True), engine.result_stack.pop())

    def test_check_multisig_with_ECDSA_Secp256r1_invalid(self):
        engine = test_engine()
        message = vm.ByteStringStackItem(b'hello')
        bad_message = vm.ByteStringStackItem(b'badmessage')

        kp1 = cryptography.KeyPair(private_key=b'\x01' * 32)
        sig1 = cryptography.sign(message.to_array(), kp1.private_key)

        signatures = vm.ArrayStackItem(engine.reference_counter)
        signatures.append(vm.ByteStringStackItem(sig1))

        public_keys = vm.ArrayStackItem(engine.reference_counter)
        public_keys.append(vm.ByteStringStackItem(kp1.public_key.encode_point(False)))

        sb = vm.ScriptBuilder()
        sb.emit_syscall(syscall_name_to_int("Neo.Crypto.CheckMultisigWithECDsaSecp256r1"))
        script = vm.Script(sb.to_array())
        engine.load_script(script)

        # setup the stack for the syscall using a different message such that verification should fail
        engine.push(signatures)
        engine.push(public_keys)
        engine.push(bad_message)
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        self.assertEqual(vm.BooleanStackItem(False), engine.result_stack.pop())

    def test_check_multisig_with_ECDSA_Secp256k1(self):
        # values taken from test_verify_secp256k1()
        engine = test_engine()
        message = vm.ByteStringStackItem(b'hello')
        signature = vm.ByteStringStackItem(binascii.unhexlify(b'5331be791532d157df5b5620620d938bcb622ad02c81cfc184c460efdad18e695480d77440c511e9ad02ea30d773cb54e88f8cbb069644aefa283957085f38b5'))
        signatures = vm.ArrayStackItem(engine.reference_counter)
        signatures.append(signature)

        public_keys = vm.ArrayStackItem(engine.reference_counter)
        public_key = vm.ByteStringStackItem(binascii.unhexlify(b'03ea01cb94bdaf0cd1c01b159d474f9604f4af35a3e2196f6bdfdb33b2aa4961fa'))
        public_keys.append(public_key)

        sb = vm.ScriptBuilder()
        sb.emit_syscall(syscall_name_to_int("Neo.Crypto.CheckMultisigWithECDsaSecp256k1"))
        script = vm.Script(sb.to_array())
        engine.load_script(script)

        engine.push(signatures)
        engine.push(public_keys)
        engine.push(message)
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        self.assertEqual(vm.BooleanStackItem(True), engine.result_stack.pop())
