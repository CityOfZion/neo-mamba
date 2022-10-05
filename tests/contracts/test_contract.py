import unittest
import binascii
from neo3 import vm
from neo3.contracts import utils, contract
from neo3.core import cryptography, types


class ContractTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_create_signature_contract(self):
        """
        var priv_key1 = new byte[]
        {
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
        };
        var kp1 = new KeyPair(priv_key1);
        var c = Contract.CreateSignatureContract(kp1.PublicKey);
        Console.WriteLine(c.Script.ToHexString());
        """
        expected = binascii.unhexlify(
            b"0c21026ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca164156e7b327"
        )
        keypair = cryptography.KeyPair(private_key=b"\x01" * 32)
        contract_ = contract.Contract.create_signature_contract(keypair.public_key)
        self.assertEqual(expected, contract_.script)

    def test_create_multisignature_contract(self):
        """
        var priv_key1 = new byte[]
        {
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
        };
        var priv_key2 = new byte[]
        {
            0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
            0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
            0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
            0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
        };
        var kp1 = new KeyPair(priv_key1);
        var kp2 = new KeyPair(priv_key2);
        var c = Contract.CreateMultiSigContract(1, new ECPoint[] {kp1.PublicKey, kp2.PublicKey});
        Console.WriteLine(c.Script.ToHexString());
        Console.WriteLine(c.ScriptHash.ToArray().ToHexString());
        """
        expected_script = binascii.unhexlify(
            b"110c2102550f471003f3df97c3df506ac797f6721fb1a1fb7b8f6f83d224498a65c88e240c21026ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca1612419ed0dc3a"
        )
        expected_script_hash = types.UInt160(
            binascii.unhexlify(b"a72d98260b3dd7d7dd4f733490b9c16b5c352644")
        )
        keypair1 = cryptography.KeyPair(private_key=b"\x01" * 32)
        keypair2 = cryptography.KeyPair(private_key=b"\x02" * 32)
        contract_ = contract.Contract.create_multisig_contract(
            1, [keypair1.public_key, keypair2.public_key]
        )
        self.assertEqual(expected_script, contract_.script)
        self.assertEqual(str(expected_script_hash), str(contract_.script_hash))

    def test_create_multisignature_redeemscript_invalid_arguments(self):
        with self.assertRaises(ValueError) as context:
            utils.create_multisig_redeemscript(0, [])
        self.assertEqual(
            "Minimum required signature count is 1, specified 0.",
            str(context.exception),
        )

        with self.assertRaises(ValueError) as context:
            utils.create_multisig_redeemscript(1, [])
        self.assertEqual(
            "Invalid public key count. Minimum required signatures is bigger than supplied public keys count.",
            str(context.exception),
        )

        with self.assertRaises(ValueError) as context:
            utils.create_multisig_redeemscript(1, [object() for _ in range(0, 1025)])
        self.assertEqual(
            "Supplied public key count (1025) exceeds maximum of 1024.",
            str(context.exception),
        )

    def test_is_signature_contract(self):
        """
        A valid signature contract script looks as follows
        - PUSHDATA1 (0xC)
        - LEN PUBLIC KEY (33)
        - PUBLIC KEY data
        - SYSCALL (0x41)
        - "System.Crypto.CheckSig" identifier
        """

        incorrect_script_len = b"\x01" * 10
        self.assertFalse(utils.is_signature_contract(incorrect_script_len))

        # first byte should be PUSHDATA1 (0xC)
        incorrect_script_start_byte = b"\x01" * 40
        self.assertFalse(utils.is_signature_contract(incorrect_script_start_byte))

        # second byte should be 33
        incorrect_second_byte = bytearray(b"\x01" * 40)
        incorrect_second_byte[0] = int(vm.OpCode.PUSHDATA1)
        self.assertFalse(utils.is_signature_contract(incorrect_second_byte))

        # index 35 should be SYSCALL
        incorrect_idx_35 = bytearray([0xC, 33]) + b"\01" * 38
        incorrect_idx_35[35] = int(vm.OpCode.PUSHNULL)
        self.assertFalse(
            utils.is_signature_contract(incorrect_idx_35)
        )  # index 35 should be SYSCALL

        # the last 4 bytes should be the "System.Crypto.CheckSig" SYSCALL
        incorrect_syscall_number = bytearray([0xC, 33]) + b"\01" * 38
        incorrect_syscall_number[35] = int(vm.OpCode.SYSCALL)
        self.assertFalse(utils.is_signature_contract(incorrect_syscall_number))

        # and finally a contract that matches the correct format
        correct = bytearray([0xC, 33]) + b"\01" * 38
        correct[35] = int(vm.OpCode.SYSCALL)
        correct[36:40] = vm.Syscalls.SYSTEM_CRYPTO_CHECK_STANDARD_ACCOUNT.to_array()
        self.assertTrue(utils.is_signature_contract(correct))

    def test_is_multisig_contract_too_short(self):
        script_too_short = b"\x00"
        self.assertFalse(utils.is_multisig_contract(script_too_short))

    def test_is_multisig_contract_invalid_public_key(self):
        """
        A valid multisignature contract looks as follows
        - signature length (variable int)
        - number of public keys times
            - PUSHDATA1
            - public key len (0x33)
            - public key data
        """
        script = bytearray([int(vm.OpCode.PUSHINT8)])
        # signature count
        script += b"\x02"
        # public key 1
        script += bytearray([int(vm.OpCode.PUSHDATA1)])
        script += bytearray([33])
        script += bytes.fromhex(
            "03a60c1deaf147b10691c344c76e5f3dac83b555fdd5a3f8d9e2f623b3d1af8df6"
        )
        # public key 2, but the key data is too short
        script += bytearray([int(vm.OpCode.PUSHDATA1)])
        script += b"\xFF" * 10
        self.assertFalse(utils.is_multisig_contract(script))

    def test_is_multisig_contract_invalid_public_key_2(self):
        script = bytearray([int(vm.OpCode.PUSHINT8)])
        # signature count
        script += b"\x02"
        # public key 1
        script += bytearray([int(vm.OpCode.PUSHDATA1)])
        script += bytearray([33])
        script += bytes.fromhex(
            "03a60c1deaf147b10691c344c76e5f3dac83b555fdd5a3f8d9e2f623b3d1af8df6"
        )
        # public key 2, but the key data is too short
        script += bytearray([int(vm.OpCode.PUSHDATA1)])
        # public key 2 length should be 33, but we make it 00
        script += b"\x00"
        script += bytes.fromhex(
            "03a60c1deaf147b10691c344c76e5f3dac83b555fdd5a3f8d9e2f623b3d1af8df6"
        )

        script += bytearray([int(vm.OpCode.PUSHINT8)])
        self.assertFalse(utils.is_multisig_contract(script))
        return script

    def test_is_multisig_contract_public_key_count_lower_than_signature_count(self):
        script = bytearray([int(vm.OpCode.PUSHINT8)])
        # signature count
        script += b"\x02"
        # make sure it meets the minimum length
        script += b"\x00" * 41
        # assert that 0 public keys does not meet the signature count of 2
        self.assertFalse(utils.is_multisig_contract(script))

    def test_public_key_count_mismatch(self):
        # the specified public key count should match the number of public keys found
        # we can re-use the script from a previous test, where we only have to fix the length field
        # for public key 2
        script = self.test_is_multisig_contract_invalid_public_key_2()
        script[-35] = 33
        self.assertFalse(utils.is_multisig_contract(script))

    def test_script_invalid_tail(self):
        # same as previous test, we re-use and fix the length
        script = self.test_is_multisig_contract_invalid_public_key_2()
        script[-35] = 33
        # now we make sure the public key count matches
        script[-1] = int(vm.OpCode.PUSHINT8)
        script += b"\x02"
        # and assert we don't have enough data left for the remainder of the checks
        self.assertFalse(utils.is_multisig_contract(script))

        # now we extend with 5 bytes to give enough data
        script += b"\x00" * 5
        # the first byte should be a SYSCALL, but it isn't
        self.assertFalse(utils.is_multisig_contract(script))

        # we fix the SYSCALL byte
        script[-5] = int(vm.OpCode.SYSCALL)
        # finally test the last 4 bytes should be "System.Crypto.CheckSig" syscall number
        self.assertFalse(utils.is_multisig_contract(script))

    def test_is_multsig_contract_ok(self):
        keypair = cryptography.KeyPair(private_key=b"\x01" * 32)
        contract_ = contract.Contract.create_multisig_contract(1, [keypair.public_key])
        self.assertTrue(utils.is_multisig_contract(contract_.script))

    def test_is_multisig_contract_256_pubkeys(self):
        # test handling of a large number of public keys
        # from 256 signatures and above the count is encoded in 2 bytes
        # for this test we manually encoded a length of 2 into 2 bytes
        script = bytearray([int(vm.OpCode.PUSHINT16), 2, 0])

        # add fake public keys
        for _ in range(0, 2):
            script += bytearray([int(vm.OpCode.PUSHDATA1)])
            script += bytearray([33])
            script += bytes.fromhex(
                "03a60c1deaf147b10691c344c76e5f3dac83b555fdd5a3f8d9e2f623b3d1af8df6"
            )

        # and now mismatch the public key count value we say is present (0 here)
        script += bytearray([int(vm.OpCode.PUSHINT16), 0, 0])
        self.assertFalse(utils.is_multisig_contract(script))

        # now we correct the public key count in the script and make it valid by adding the expected tail
        script[-2] = 2
        script += bytearray([int(vm.OpCode.SYSCALL)])
        script += vm.Syscalls.SYSTEM_CRYPTO_CHECK_MULTI_SIGNATURE_ACCOUNT.to_array()
        self.assertTrue(utils.is_multisig_contract(script))

    def test_is_multsig_contract_invalid_pubkey_count(self):
        # this is another test where we check for a mismatch between processed public keys and the claimed present
        # amount but this time for a signature count between push0 <= cnt <= PUSH16
        # we re-use the standard create_multisignature_account call
        keypair = cryptography.KeyPair(private_key=b"\x01" * 32)
        contract_ = contract.Contract.create_multisig_contract(1, [keypair.public_key])
        # and modify the claimed public key length from 1 to 255
        data = bytearray(contract_.script)
        data[-6] = int(vm.OpCode.PUSH16) - 1
        self.assertFalse(utils.is_multisig_contract(data))

        # and finally we try it again but this time the public key length is in an invalid range
        data[-6] = int(vm.OpCode.PUSH16) + 1
        self.assertFalse(utils.is_multisig_contract(data))

    def test_is_multisig_contract_invalid_sig_counts(self):
        # no valid signature length byte
        script = b"\xFF" * 43
        self.assertFalse(utils.is_multisig_contract(script))

        # more than 1024 signatures
        sig_cnt = 1025
        script = b"\x01" + sig_cnt.to_bytes(2, "little") + b"\x01" * 40
        self.assertFalse(utils.is_multisig_contract(script))
