import unittest
import binascii
from unittest import mock
from collections import namedtuple
from neo3 import vm, contracts, storage, settings, cryptography
from neo3.core import types, to_script_hash, msgrouter
from neo3.network import message
from .utils import syscall_name_to_int, test_engine, test_block, TestIVerifiable


def test_native_contract(contract_hash: types.UInt160, operation: str, args=None):
    engine = test_engine(has_snapshot=True)
    block = test_block(0)
    # or we won't pass the native deploy call
    engine.snapshot.persisting_block = block

    sb = vm.ScriptBuilder()
    sb.emit_syscall(syscall_name_to_int("Neo.Native.Deploy"))

    # now call the actual native contract
    sb.emit_contract_call(contract_hash, operation)

    script = vm.Script(sb.to_array())
    engine.load_script(script)

    # storing the current script in a contract otherwise "System.Contract.Call" will fail its checks
    engine.snapshot.contracts.put(storage.ContractState(sb.to_array(), contracts.ContractManifest()))

    return engine


class NativeInteropTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        settings.network.standby_committee = ['02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765']
        settings.network.validators_count = 1

    @classmethod
    def tearDownClass(cls) -> None:
        settings.reset_settings_to_default()

    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_native_deploy_fail(self):
        engine = test_engine(has_snapshot=True)
        block = test_block(1)

        engine.snapshot.persisting_block = block
        with self.assertRaises(ValueError) as context:
            engine.invoke_syscall_by_name("Neo.Native.Deploy")
        self.assertEqual("Can only deploy native contracts in the genenis block", str(context.exception))

    def test_native_deploy_ok(self):
        engine = test_engine(has_snapshot=True)
        block = test_block(0)

        engine.snapshot.persisting_block = block
        engine.invoke_syscall_by_name("Neo.Native.Deploy")

        self.assertIn("Policy", contracts.NativeContract().registered_contract_names)
        self.assertEqual(contracts.PolicyContract(), contracts.NativeContract.get_contract("Policy"))

    def test_native_call(self):
        engine = test_engine(has_snapshot=True, default_script=True)
        block = test_block(0)

        engine.snapshot.persisting_block = block
        # need to create and store a contract matching the current_context.script
        # otherwise system.contract.call checks will fail
        engine.snapshot.contracts.put(storage.ContractState(b'\x40', contracts.ContractManifest()))
        engine.invoke_syscall_by_name("Neo.Native.Deploy")
        engine.push(vm.ArrayStackItem(engine.reference_counter))  # empty array for no arguments
        engine.push(vm.ByteStringStackItem(b'getMaxTransactionsPerBlock'))
        policy_contract_hash = vm.ByteStringStackItem(contracts.PolicyContract().script_hash.to_array())
        engine.push(policy_contract_hash)
        engine.invoke_syscall_by_name("System.Contract.Call")


class TestNativeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        settings.network.standby_committee = ['02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765']
        settings.network.validators_count = 1
        cls.validator_public_key = cryptography.ECPoint.deserialize_from_bytes(
            binascii.unhexlify(settings.network.standby_committee[0])
        )
        cls.validator_account = to_script_hash(
            contracts.Contract.create_multisig_redeemscript(1, [cls.validator_public_key]))

    @classmethod
    def tearDownClass(cls) -> None:
        settings.reset_settings_to_default()

    def test_requesting_non_existing_contract(self):
        with self.assertRaises(ValueError) as context:
            contracts.NativeContract.get_contract("bogus_contract")
        self.assertEqual("There is no native contract with name: bogus_contract", str(context.exception))

    def test_parameter_types_matched_parameter_names(self):
        class NativeTestContract(contracts.NativeContract):
            def init(self):
                self._register_contract_method(None, None, 0, None, parameter_types=[], parameter_names=["error"])

        with self.assertRaises(ValueError) as context:
            NativeTestContract()
        self.assertEqual("Parameter types count must match parameter names count! 0!=1", str(context.exception))

    def test_invoke_not_allowed_through_native_syscall(self):
        engine = test_engine(has_snapshot=True)
        engine.snapshot.persisting_block = test_block(0)
        engine.invoke_syscall_by_name("Neo.Native.Deploy")
        engine.push(vm.ByteStringStackItem(b'Policy'))

        with self.assertRaises(SystemError) as context:
            engine.invoke_syscall_by_name("Neo.Native.Call")
        self.assertEqual("It is not allowed to use Neo.Native.Call directly, use System.Contract.Call", str(context.exception))

    def test_various(self):
        native = contracts.NativeContract()
        known_contracts = native.registered_contracts
        self.assertIn(contracts.GasToken(), known_contracts)
        self.assertIn(contracts.NeoToken(), known_contracts)
        self.assertIn(contracts.PolicyContract(), known_contracts)


class TestPolicyContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        settings.network.standby_committee = ['02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765']
        settings.network.validators_count = 1

    @classmethod
    def tearDownClass(cls) -> None:
        settings.reset_settings_to_default()

    def test_basics(self):
        policy = contracts.PolicyContract()
        self.assertEqual(-3, policy.id)
        self.assertEqual("Policy", contracts.PolicyContract.service_name())
        self.assertEqual([], policy.supported_standards())

    def test_policy_defaul_get_max_tx_per_block(self):
        engine = test_native_contract(contracts.PolicyContract().script_hash, "getMaxTransactionsPerBlock")
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertEqual(vm.IntegerStackItem(512), item)

    def test_policy_default_get_max_block_size(self):
        engine = test_native_contract(contracts.PolicyContract().script_hash, "getMaxBlockSize")
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertEqual(vm.IntegerStackItem(262144), item)

    def test_policy_default_get_max_block_system_fee(self):
        engine = test_native_contract(contracts.PolicyContract().script_hash, "getMaxBlockSystemFee")
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertEqual(vm.IntegerStackItem(900000000000), item)

    def test_policy_default_get_fee_per_byte(self):
        engine = test_native_contract(contracts.PolicyContract().script_hash, "getFeePerByte")
        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(1, len(engine.result_stack))
        item = engine.result_stack.pop()
        self.assertEqual(vm.IntegerStackItem(1000), item)

    def test_policy_block_account_and_is_blocked(self):
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        # set or we won't pass the native deploy call
        engine.snapshot.persisting_block = block

        sb = vm.ScriptBuilder()
        sb.emit_syscall(syscall_name_to_int("Neo.Native.Deploy"))

        # set or we won't pass the check_comittee() in the policy contract function implementations
        engine.script_container = TestIVerifiable()
        validator = settings.standby_committee[0]
        script_hash = to_script_hash(contracts.Contract.create_multisig_redeemscript(1, [validator]))
        engine.script_container.script_hashes = [script_hash]

        # first we setup the stack for calling `blockAccount`
        # push data to create a vm.Array holding 20 bytes for the UInt160 Account parameter of the _block_account function.
        sb.emit_push(b'\x11' * 20)
        sb.emit(vm.OpCode.PUSH1)
        sb.emit(vm.OpCode.PACK)
        sb.emit_push("blockAccount")
        sb.emit_push(contracts.PolicyContract().script_hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))

        # next we call `isBlocked`
        sb.emit_push(b'\x11' * 20)
        sb.emit(vm.OpCode.PUSH1)
        sb.emit(vm.OpCode.PACK)
        sb.emit_push("isBlocked")
        sb.emit_push(contracts.PolicyContract().script_hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))

        script = vm.Script(sb.to_array())
        engine.load_script(script)

        # storing the current script in a contract otherwise "System.Contract.Call" will fail its checks
        engine.snapshot.contracts.put(storage.ContractState(sb.to_array(), contracts.ContractManifest()))

        engine.execute()
        self.assertEqual(vm.VMState.HALT, engine.state)
        self.assertEqual(2, len(engine.result_stack))
        get_is_blocked_result = engine.result_stack.pop()
        set_blocked_account_result = engine.result_stack.pop()
        self.assertTrue(set_blocked_account_result.to_boolean())
        self.assertTrue(get_is_blocked_result.to_boolean())

    def test_policy_unblock_account(self):
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        engine.snapshot.persisting_block = block
        engine.invoke_syscall_by_name("Neo.Native.Deploy")

        # we must add a script_container with valid signature to pass the check_comittee() validation check
        # in the function itself
        engine.script_container = TestIVerifiable()
        validator = settings.standby_committee[0]
        script_hash = to_script_hash(contracts.Contract.create_multisig_redeemscript(1, [validator]))
        engine.script_container.script_hashes = [script_hash]

        policy = contracts.PolicyContract()
        account_not_found = types.UInt160(data=b'\x11' * 20)
        account = types.UInt160.zero()
        self.assertTrue(policy._block_account(engine, account))
        self.assertFalse(policy._unblock_account(engine, account_not_found))
        self.assertTrue(policy._unblock_account(engine, account))
        storage_key = storage.StorageKey(policy.script_hash, policy._PREFIX_BLOCKED_ACCOUNT + account.to_array())
        storage_item = engine.snapshot.storages.try_get(storage_key)
        self.assertIsNone(storage_item)

    def test_policy_limit_setters(self):
        policy = contracts.PolicyContract()
        D = namedtuple('D', ['test_func', 'value', 'expected_return', 'storage_prefix'])
        testdata = [
            D(policy._set_max_block_size, message.Message.PAYLOAD_MAX_SIZE +1, ValueError, policy._PREFIX_MAX_BLOCK_SIZE),
            D(policy._set_max_block_size, 123, True, policy._PREFIX_MAX_BLOCK_SIZE),
            D(policy._set_max_transactions_per_block, 123, True, policy._PREFIX_MAX_TRANSACTIONS_PER_BLOCK),
            D(policy._set_max_block_system_fee, 123, False, policy._PREFIX_MAX_BLOCK_SYSTEM_FEE),
            # value is lower than magic number
            D(policy._set_max_block_system_fee, 5_000_000, True, policy._PREFIX_MAX_BLOCK_SYSTEM_FEE),
            D(policy._set_fee_per_byte, 123, True, policy._PREFIX_FEE_PER_BYTE)
        ]

        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        engine.snapshot.persisting_block = block
        engine.invoke_syscall_by_name("Neo.Native.Deploy")

        # set or we won't pass the check_comittee() in the policy contract function implementations
        engine.script_container = TestIVerifiable()
        validator = settings.standby_committee[0]
        script_hash = to_script_hash(contracts.Contract.create_multisig_redeemscript(1, [validator]))
        engine.script_container.script_hashes = [script_hash]

        for d in testdata:
            if isinstance(d.expected_return, type) and issubclass(d.expected_return, Exception):
                with self.assertRaises(d.expected_return):
                    d.test_func(engine, d.value)
            else:
                self.assertEqual(d.expected_return, d.test_func(engine, d.value))
                if d.expected_return is True:
                    item = engine.snapshot.storages.try_get(storage.StorageKey(policy.script_hash, d.storage_prefix))
                    self.assertIsNotNone(item)
                    self.assertEqual(d.value, int.from_bytes(item.value, 'little'))

    def test_policy_setters_fail_without_signatures(self):
        # cover set functions where check_committee fails
        policy = contracts.PolicyContract()
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        engine.snapshot.persisting_block = block
        engine.invoke_syscall_by_name("Neo.Native.Deploy")
        engine.script_container = TestIVerifiable()

        self.assertFalse(policy._set_max_block_size(engine, 0))
        self.assertFalse(policy._set_max_transactions_per_block(engine, 0))
        self.assertFalse(policy._set_max_block_system_fee(engine, 0))
        self.assertFalse(policy._set_fee_per_byte(engine, 0))
        self.assertFalse(policy._block_account(engine, None))
        self.assertFalse(policy._unblock_account(engine, None))


class Nep5TestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        settings.network.standby_committee = ['02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765']
        settings.network.validators_count = 1
        cls.validator_public_key = cryptography.ECPoint.deserialize_from_bytes(
            binascii.unhexlify(settings.network.standby_committee[0])
        )
        cls.validator_account = to_script_hash(
            contracts.Contract.create_multisig_redeemscript(1, [cls.validator_public_key]))

    @classmethod
    def tearDownClass(cls) -> None:
        settings.reset_settings_to_default()

    def test_token_standards(self):
        gas_standards = contracts.GasToken().supported_standards()
        neo_standards = contracts.NeoToken().supported_standards()
        self.assertEqual(["NEP-5"], gas_standards)
        self.assertEqual(["NEP-5"], neo_standards)

    def test_token_symbols(self):
        gas_symbol = contracts.GasToken().symbol()
        neo_symbol = contracts.NeoToken().symbol()
        self.assertEqual("gas", gas_symbol)
        self.assertEqual("neo", neo_symbol)

    def test_total_supply(self):
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        # set or we won't pass the native deploy call
        engine.snapshot.persisting_block = block

        engine.invoke_syscall_by_name("Neo.Native.Deploy")
        gas = contracts.GasToken()
        neo = contracts.NeoToken()
        self.assertEqual(30_000_000 * gas.factor, gas.total_supply(engine.snapshot))
        self.assertEqual(100_000_000, neo.total_supply(engine.snapshot))

    def test_burn(self):
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        # set or we won't pass the native deploy call
        engine.snapshot.persisting_block = block

        engine.invoke_syscall_by_name("Neo.Native.Deploy")

        gas = contracts.GasToken()

        with self.assertRaises(ValueError) as context:
            gas.burn(engine, self.validator_account, vm.BigInteger(-1))
        self.assertEqual("Can't burn a negative amount", str(context.exception))

        # burning nothing should not change the total supply
        default_gas = 30_000_000
        self.assertEqual(default_gas, gas.total_supply(engine.snapshot) / gas.factor)
        gas.burn(engine, self.validator_account, vm.BigInteger(0))
        self.assertEqual(default_gas, gas.total_supply(engine.snapshot) / gas.factor)

        # Note: our account holds the total supply
        with self.assertRaises(ValueError) as context:
            gas.burn(engine, self.validator_account, vm.BigInteger(default_gas + 1) * gas.factor)
        self.assertEqual("Insufficient balance. Requesting to burn 3000000100000000, available 3000000000000000",
                         str(context.exception))

        # burn a bit
        gas.burn(engine, self.validator_account, vm.BigInteger(10) * gas.factor)
        remaining_total_supply = int(gas.total_supply(engine.snapshot) / gas.factor)
        self.assertEqual(default_gas - 10, remaining_total_supply)

        # now burn it all
        gas.burn(engine, self.validator_account, vm.BigInteger(remaining_total_supply) * gas.factor)
        self.assertEqual(0, gas.total_supply(engine.snapshot) / gas.factor)

    def test_balance_of(self):
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        # set or we won't pass the native deploy call
        engine.snapshot.persisting_block = block

        engine.invoke_syscall_by_name("Neo.Native.Deploy")

        gas = contracts.GasToken()
        neo = contracts.NeoToken()

        deploy_expected_gas = 30_000_000
        deploy_expected_neo = 100_000_000
        self.assertEqual(deploy_expected_gas, gas.balance_of(engine.snapshot, self.validator_account) / gas.factor)
        self.assertEqual(deploy_expected_neo, neo.balance_of(engine.snapshot, self.validator_account))

        self.assertEqual(vm.BigInteger.zero(), gas.balance_of(engine.snapshot, types.UInt160.zero()))
        self.assertEqual(vm.BigInteger.zero(), neo.balance_of(engine.snapshot, types.UInt160.zero()))

    def test_on_persist(self):
        """
        OnPersist will do the following
        * burn the system and network fees for all transactions
        * mint the sum of network_fees for all transactions to the address of the consensus node that acted as primary
          speaker for the block
        """
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        # set or we won't pass the native deploy call
        engine.snapshot.persisting_block = block
        engine.invoke_syscall_by_name("Neo.Native.Deploy")

        gas = contracts.GasToken()

        # with the default Application trigger type we're not allowed to call on_persist
        with self.assertRaises(SystemError) as context:
            gas.on_persist(engine)
        self.assertEqual("Invalid operation", str(context.exception))

        # set correct trigger type or we fail super().on_persist()
        engine.trigger = contracts.TriggerType.ON_PERSIST
        # update the TX signer account to point to our validator or the token burn() (part of on persist)
        # will fail because it can't find an account with balance
        mock_signer = mock.MagicMock()
        mock_signer.account = self.validator_account
        engine.snapshot.persisting_block.transactions[0].signers = [mock_signer]
        # our consensus_data is not setup in a realistic way, so we have to correct for that here
        # or we fail to get the account of primary consensus node
        engine.snapshot.persisting_block.consensus_data.primary_index = settings.network.validators_count - 1

        gas.on_persist(engine)

        """
            Drop the below in a test in UT_NativeContract.cs and change ProtocolSettings.cs to
            * have a ValidatorsCount of 1 
            * and the StandbyCommittee should be: 02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765
            
            var snapshot = Blockchain.Singleton.GetSnapshot();
            snapshot.PersistingBlock = new Block() { Index = 1000 };
            var point = ECPoint.Parse("02158c4a4810fa2a6a12f7d33d835680429e1a68ae61161c5b3fbc98c7f1f17765", ECCurve.Secp256r1);
            var account = Contract.CreateMultiSigRedeemScript(1, new ECPoint[] {point}).ToScriptHash();
            var tx = TestUtils.GetTransaction(account);
            tx.SystemFee = 456;
            tx.NetworkFee = 789;
            snapshot.PersistingBlock.Transactions = new Transaction[] {tx};
            snapshot.PersistingBlock.ConsensusData = new ConsensusData { PrimaryIndex = 0};

            ApplicationEngine engine2 = ApplicationEngine.Create(TriggerType.System, tx, snapshot, 0);
            NativeContract.GAS.OnPersist(engine2);
            var key = new byte[] {0x14};
            var sk  = key.Concat(account.ToArray());
            var item = engine2.Snapshot.Storages.TryGet(new StorageKey {Id = NativeContract.GAS.Id, Key = sk.ToArray()});
            var state = item.GetInteroperable<AccountState>();
            Console.WriteLine($"account state {state.Balance}");

            var item2 = engine2.Snapshot.Storages.TryGet(new StorageKey {Id = NativeContract.GAS.Id, Key = new byte[]{11}});
            Console.WriteLine($"total supply {(BigInteger)item2}");

            var primary_account = Contract.CreateSignatureRedeemScript(point).ToScriptHash();
            var primary_sk = key.Concat(primary_account.ToArray());
            var primary_item = engine2.Snapshot.Storages.TryGet(new StorageKey {Id = NativeContract.GAS.Id, Key = primary_sk.ToArray()});
            var primary_state = primary_item.GetInteroperable<AccountState>();
            Console.WriteLine($"primary account state {primary_state.Balance}");
        """

        # * our validator prior to on_persist had a balance of 30_000_000
        # * after it should have been reduced by the network + system_fee's paid in the transaction
        sk_gas_supply = storage.StorageKey(gas.script_hash, gas._PREFIX_ACCOUNT + self.validator_account.to_array())
        si_supply = engine.snapshot.storages.try_get(sk_gas_supply)
        self.assertIsNotNone(si_supply)
        token_state = gas._state.deserialize_from_bytes(si_supply.value)
        total_fees = engine.snapshot.persisting_block.transactions[0].network_fee + \
                     engine.snapshot.persisting_block.transactions[0].system_fee
        expected = (30_000_000 * gas.factor) - total_fees
        self.assertEqual(expected, int(token_state.balance))

        # * total GAS supply was 30_000_000, should be reduced by the system_fee
        sk_total_supply = storage.StorageKey(gas.script_hash, gas._PREFIX_TOTAL_SUPPLY)
        si_total_supply = engine.snapshot.storages.try_get(sk_total_supply)
        self.assertIsNotNone(si_total_supply)
        expected = (30_000_000 * gas.factor) - engine.snapshot.persisting_block.transactions[0].system_fee
        self.assertEqual(expected, vm.BigInteger(si_total_supply.value))

        # * the persisting block contains exactly 1 transaction
        # * after on_persist the account our primary validator should have been credited with the transaction's
        #   network_fee
        primary_validator = to_script_hash(contracts.Contract.create_signature_redeemscript(self.validator_public_key))
        sk_gas_supply = storage.StorageKey(gas.script_hash, gas._PREFIX_ACCOUNT + primary_validator.to_array())
        si_supply = engine.snapshot.storages.try_get(sk_gas_supply)
        self.assertIsNotNone(si_supply)
        token_state = gas._state.deserialize_from_bytes(si_supply.value)
        expected = engine.snapshot.persisting_block.transactions[0].network_fee
        self.assertEqual(expected, int(token_state.balance))

    def transfer_helper(self, contract: contracts.NativeContract,
                        from_account: types.UInt160,
                        to_account: types.UInt160,
                        amount: vm.BigInteger):
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        # set or we won't pass the native deploy call
        engine.snapshot.persisting_block = block
        engine.invoke_syscall_by_name("Neo.Native.Deploy")
        engine.invocation_stack.pop()  # we no longer need the default script
        engine.script_container = TestIVerifiable()
        engine.script_container.script_hashes = [from_account]

        sb = vm.ScriptBuilder()
        sb.emit_push(amount)
        sb.emit_push(to_account.to_array())
        sb.emit_push(from_account.to_array())
        sb.emit_push(3)
        sb.emit(vm.OpCode.PACK)
        sb.emit_push(b'transfer')
        sb.emit_push(contract.script_hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))
        engine.load_script(vm.Script(sb.to_array()))

        engine.snapshot.contracts.put(storage.ContractState(sb.to_array(), contracts.ContractManifest()))
        return engine

    def test_transfer_negative_amount(self):
        engine = test_engine(has_snapshot=True, default_script=False)
        engine.load_script(vm.Script(contracts.GasToken().script))
        block = test_block(0)
        # set or we won't pass the native deploy call
        engine.snapshot.persisting_block = block
        engine.invoke_syscall_by_name("Neo.Native.Deploy")

        gas = contracts.GasToken()

        with self.assertRaises(ValueError) as context:
            gas.transfer(engine, types.UInt160.zero(), types.UInt160.zero(), vm.BigInteger(-1))
        self.assertEqual("Can't transfer a negative amount", str(context.exception))

    def test_transfer_fail_no_permission(self):
        """
        Test to transfer tokens from a source account that is not owned by the smart contract that is asking for the transfer.
        We do not add a witness that approves that we can transfer from the source account, thus it should fail
        Returns:

        """
        gas = contracts.GasToken()

        engine = self.transfer_helper(gas, types.UInt160.zero(), types.UInt160.zero(), vm.BigInteger(1))
        engine.script_container.script_hashes = []  # ensure checkwitness returns False
        engine.execute()
        self.assertEqual(1, len(engine.result_stack))
        result = engine.result_stack.pop()
        self.assertFalse(result)

    def test_to_account_not_payable(self):
        gas = contracts.GasToken()
        state = storage.ContractState(b'\x00', contracts.ContractManifest())

        engine = self.transfer_helper(gas, types.UInt160.zero(), state.script_hash(), vm.BigInteger(1))
        # default manifest is not payable
        engine.snapshot.contracts.put(state)
        engine.execute()
        self.assertEqual(1, len(engine.result_stack))
        result = engine.result_stack.pop()
        self.assertFalse(result)

    def test_transfer_from_empty_account(self):
        gas = contracts.GasToken()
        manifest = contracts.ContractManifest()
        state = storage.ContractState(b'\x00', manifest)

        engine = self.transfer_helper(gas, types.UInt160.zero(), state.script_hash(), vm.BigInteger(1))
        engine.snapshot.contracts.put(state)
        engine.execute()
        self.assertEqual(1, len(engine.result_stack))
        result = engine.result_stack.pop()
        self.assertFalse(result)

    def test_transfer_zero_amount(self):
        gas = contracts.GasToken()
        account_from = types.UInt160(b'\x01' * 20)
        storage_key_from = storage.StorageKey(gas.script_hash, gas._PREFIX_ACCOUNT + account_from.to_array())
        account_state = gas._state()
        account_state.balance = vm.BigInteger(123)
        storage_item_from = storage.StorageItem(account_state.to_array())

        manifest = contracts.ContractManifest()
        state_to = storage.ContractState(b'\x00', manifest)
        account_to = state_to.script_hash()
        amount = vm.BigInteger(0)

        engine = self.transfer_helper(gas, account_from, account_to, amount)
        # ensure the destination contract exists
        engine.snapshot.contracts.put(state_to)
        # ensure the source account has balance
        engine.snapshot.storages.put(storage_key_from, storage_item_from)

        transfer_event = ()

        def notify_listener(contract_script_hash, event, state):
            nonlocal transfer_event
            transfer_event = (contract_script_hash, event, state)

        msgrouter.interop_notify += notify_listener
        engine.execute()
        self.assertEqual(1, len(engine.result_stack))
        result = engine.result_stack.pop()
        self.assertTrue(result)
        self.assertEqual(gas.script_hash, transfer_event[0])
        self.assertEqual("Transfer", transfer_event[1])
        state_items = list(transfer_event[2])
        self.assertEqual(account_from, types.UInt160(state_items[0].to_array()))
        self.assertEqual(account_to, types.UInt160(state_items[1].to_array()))
        self.assertEqual(amount, state_items[2].to_biginteger())

    def test_transfer_more_than_balance(self):
        gas = contracts.GasToken()
        account_from = types.UInt160.zero()
        storage_key_from = storage.StorageKey(gas.script_hash, gas._PREFIX_ACCOUNT + account_from.to_array())
        account_state = gas._state()
        account_state.balance = vm.BigInteger(123)
        storage_item_from = storage.StorageItem(account_state.to_array())

        manifest = contracts.ContractManifest()
        state_to = storage.ContractState(b'\x00', manifest)
        account_to = state_to.script_hash()
        amount = account_state.balance + 1

        engine = self.transfer_helper(gas, account_from, account_to, amount)
        # ensure the destination contract exists
        engine.snapshot.contracts.put(state_to)
        # ensure the source account has balance
        engine.snapshot.storages.put(storage_key_from, storage_item_from)
        engine.execute()
        self.assertEqual(1, len(engine.result_stack))
        result = engine.result_stack.pop()
        self.assertFalse(result)

    def test_transfer_to_self(self):
        gas = contracts.GasToken()

        manifest = contracts.ContractManifest()
        state_to = storage.ContractState(b'\x00' * 20, manifest)
        account = state_to.script_hash()

        storage_key_from = storage.StorageKey(gas.script_hash, gas._PREFIX_ACCOUNT + account.to_array())
        account_state = gas._state()
        account_state.balance = vm.BigInteger(123)
        storage_item_from = storage.StorageItem(account_state.to_array())

        amount = account_state.balance

        engine = self.transfer_helper(gas, account, account, amount)
        # ensure the destination contract exists
        engine.snapshot.contracts.put(state_to)
        # ensure the source account has balance
        engine.snapshot.storages.put(storage_key_from, storage_item_from)

        transfer_event = ()

        def notify_listener(contract_script_hash, event, state):
            nonlocal transfer_event
            transfer_event = (contract_script_hash, event, state)

        msgrouter.interop_notify += notify_listener
        engine.execute()
        self.assertEqual(1, len(engine.result_stack))
        result = engine.result_stack.pop()
        self.assertTrue(result)
        self.assertEqual(gas.script_hash, transfer_event[0])
        self.assertEqual("Transfer", transfer_event[1])
        state_items = list(transfer_event[2])
        self.assertEqual(account, types.UInt160(state_items[0].to_array()))
        self.assertEqual(account, types.UInt160(state_items[1].to_array()))
        self.assertEqual(amount, state_items[2].to_biginteger())

    def test_transfer_full_balance(self):
        gas = contracts.GasToken()

        manifest = contracts.ContractManifest()
        state_to = storage.ContractState(b'\x00' * 20, manifest)
        account_to = state_to.script_hash()

        account_from = types.UInt160(b'\x01' * 20)
        storage_key_from = storage.StorageKey(gas.script_hash, gas._PREFIX_ACCOUNT + account_from.to_array())
        account_from_state = gas._state()
        account_from_state.balance = vm.BigInteger(123)
        storage_item_from = storage.StorageItem(account_from_state.to_array())

        amount = account_from_state.balance

        engine = self.transfer_helper(gas, account_from, account_to, amount)
        # ensure the destination contract exists
        engine.snapshot.contracts.put(state_to)
        # ensure the source account has balance
        engine.snapshot.storages.put(storage_key_from, storage_item_from)

        transfer_event = ()

        def notify_listener(contract_script_hash, event, state):
            nonlocal transfer_event
            transfer_event = (contract_script_hash, event, state)

        msgrouter.interop_notify += notify_listener
        engine.execute()
        self.assertEqual(1, len(engine.result_stack))
        result = engine.result_stack.pop()
        self.assertTrue(result)
        self.assertEqual(gas.script_hash, transfer_event[0])
        self.assertEqual("Transfer", transfer_event[1])
        state_items = list(transfer_event[2])
        self.assertEqual(account_from, types.UInt160(state_items[0].to_array()))
        self.assertEqual(account_to, types.UInt160(state_items[1].to_array()))
        self.assertEqual(amount, state_items[2].to_biginteger())

        # test that the source account is no longer present in storage as the balance is zero
        self.assertIsNone(engine.snapshot.storages.try_get(storage_key_from))

    def test_transfer_partial_balance_to_account_with_balance(self):
        gas = contracts.GasToken()

        manifest = contracts.ContractManifest()
        state_to = storage.ContractState(b'\x00' * 20, manifest)
        account_to = state_to.script_hash()
        storage_key_to = storage.StorageKey(gas.script_hash, gas._PREFIX_ACCOUNT + account_to.to_array())
        account_to_state = gas._state()
        account_to_state.balance = vm.BigInteger(100)
        storage_item_to = storage.StorageItem(account_to_state.to_array())

        account_from = types.UInt160(b'\x01' * 20)
        storage_key_from = storage.StorageKey(gas.script_hash, gas._PREFIX_ACCOUNT + account_from.to_array())
        account_from_state = gas._state()
        account_from_state.balance = vm.BigInteger(123)
        storage_item_from = storage.StorageItem(account_from_state.to_array())

        amount = vm.BigInteger(50)

        engine = self.transfer_helper(gas, account_from, account_to, amount)
        # ensure the destination contract exists
        engine.snapshot.contracts.put(state_to)
        # ensure the source and destination account have balances
        engine.snapshot.storages.put(storage_key_from, storage_item_from)
        engine.snapshot.storages.put(storage_key_to, storage_item_to)

        transfer_event = ()

        def notify_listener(contract_script_hash, event, state):
            nonlocal transfer_event
            transfer_event = (contract_script_hash, event, state)

        msgrouter.interop_notify += notify_listener
        engine.execute()
        self.assertEqual(1, len(engine.result_stack))
        result = engine.result_stack.pop()
        self.assertTrue(result)
        self.assertEqual(gas.script_hash, transfer_event[0])
        self.assertEqual("Transfer", transfer_event[1])
        state_items = list(transfer_event[2])
        self.assertEqual(account_from, types.UInt160(state_items[0].to_array()))
        self.assertEqual(account_to, types.UInt160(state_items[1].to_array()))
        self.assertEqual(amount, state_items[2].to_biginteger())

        # validate from account is deducted by `amount`
        new_storage_account_from = engine.snapshot.storages.get(storage_key_from)
        new_account_state_from = gas._state.deserialize_from_bytes(new_storage_account_from.value)
        self.assertEqual(account_from_state.balance - amount, new_account_state_from.balance)

        # validate to account is credited with `amount`
        new_storage_account_to = engine.snapshot.storages.get(storage_key_to)
        new_account_state_to = gas._state.deserialize_from_bytes(new_storage_account_to.value)
        self.assertEqual(account_to_state.balance + amount, new_account_state_to.balance)

    def test_negative_mint(self):
        gas = contracts.GasToken()
        with self.assertRaises(ValueError) as context:
            gas.mint(None, None, vm.BigInteger(-1))
        self.assertEqual("Can't mint a negative amount", str(context.exception))

