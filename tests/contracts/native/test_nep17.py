import unittest
from unittest import mock
import binascii
from neo3 import settings, contracts, storage, vm
from neo3.core import cryptography, types, syscall_name_to_int, to_script_hash, msgrouter
from tests.contracts.interop.utils import test_engine, test_block, TestIVerifiable, contract_hash


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

    def test_token_symbols(self):
        gas_symbol = contracts.GasToken().symbol()
        neo_symbol = contracts.NeoToken().symbol()
        self.assertEqual("GAS", gas_symbol)
        self.assertEqual("NEO", neo_symbol)

    def test_total_supply(self):
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        # set or we won't pass the native deploy call
        engine.snapshot.persisting_block = block

        gas = contracts.GasToken()
        neo = contracts.NeoToken()
        # this is now the initial stored value + the result of the post_persist event (=committee reward added)
        expected_total_gas_supply = vm.BigInteger(3000000050000000)
        self.assertEqual(expected_total_gas_supply, gas.total_supply(engine.snapshot))
        self.assertEqual(100_000_000, neo.total_supply(engine.snapshot))

    def test_burn(self):
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        # set or we won't pass the native deploy call
        engine.snapshot.persisting_block = block

        gas = contracts.GasToken()

        with self.assertRaises(ValueError) as context:
            gas.burn(engine, self.validator_account, vm.BigInteger(-1))
        self.assertEqual("Can't burn a negative amount", str(context.exception))

        default_gas = 30_000_000
        self.assertEqual(default_gas, gas.balance_of(engine.snapshot, self.validator_account) / gas.factor)
        gas.burn(engine, self.validator_account, vm.BigInteger(0))
        self.assertEqual(default_gas, gas.balance_of(engine.snapshot, self.validator_account) / gas.factor)

        with self.assertRaises(ValueError) as context:
            gas.burn(engine, self.validator_account, vm.BigInteger(default_gas + 1) * gas.factor)
        self.assertEqual("Insufficient balance. Requesting to burn 3000000100000000, available 3000000000000000",
                         str(context.exception))

        # burn a bit
        gas.burn(engine, self.validator_account, vm.BigInteger(10) * gas.factor)
        remaining_balance = int(gas.balance_of(engine.snapshot, self.validator_account) / gas.factor)
        self.assertEqual(default_gas - 10, remaining_balance)

        # now burn it all
        gas.burn(engine, self.validator_account, vm.BigInteger(remaining_balance) * gas.factor)
        self.assertEqual(0, gas.balance_of(engine.snapshot, self.validator_account) / gas.factor)

    def test_balance_of(self):
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        # set or we won't pass the native deploy call
        engine.snapshot.persisting_block = block

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

        gas = contracts.GasToken()

        # update the TX signer account to point to our validator or the token burn() (part of on persist)
        # will fail because it can't find an account with balance
        mock_signer = mock.MagicMock()
        mock_signer.account = self.validator_account
        engine.snapshot.persisting_block.transactions[0].signers = [mock_signer]
        # our consensus_data is not setup in a realistic way, so we have to correct for that here
        # or we fail to get the account of primary consensus node
        engine.snapshot.persisting_block.header.primary_index = settings.network.validators_count - 1

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
        sk_gas_supply = gas.key_account + self.validator_account
        si_supply = engine.snapshot.storages.try_get(sk_gas_supply)
        self.assertIsNotNone(si_supply)
        token_state = gas._state.deserialize_from_bytes(si_supply.value)
        total_fees = engine.snapshot.persisting_block.transactions[0].network_fee + \
                     engine.snapshot.persisting_block.transactions[0].system_fee
        expected = (30_000_000 * gas.factor) - total_fees
        self.assertEqual(expected, int(token_state.balance))

        # * total GAS supply was 30_000_000 + 0.5 for committee reward, should be reduced by the system_fee
        sk_total_supply = gas.key_total_supply
        si_total_supply = engine.snapshot.storages.try_get(sk_total_supply)
        self.assertIsNotNone(si_total_supply)
        committee_reward = vm.BigInteger(50000000)
        expected = ((30_000_000 * gas.factor) + committee_reward) - engine.snapshot.persisting_block.transactions[0].system_fee
        self.assertEqual(expected, vm.BigInteger(si_total_supply.value))

        # * the persisting block contains exactly 1 transaction
        # * after on_persist the account our primary validator should have been credited with the transaction's
        #   network_fee
        primary_validator = to_script_hash(contracts.Contract.create_signature_redeemscript(self.validator_public_key))
        sk_gas_supply = gas.key_account + primary_validator
        si_supply = engine.snapshot.storages.try_get(sk_gas_supply)
        self.assertIsNotNone(si_supply)
        token_state = gas._state.deserialize_from_bytes(si_supply.value)
        expected = engine.snapshot.persisting_block.transactions[0].network_fee + committee_reward
        self.assertEqual(expected, int(token_state.balance))

    def transfer_helper(self, contract: contracts.NativeContract,
                        from_account: types.UInt160,
                        to_account: types.UInt160,
                        amount: vm.BigInteger):
        engine = test_engine(has_snapshot=True)
        block = test_block(0)
        # set or we won't pass the native deploy call
        engine.snapshot.persisting_block = block
        engine.invocation_stack.pop()  # we no longer need the default script
        engine.script_container = TestIVerifiable()
        engine.script_container.script_hashes = [from_account]

        sb = vm.ScriptBuilder()
        sb.emit(vm.OpCode.PUSHNULL)
        sb.emit_push(amount)
        sb.emit_push(to_account.to_array())
        sb.emit_push(from_account.to_array())
        sb.emit_push(4)
        sb.emit(vm.OpCode.PACK)
        sb.emit_push(15)  # callflags
        sb.emit_push(b'transfer')
        sb.emit_push(contract.hash.to_array())
        sb.emit_syscall(syscall_name_to_int("System.Contract.Call"))
        engine.load_script(vm.Script(sb.to_array()))

        nef = contracts.NEF(script=sb.to_array())
        manifest = contracts.ContractManifest("test_contract")
        contract_state = contracts.ContractState(1, nef, manifest, 0, contract_hash(from_account, nef.checksum, manifest.name))
        engine.snapshot.contracts.put(contract_state)
        return engine

    def test_transfer_negative_amount(self):
        engine = test_engine(has_snapshot=True, default_script=False)
        engine.load_script(vm.Script(contracts.GasToken().script))
        block = test_block(0)
        # set or we won't pass the native deploy call
        engine.snapshot.persisting_block = block

        gas = contracts.GasToken()

        with self.assertRaises(ValueError) as context:
            gas.transfer(engine, types.UInt160.zero(), types.UInt160.zero(), vm.BigInteger(-1), vm.NullStackItem())
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

    def test_transfer_from_empty_account(self):
        gas = contracts.GasToken()
        manifest = contracts.ContractManifest("test_contract2")
        nef = contracts.NEF(script=b'\x40')
        state = contracts.ContractState(2, nef, manifest, 0, contract_hash(types.UInt160.zero(), nef.checksum, manifest.name))

        engine = self.transfer_helper(gas, types.UInt160.zero(), state.hash, vm.BigInteger(1))
        engine.snapshot.contracts.put(state)
        engine.execute()
        self.assertEqual(1, len(engine.result_stack))
        result = engine.result_stack.pop()
        self.assertFalse(result)

    def test_transfer_zero_amount(self):
        gas = contracts.GasToken()
        account_from = types.UInt160(b'\x01' * 20)
        storage_key_from = gas.key_account + account_from
        account_state = gas._state()
        account_state.balance = vm.BigInteger(123)
        storage_item_from = storage.StorageItem(account_state.to_array())

        manifest_to = contracts.ContractManifest("source_contract")
        nef_to = contracts.NEF(script=b'\x40')
        state_to = contracts.ContractState(1, nef_to, manifest_to, 0, contract_hash(types.UInt160.zero(), nef_to.checksum, manifest_to.name))
        account_to = state_to.hash
        amount = vm.BigInteger(0)

        engine = self.transfer_helper(gas, account_from, account_to, amount)

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
        self.assertEqual(gas.hash, transfer_event[0])
        self.assertEqual("Transfer", transfer_event[1])
        state_items = list(transfer_event[2])
        self.assertEqual(account_from, types.UInt160(state_items[0].to_array()))
        self.assertEqual(account_to, types.UInt160(state_items[1].to_array()))
        self.assertEqual(amount, state_items[2].to_biginteger())

    def test_transfer_more_than_balance(self):
        gas = contracts.GasToken()
        account_from = types.UInt160.zero()
        storage_key_from = gas.key_account + account_from
        account_state = gas._state()
        account_state.balance = vm.BigInteger(123)
        storage_item_from = storage.StorageItem(account_state.to_array())

        manifest_to = contracts.ContractManifest("source_contract")
        nef_to = contracts.NEF(script=b'\x40')
        state_to = contracts.ContractState(1, nef_to, manifest_to, 0, contract_hash(types.UInt160.zero(), nef_to.checksum, manifest_to.name))
        account_to = state_to.hash
        amount = account_state.balance + 1

        engine = self.transfer_helper(gas, account_from, account_to, amount)
        # ensure the source account has balance
        engine.snapshot.storages.put(storage_key_from, storage_item_from)
        engine.execute()
        self.assertEqual(1, len(engine.result_stack))
        result = engine.result_stack.pop()
        self.assertFalse(result)

    def test_transfer_to_self(self):
        gas = contracts.GasToken()

        manifest = contracts.ContractManifest("test_contract")
        nef = contracts.NEF(script=b'\x40')
        state_to = contracts.ContractState(1, nef, manifest, 0, contract_hash(types.UInt160.zero(), nef.checksum, manifest.name))
        account = state_to.hash

        storage_key_from = gas.key_account + account
        account_state = gas._state()
        account_state.balance = vm.BigInteger(123)
        storage_item_from = storage.StorageItem(account_state.to_array())

        amount = account_state.balance

        engine = self.transfer_helper(gas, account, account, amount)
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
        self.assertEqual(gas.hash, transfer_event[0])
        self.assertEqual("Transfer", transfer_event[1])
        state_items = list(transfer_event[2])
        self.assertEqual(account, types.UInt160(state_items[0].to_array()))
        self.assertEqual(account, types.UInt160(state_items[1].to_array()))
        self.assertEqual(amount, state_items[2].to_biginteger())

    def test_transfer_full_balance(self):
        gas = contracts.GasToken()

        manifest = contracts.ContractManifest("contract_name_to")
        nef = contracts.NEF(script=b'\x40')
        state_to = contracts.ContractState(1, nef, manifest, 0, contract_hash(types.UInt160.zero(), nef.checksum, manifest.name))
        account_to = state_to.hash

        account_from = types.UInt160(b'\x01' * 20)
        storage_key_from = gas.key_account + account_from
        account_from_state = gas._state()
        account_from_state.balance = vm.BigInteger(123)
        storage_item_from = storage.StorageItem(account_from_state.to_array())

        amount = account_from_state.balance

        engine = self.transfer_helper(gas, account_from, account_to, amount)

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
        self.assertEqual(gas.hash, transfer_event[0])
        self.assertEqual("Transfer", transfer_event[1])
        state_items = list(transfer_event[2])
        self.assertEqual(account_from, types.UInt160(state_items[0].to_array()))
        self.assertEqual(account_to, types.UInt160(state_items[1].to_array()))
        self.assertEqual(amount, state_items[2].to_biginteger())

        # test that the source account is no longer present in storage as the balance is zero
        self.assertIsNone(engine.snapshot.storages.try_get(storage_key_from))

    def test_transfer_partial_balance_to_account_with_balance(self):
        gas = contracts.GasToken()

        manifest = contracts.ContractManifest("contract_name")
        nef = contracts.NEF(script=b'\x40')
        state_to = contracts.ContractState(1, nef, manifest, 0, contract_hash(types.UInt160.zero(), nef.checksum, manifest.name))
        account_to = state_to.hash
        storage_key_to = gas.key_account + account_to
        account_to_state = gas._state()
        account_to_state.balance = vm.BigInteger(100)
        storage_item_to = storage.StorageItem(account_to_state.to_array())

        account_from = types.UInt160(b'\x01' * 20)
        storage_key_from = gas.key_account + account_from
        account_from_state = gas._state()
        account_from_state.balance = vm.BigInteger(123)
        storage_item_from = storage.StorageItem(account_from_state.to_array())

        amount = vm.BigInteger(50)

        engine = self.transfer_helper(gas, account_from, account_to, amount)
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
        self.assertEqual(gas.hash, transfer_event[0])
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
            gas.mint(None, None, vm.BigInteger(-1), False)
        self.assertEqual("Can't mint a negative amount", str(context.exception))
