from __future__ import annotations
from collections import deque
from neo3 import vm, contracts
from neo3.core import cryptography, IInteroperable, types, msgrouter, to_script_hash
from neo3.contracts.interop import register
from typing import cast, List, Deque


@register("System.Runtime.Platform", 250, contracts.native.CallFlags.NONE, True)
def get_platform(engine: contracts.ApplicationEngine) -> str:
    return "NEO"


@register("System.Runtime.GetTrigger", 250, contracts.native.CallFlags.NONE, True)
def get_trigger(engine: contracts.ApplicationEngine) -> vm.BigInteger:
    return vm.BigInteger(engine.trigger.value)


@register("System.Runtime.GetTime", 250, contracts.native.CallFlags.ALLOW_STATES, True)
def get_time(engine: contracts.ApplicationEngine) -> int:
    return engine.snapshot.persisting_block.timestamp


@register("System.Runtime.GetScriptContainer", 250, contracts.native.CallFlags.NONE, True)
def get_scriptcontainer(engine: contracts.ApplicationEngine) -> IInteroperable:
    if not isinstance(engine.script_container, IInteroperable):
        raise ValueError("script container is not a valid IInteroperable type")
    container = cast(IInteroperable, engine.script_container)
    return container


@register("System.Runtime.GetExecutingScriptHash", 400, contracts.native.CallFlags.NONE, True)
def get_executingscripthash(engine: contracts.ApplicationEngine) -> types.UInt160:
    return engine.current_scripthash


@register("System.Runtime.GetCallingScriptHash", 400, contracts.native.CallFlags.NONE, True)
def get_callingscripthash(engine: contracts.ApplicationEngine) -> types.UInt160:
    return engine.calling_scripthash


@register("System.Runtime.GetEntryScriptHash", 400, contracts.native.CallFlags.NONE, True)
def get_entryscripthash(engine: contracts.ApplicationEngine) -> types.UInt160:
    return engine.entry_scripthash


@register("System.Runtime.CheckWitness", 30000, contracts.native.CallFlags.ALLOW_STATES, True, [bytes])
def do_checkwitness(engine: contracts.ApplicationEngine, data: bytes) -> bool:
    if len(data) == 20:
        hash_ = types.UInt160(data)
    elif len(data) == 33:
        redeemscript = contracts.Contract.create_signature_redeemscript(
            cryptography.ECPoint.deserialize_from_bytes(data)
        )
        hash_ = to_script_hash(redeemscript)
    else:
        raise ValueError("Supplied CheckWitness data is not a valid hash")

    return engine.checkwitness(hash_)


@register("System.Runtime.GetInvocationCounter", 400, contracts.native.CallFlags.NONE, True)
def get_invocationcounter(engine: contracts.ApplicationEngine) -> int:
    return engine.get_invocation_counter()


@register("System.Runtime.Log", 1000000, contracts.native.CallFlags.ALLOW_NOTIFY, False, [bytes])
def do_log(engine: contracts.ApplicationEngine, message: bytes) -> None:
    if len(message) > engine.MAX_NOTIFICATION_SIZE:
        raise ValueError(f"Log message length ({len(message)}) exceeds maximum allowed ({engine.MAX_NOTIFICATION_SIZE})")  # noqa
    msgrouter.interop_log(engine.script_container, message.decode('utf-8'))


def _validate_state_item_limits(engine: contracts.ApplicationEngine, state: vm.StackItem):
    size = 0
    checked: List[vm.StackItem] = []
    not_checked: Deque[vm.StackItem] = deque()

    while True:
        if isinstance(state, vm.StructStackItem):
            for item in state:
                not_checked.append(item)
        elif isinstance(state, vm.ArrayStackItem):
            if not any(map(lambda item: id(item) == id(state), checked)):
                checked.append(state)
                for item in state:
                    not_checked.append(item)
        elif isinstance(state, vm.PrimitiveType):
            size += len(state)
        elif isinstance(state, vm.NullStackItem):
            pass
        elif isinstance(state, vm.InteropStackItem):
            size = engine.MAX_NOTIFICATION_SIZE + 1
        elif isinstance(state, vm.MapStackItem):
            if not any(map(lambda item: id(item) == id(state), checked)):
                checked.append(state)
                for k, v in state:
                    size += len(k)
                    not_checked.append(v)
        if size > engine.MAX_NOTIFICATION_SIZE:
            raise ValueError("An item in the notification state exceeds the allowed notification size limit")
        if len(not_checked) == 0:
            break
        state = not_checked.pop()

    return size


@register("System.Runtime.Notify", 1000000, contracts.native.CallFlags.ALLOW_NOTIFY, False, [bytes, vm.ArrayStackItem])
def do_notify(engine: contracts.ApplicationEngine, event_name: bytes, state: vm.ArrayStackItem) -> None:
    """

    Args:
        engine:
        event_name:
        state: values belonging to the notification event.
        e.g. a NEP-5 transfer event might have as state: from script_hash, to script_hash and an ammount
    """
    if len(event_name) > engine.MAX_EVENT_SIZE:
        raise ValueError(
            f"Notify event name length ({len(event_name)}) exceeds maximum allowed ({engine.MAX_EVENT_SIZE})")
    _validate_state_item_limits(engine, state)
    engine.notifications.append((engine.script_container, engine.current_scripthash, event_name, state))
    msgrouter.interop_notify(engine.current_scripthash, event_name.decode('utf-8'), state)


@register("System.Runtime.GetNotifications", 10000, contracts.native.CallFlags.NONE, True, [types.UInt160])
def get_notifications(engine: contracts.ApplicationEngine, for_hash: types.UInt160) -> vm.ArrayStackItem:
    array = vm.ArrayStackItem(engine.reference_counter)
    for notification in engine.notifications:
        if notification[1] == for_hash:
            notification_stackitem = vm.ArrayStackItem(engine.reference_counter)
            notification_stackitem.append([
                vm.ByteStringStackItem(notification[1].to_array()),  # script_hash
                vm.ByteStringStackItem(notification[2]),  # message
                notification[3].deep_copy()  # state
            ])
            array.append(notification_stackitem)
    if len(array) > engine.MAX_STACK_SIZE:
        raise ValueError("Notification count exceeds limits")
    return array


@register("System.Runtime.GasLeft", 400, contracts.native.CallFlags.NONE, True)
def get_gasleft(engine: contracts.ApplicationEngine) -> int:
    if engine.is_test_mode:
        return -1
    else:
        return engine.gas_amount - engine.gas_consumed
