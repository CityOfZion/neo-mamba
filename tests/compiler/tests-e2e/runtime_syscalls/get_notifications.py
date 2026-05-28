from neo3.sc.compiletime import event, public
from neo3.sc.runtime import get_notifications, get_executing_script_hash
from neo3.sc.types import Notification, UInt160
from neo3.sc.utils import call_contract


@event(name="MyEvent")
def on_my_event(value: int) -> None:
    pass


@public
def get_all(helper_hash: UInt160) -> list[Notification]:
    on_my_event(1)
    call_contract(helper_hash, "emit", [2])
    return get_notifications()


@public
def get_filtered(helper_hash: UInt160) -> list[Notification]:
    on_my_event(1)
    call_contract(helper_hash, "emit", [2])
    my_hash = get_executing_script_hash()
    return get_notifications(my_hash)
