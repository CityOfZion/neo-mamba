from neo3.sc.compiletime import event, public


@event(name="HelperEvent")
def on_helper_event(value: int) -> None:
    pass


@public
def emit(value: int) -> None:
    on_helper_event(value)
