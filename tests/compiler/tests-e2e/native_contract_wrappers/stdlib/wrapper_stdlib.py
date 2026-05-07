from neo3.sc.compiletime import public
from neo3.sc.contracts.stdlib import StdLib


@public
def main(input: bytes) -> str:
    return StdLib.hex_encode(input)
