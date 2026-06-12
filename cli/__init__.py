#!/usr/bin/env python3
"""neo3 - NEO smart contract toolchain CLI."""

import argparse
import sys
from neo3 import __version__
from cli.cmd_compile import compile_contract
from cli.cmd_contract_init import scaffold_init

def cmd_version(_: argparse.Namespace) -> int:
    print(f"v{__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="neo3",
        description="NEO smart contract toolchain",
    )
    parser.set_defaults(func=None)

    subparsers = parser.add_subparsers(title="commands", metavar="<command>")

    version_parser = subparsers.add_parser("version", help="Print the SDK version")
    version_parser.set_defaults(func=cmd_version)

    contract_parser = subparsers.add_parser("contract", help="Smart contract building operations")
    contract_subparsers = contract_parser.add_subparsers(title="contract commands", metavar="<subcommand>")
    contract_parser.set_defaults(func=lambda _: contract_parser.print_help() or 1)

    compile_parser = contract_subparsers.add_parser("compile", help="Compile a smart contract source file")
    compile_parser.add_argument("input_file", metavar="<input_file>", help="Path to the contract source file")
    compile_parser.set_defaults(func=compile_contract)

    init_parser = contract_subparsers.add_parser("init", help="Scaffold a new smart contract project")
    init_parser.add_argument("name", metavar="<name>", help="Name of the new contract")
    init_parser.set_defaults(func=scaffold_init)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.func is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(args.func(args))


if __name__ == "__main__":
    main()