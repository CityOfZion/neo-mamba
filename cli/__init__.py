#!/usr/bin/env python3
"""neo3 - NEO smart contract toolchain CLI."""

import argparse
import sys
from neo3 import __version__
from cli.cmd_compile import compile_contract
from cli.cmd_contract_init import scaffold_init
from cli.cmd_disassemble import disassemble_bytecode
from cli.generate_sdk import generate_sdk
from cli.cpm_download import cpm_download


def cmd_version(_: argparse.Namespace) -> int:
    print(f"v{__version__}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mamba",
        description="NEO smart contract toolchain",
    )
    parser.set_defaults(func=None)

    subparsers = parser.add_subparsers(title="commands", metavar="<command>")

    create_parser = subparsers.add_parser("create", help="Create a new dApp with a smart contract and tests")
    create_parser.add_argument("name", metavar="<name>", help="dApp name")
    create_parser.set_defaults(func=scaffold_init, gen_cpm=True)

    version_parser = subparsers.add_parser("version", help="Print the SDK version")
    version_parser.set_defaults(func=cmd_version)

    contract_parser = subparsers.add_parser("contract", help="Smart contract building operations")
    contract_subparsers = contract_parser.add_subparsers(title="contract commands", metavar="<subcommand>")
    contract_parser.set_defaults(func=lambda _: contract_parser.print_help() or 1)

    compile_parser = contract_subparsers.add_parser("compile", help="Compile a smart contract source file")
    compile_parser.add_argument("input_file", metavar="<input_file>", help="Path to the contract source file")
    compile_parser.set_defaults(func=compile_contract)

    generate_parser = subparsers.add_parser("sdk", help="Generate SDK(s)")
    generate_parser.add_argument("manifest", metavar="<manifest>", help="Path to contract manifest.json")
    generate_parser.add_argument("-c", metavar="<contract hash>", help="Contract script hash if known")
    generate_mode = generate_parser.add_mutually_exclusive_group(required=True)
    generate_mode.add_argument("--off-chain", action="store_true", help="Create SDK for off-chain access to the contract")
    generate_mode.add_argument("--on-chain", action="store_true", help="Create SDK inter smart contract access")
    generate_parser.set_defaults(func=generate_sdk)

    init_parser = contract_subparsers.add_parser("init", help="Scaffold a new smart contract project")
    init_parser.add_argument("name", metavar="<name>", help="Name of the new contract")
    init_parser.set_defaults(func=scaffold_init, gen_cpm=False)

    download_parser = contract_subparsers.add_parser("download", help="Download contracts defined in cpm.yaml to your local neo-express chain.")
    download_parser.set_defaults(func=cpm_download)

    disassemble_parser = subparsers.add_parser("disassemble", help="Disassemble NeoVM bytecode")
    disassemble_parser.add_argument("input", metavar="<input>", help="Hex bytecode, base64 bytecode, or path to a .nef file")
    disassemble_mode = disassemble_parser.add_mutually_exclusive_group()
    disassemble_mode.add_argument("--base64", action="store_true", help="Decode input as base64")
    disassemble_mode.add_argument("--nef", action="store_true", help="Load input from a .nef file")
    disassemble_parser.set_defaults(func=disassemble_bytecode)

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