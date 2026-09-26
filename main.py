##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## main
##

import sys

from xor import run_xor
from aes import run_aes
from rsa import run_rsa, run_rsa_generate
from elgamal import run_elgamal, run_elgamal_generate
from pgp import run_pgp_aes, run_pgp_xor

USAGE = """USAGE
     ./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]

DESCRIPTION
Cipher or decipher MESSAGE using a given CRYPTO_SYSTEM. The MESSAGE is read from the standard input.

     CRYPTO_SYSTEM
        "xor"            computation using XOR algorithm
        "aes"            computation using AES algorithm
        "rsa"            computation using RSA algorithm
        "elgamal"        computation using ElGamal algorithm (bonus)
        "pgp-xor"        computation using both RSA and XOR algorithm
        "pgp-aes"        computation using both RSA and AES algorithm

     MODE
        -c               MESSAGE is clear and we want to cipher it
        -d               MESSAGE is ciphered and we want to decipher it
        -g P Q           RSA only: don't read a MESSAGE, but instead generate a public and private key
        pair from the prime number P and Q

     OPTIONS
        -b               for XOR, AES and PGP, only works on one block. The MESSAGE and the symmetric
        key must be the same size

     key                Key used to cipher/decipher MESSAGE (incompatible with -g MODE)"""

def help():
    print(USAGE)

HANDLERS = {
    "xor": run_xor,
    "aes": run_aes,
    "rsa": run_rsa,
    "elgamal": run_elgamal,
    "pgp-xor": run_pgp_xor,
    "pgp-aes": run_pgp_aes
}

def print_error(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 84

def parse_args(argv: list[str]) -> dict:
    return {
        "crypto_system": argv[1],
        "mode": argv[2] if len(argv) > 2 else None,
        "options": [a for a in argv[3:] if a.startswith("-")],
        "operands": [a for a in argv[3:] if not a.startswith("-")]
    }

def check_args(args: dict) -> int:
    if args["crypto_system"] not in HANDLERS:
        return print_error("unknown crypto system: " + args["crypto_system"])

    if args["mode"] is None:
        return print_error("missing mode.")

    if args["mode"] not in {"-c", "-d", "-g"}:
        return print_error("unknown mode: " + args["mode"])

    if args["mode"] == "-g":
        if args["crypto_system"] == "rsa":
            if len(args["operands"]) != 2:
                return print_error("-g requires exactly two prime numbers.")
            return 0
        if args["crypto_system"] == "elgamal":
            if len(args["operands"]) != 3:
                return print_error("-g requires exactly three parameters "
                                   "(prime, generator, private exponent).")
            return 0
        return print_error("-g is only available for rsa and elgamal.")

    for option in args["options"]:
        if option != "-b":
            return print_error("unknown option: " + option)

    if len(args["operands"]) != 1:
        return print_error("expected exactly one key.")

    return 0

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        help()
        return 84

    if argv[1] == "-h":
        help()
        return 0

    args = parse_args(argv)
    if check_args(args) != 0:
        return 84

    if args["mode"] == "-g":
        if args["crypto_system"] == "rsa":
            return run_rsa_generate(args["operands"][0], args["operands"][1])
        return run_elgamal_generate(*args["operands"])

    handler = HANDLERS[args["crypto_system"]]
    return handler(mode=args["mode"],
                   key=args["operands"][0],
                   block="-b" in args["options"],
                   data=sys.stdin.buffer.read())

if __name__ == "__main__":
    sys.exit(main(sys.argv))
