##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## pgp
##

import sys

from aes import cipher_aes, decipher_aes
from rsa import parse_key, get_int_from_hex, get_hex_from_int
from xor import cipher_xor, decipher_xor


def parse_pgp_key(key: str) -> tuple:
    parts = key.split(":", maxsplit=1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("key must be formatted as SYMMETRIC_KEY:RSA_KEY.")
    return parts[0], parts[1]


def run_pgp(cipher_sym, decipher_sym, mode: str, key: str, block: bool,
            data: bytes) -> int:
    try:
        sym_key_hex, rsa_key = parse_pgp_key(key)
        exponent, modulus = parse_key(rsa_key)
    except ValueError:
        print("error: invalid key.", file=sys.stderr)
        return 84

    if mode == "-c":
        try:
            sym_key_bytes = bytes.fromhex(sym_key_hex)
        except ValueError:
            print("error: invalid symmetric key.", file=sys.stderr)
            return 84

        if len(sym_key_bytes) == 0:
            print("error: empty symmetric key.", file=sys.stderr)
            return 84

        m = get_int_from_hex(sym_key_hex)
        ciphered_key = get_hex_from_int(pow(m, exponent, modulus))

        if data.endswith(b"\n"):
            data = data[:-1]

        print(ciphered_key)
        print(cipher_sym(data, sym_key_bytes, block).hex())
        return 0

    if mode == "-d":
        try:
            c = get_int_from_hex(sym_key_hex)
        except ValueError:
            print("error: invalid ciphered symmetric key.", file=sys.stderr)
            return 84

        m = pow(c, exponent, modulus)
        byte_count = (m.bit_length() + 7) // 8
        sym_key_bytes = m.to_bytes(byte_count, "little")

        if len(sym_key_bytes) == 0:
            print("error: empty symmetric key.", file=sys.stderr)
            return 84

        try:
            ciphered = bytes.fromhex(data.decode().strip())
        except (ValueError, UnicodeDecodeError):
            print("error: invalid ciphered message.", file=sys.stderr)
            return 84

        sys.stdout.buffer.write(decipher_sym(ciphered, sym_key_bytes, block)
                               + b"\n")
        return 0

    return 0


def run_pgp_xor(mode: str, key: str, block: bool, data: bytes) -> int:
    return run_pgp(cipher_xor, decipher_xor, mode, key, block, data)


def run_pgp_aes(mode: str, key: str, block: bool, data: bytes) -> int:
    return run_pgp(cipher_aes, decipher_aes, mode, key, block, data)
