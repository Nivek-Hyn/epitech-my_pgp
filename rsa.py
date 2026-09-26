##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## rsa
##
import sys

from math import lcm, gcd

FERMAT_PRIMES = [65537, 257, 17, 5, 3]

def run_rsa(mode: str, key: str, block: bool, data: bytes) -> int:
    return 0


def get_int_from_hex(hex_str: str) -> int:
    return int.from_bytes(bytes.fromhex(hex_str), "little")


def get_hex_from_int(value: int) -> str:
    byte_count = (value.bit_length() + 7) // 8
    return value.to_bytes(byte_count, "little").hex()

def run_rsa_generate(p_hex: str, q_hex: str) -> int:
    try:
        p_int = get_int_from_hex(p_hex)
        q_int = get_int_from_hex(q_hex)
    except ValueError:
        print("error: invalid prime numbers given.", file=sys.stderr)
        return 84

    n = p_int * q_int
    lambda_n = lcm(p_int - 1, q_int - 1)

    e = next(candidate for candidate in FERMAT_PRIMES
             if candidate < lambda_n and gcd(candidate, lambda_n) == 1)

    d = pow(e, -1, lambda_n)

    print(f"public key: {get_hex_from_int(e)}-{get_hex_from_int(n)}")
    print(f"private key: {get_hex_from_int(d)}-{get_hex_from_int(n)}")
    return 0
