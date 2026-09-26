##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## rsa
##
from math import lcm, gcd

def run_rsa(mode: str, key: str, block: bool, data: bytes) -> int:
    return 0


def get_int_from_hex(hex_str: str) -> int:
    return int.from_bytes(bytes.fromhex(hex_str), "little")

def run_rsa_generate(p_hex: str, q_hex: str) -> int:
    p_int = get_int_from_hex(p_hex)
    q_int = get_int_from_hex(q_hex)
    n = p_int * q_int
    lambda_n = lcm(p_int - 1, q_int - 1)
    
