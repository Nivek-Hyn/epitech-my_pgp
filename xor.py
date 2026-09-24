##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## xor
##

import sys

def xor(message: bytes, key_hex: str) -> str:
    key_bytes = bytes.fromhex(key_hex)

    result = []
    for byte, key in zip(message[::-1], key_bytes):
        result.append(byte ^ key)

    result = bytes(result)
    return result.hex()

def run_xor(mode: str, key: str, block: bool, data: bytes) -> int:

    try:
        bytes.fromhex(key)
    except ValueError:
        print("error: invalid key.", file=sys.stderr)
        return 84

    if data.endswith(b"\n"):
        data = data[:-1]

    print(xor(data, key))
    return 0
