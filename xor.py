##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## xor
##

import sys

def xor(data: bytes, key: bytes) -> bytes:

    result = []

    for data_byte, key_byte in zip(data, key):
        result.append(data_byte ^ key_byte)

    return bytes(result)

def run_xor(mode: str, key: str, block: bool, data: bytes) -> int:

    try:
        bytes.fromhex(key)
    except ValueError:
        print("error: invalid key.", file=sys.stderr)
        return 84

    if data.endswith(b"\n"):
        data = data[:-1]

    key_bytes = bytes.fromhex(key)
    if mode == "-c":
        result = xor(data[::-1], key_bytes).hex()
        print(result)
    elif mode == "-d":
        data_hexa = data.decode()
        data_bytes = bytes.fromhex(data)
        result = xor(data_bytes, key_bytes)
        sys.stdout.buffer.write(result[::-1])

    return 0
