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

def split_blocks(data: bytes, size: int, block: bool) -> list:

    blocks = []

    for i in range(0, len(data), size):
        chunk = data[i:i + size]
        chunk = chunk + b"\x00" * (size - len(chunk))
        blocks.append(chunk)
        if block:
            break

    return blocks

def run_xor(mode: str, key: str, block: bool, data: bytes) -> int:

    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        print("error: invalid key.", file=sys.stderr)
        return 84

    if len(key_bytes) == 0:
        print("error: empty key.", file=sys.stderr)
        return 84

    if data.endswith(b"\n"):
        data = data[:-1]

    if mode == "-c":
        result = b""
        for chunk in split_blocks(data, len(key_bytes), block):
            result += xor(chunk[::-1], key_bytes)
        print(result.hex())
        return 0

    if mode == "-d":
        try:
            data = bytes.fromhex(data.decode())
        except (ValueError, UnicodeDecodeError):
            print("error: invalid ciphered message.", file=sys.stderr)
            return 84

        result = b""
        for chunk in split_blocks(data, len(key_bytes), block):
            result += xor(chunk, key_bytes)[::-1]
        sys.stdout.buffer.write(result + b"\n")

    return 0
