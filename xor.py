##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## xor
##

def xor(message: bytes, key_hex: str) -> str:
    key_bytes = bytes.fromhex(key_hex)

    result = []
    for byte, key in zip(message[::-1], key_bytes):
        result.append(byte ^ key)

    result = bytes(result)
    return result.hex()

def run_xor(mode: str, key: str, block: bool, data: bytes) -> int:
    return 0
