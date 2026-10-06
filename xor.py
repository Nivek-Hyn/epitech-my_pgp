##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## xor
##

import sys


##
## @brief XOR two byte sequences together, byte by byte.
##
## The pure operation, with no notion of hexadecimal or byte order. Stops on
## the shorter of the two, so the caller pads beforehand.
##
## @param data: the bytes to combine
## @param key: the key bytes
##
## @return The combined bytes
##
def xor(data: bytes, key: bytes) -> bytes:

    result = []

    for data_byte, key_byte in zip(data, key):
        result.append(data_byte ^ key_byte)

    return bytes(result)


##
## @brief Cut data into blocks, padding the last one with zeros.
##
## @param data: the bytes to cut
## @param size: block size; for XOR it is the key length
## @param block: True to keep only the first block, as -b requires
##
## @return The list of blocks, all exactly size bytes long
##
def split_blocks(data: bytes, size: int, block: bool) -> list:

    blocks = []

    for i in range(0, len(data), size):
        chunk = data[i:i + size]
        chunk = chunk + b"\x00" * (size - len(chunk))
        blocks.append(chunk)
        if block:
            break

    return blocks


##
## @brief Cipher a message with XOR.
##
## The message is a sequence of bytes while the key and the output are numbers
## written in little endian, two opposite conventions. Reversing each block
## lines the bytes up, so the last byte of a block meets the first byte of the
## key.
##
## @param data: the clear message
## @param key_bytes: the key bytes, which also set the block size
## @param block: True to treat only the first block
##
## @return The ciphered bytes, ready to be printed as hexadecimal
##
def cipher_xor(data: bytes, key_bytes: bytes, block: bool) -> bytes:

    result = b""

    for chunk in split_blocks(data, len(key_bytes), block):
        result += xor(chunk[::-1], key_bytes)

    return result


##
## @brief Decipher a message with XOR.
##
## XOR is its own inverse, so the operation is unchanged; only the reversal
## moves to the output, the side that is a sequence of bytes.
##
## @param data: the ciphered bytes
## @param key_bytes: the key bytes, which also set the block size
## @param block: True to treat only the first block
##
## @return The clear bytes
##
def decipher_xor(data: bytes, key_bytes: bytes, block: bool) -> bytes:

    result = b""

    for chunk in split_blocks(data, len(key_bytes), block):
        result += xor(chunk, key_bytes)[::-1]

    return result


##
## @brief Entry point of the "xor" crypto system.
##
## Validates the key, drops the trailing line feed of the message, then
## ciphers to hexadecimal or deciphers to raw bytes.
##
## @param mode: "-c" to cipher, "-d" to decipher
## @param key: the key in hexadecimal, of any non-zero length
## @param block: True when -b was given
## @param data: the message read on the standard input
##
## @return 0 on success, 84 on error
##
def run_xor(mode: str, key: str, block: bool, data: bytes = None) -> int:

    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        print("error: invalid key.", file=sys.stderr)
        return 84

    if len(key_bytes) == 0:
        print("error: empty key.", file=sys.stderr)
        return 84

    if data is None:
        data = sys.stdin.buffer.read()

    if data.endswith(b"\n"):
        data = data[:-1]

    if mode == "-c":
        print(cipher_xor(data, key_bytes, block).hex())
        return 0

    if mode == "-d":
        try:
            ciphered = bytes.fromhex(data.decode())
        except (ValueError, UnicodeDecodeError):
            print("error: invalid ciphered message.", file=sys.stderr)
            return 84

        sys.stdout.buffer.write(decipher_xor(ciphered, key_bytes, block) + b"\n")

    return 0
