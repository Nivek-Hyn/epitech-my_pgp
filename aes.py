##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## aes
##

import sys

from xor import split_blocks

BLOCK_SIZE = 16
KEY_SIZE = 16

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

def invert_table(table: bytes) -> bytes:
    inverted = [0] * 256

    for value, substitute in enumerate(table):
        inverted[substitute] = value

    return bytes(inverted)

INV_SBOX = invert_table(SBOX)

MIX_MATRIX = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
]

INV_MIX_MATRIX = [
    [14, 11, 13, 9],
    [9, 14, 11, 13],
    [13, 9, 14, 11],
    [11, 13, 9, 14],
]

def to_state(block: bytes) -> list:
    state = [[0] * 4 for _ in range(4)]

    for i in range(16):
        state[i % 4][i // 4] = block[i]

    return state

def from_state(state: list) -> bytes:
    return bytes(state[i % 4][i // 4] for i in range(16))

def substitute_bytes(state: list, table: bytes) -> list:
    return [[table[value] for value in row] for row in state]

def rotate_left(row: list, shift: int) -> list:
    return row[shift:] + row[:shift]

def shift_rows(state: list) -> list:
    return [rotate_left(state[n], n) for n in range(4)]

def inv_shift_rows(state: list) -> list:
    return [rotate_left(state[n], -n) for n in range(4)]

def xtime(value: int) -> int:
    doubled = (value << 1) & 0xFF

    if value & 0x80:
        doubled ^= 0x1B

    return doubled

def gf_mul(a: int, b: int) -> int:
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1

    return result

def get_column(state: list, col: int) -> list:
    return [state[row][col] for row in range(4)]

def mix_one_column(column: list, matrix: list) -> list:
    mixed = []

    for matrix_row in matrix:
        value = 0
        for coefficient, byte in zip(matrix_row, column):
            value ^= gf_mul(coefficient, byte)
        mixed.append(value)

    return mixed

def mix_columns(state: list, matrix: list) -> list:
    new_state = [[0] * 4 for _ in range(4)]

    for col in range(4):
        mixed = mix_one_column(get_column(state, col), matrix)
        for row in range(4):
            new_state[row][col] = mixed[row]

    return new_state

def substitute_word(word: list) -> list:
    return [SBOX[byte] for byte in word]

def xor_words(left: list, right: list) -> list:
    return [a ^ b for a, b in zip(left, right)]

def round_constants(count: int) -> list:
    constants = [0x01]

    while len(constants) < count:
        constants.append(xtime(constants[-1]))

    return constants

RCON = round_constants(10)

def expand_key(key: bytes) -> list:
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]

    for i in range(4, 44):
        previous = list(words[i - 1])
        if i % 4 == 0:
            previous = substitute_word(rotate_left(previous, 1))
            previous[0] ^= RCON[i // 4 - 1]
        words.append(xor_words(words[i - 4], previous))

    return [words[i:i + 4] for i in range(0, 44, 4)]

def add_round_key(state: list, round_key: list) -> list:
    new_state = [[0] * 4 for _ in range(4)]

    for row in range(4):
        for col in range(4):
            new_state[row][col] = state[row][col] ^ round_key[col][row]

    return new_state

def cipher_block(block: bytes, round_keys: list) -> bytes:
    state = add_round_key(to_state(block), round_keys[0])

    for round_number in range(1, 10):
        state = substitute_bytes(state, SBOX)
        state = shift_rows(state)
        state = mix_columns(state, MIX_MATRIX)
        state = add_round_key(state, round_keys[round_number])

    state = substitute_bytes(state, SBOX)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    return from_state(state)

def decipher_block(block: bytes, round_keys: list) -> bytes:
    state = add_round_key(to_state(block), round_keys[10])

    for round_number in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = substitute_bytes(state, INV_SBOX)
        state = add_round_key(state, round_keys[round_number])
        state = mix_columns(state, INV_MIX_MATRIX)

    state = inv_shift_rows(state)
    state = substitute_bytes(state, INV_SBOX)
    state = add_round_key(state, round_keys[0])

    return from_state(state)

def reverse_words(data: bytes) -> bytes:
    return b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))

def cipher_aes(data: bytes, key_bytes: bytes, block: bool) -> bytes:
    round_keys = expand_key(reverse_words(key_bytes))
    result = b""

    for chunk in split_blocks(data, BLOCK_SIZE, block):
        result += reverse_words(cipher_block(chunk, round_keys))

    return result

def decipher_aes(data: bytes, key_bytes: bytes, block: bool) -> bytes:
    round_keys = expand_key(reverse_words(key_bytes))
    result = b""

    for chunk in split_blocks(data, BLOCK_SIZE, block):
        result += decipher_block(reverse_words(chunk), round_keys)

    return result

def run_aes(mode: str, key: str, block: bool, data: bytes) -> int:
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        print("error: invalid key.", file=sys.stderr)
        return 84

    if len(key_bytes) != KEY_SIZE:
        print("error: aes key must be 16 bytes.", file=sys.stderr)
        return 84

    if data.endswith(b"\n"):
        data = data[:-1]

    if mode == "-c":
        print(cipher_aes(data, key_bytes, block).hex())
        return 0

    try:
        ciphered = bytes.fromhex(data.decode())
    except (ValueError, UnicodeDecodeError):
        print("error: invalid ciphered message.", file=sys.stderr)
        return 84

    sys.stdout.buffer.write(decipher_aes(ciphered, key_bytes, block) + b"\n")

    return 0
