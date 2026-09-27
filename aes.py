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
