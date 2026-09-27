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

def to_state(block: bytes) -> list:
    state = [[0] * 4 for _ in range(4)]

    for i in range(16):
        state[i % 4][i // 4] = block[i]

    return state

def from_state(state: list) -> bytes:
    return bytes(state[i % 4][i // 4] for i in range(16))
