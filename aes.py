##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## aes
##

import sys

from xor import split_blocks

## An AES block is always 16 bytes, whatever the key size.
BLOCK_SIZE = 16

## AES-128 key size, in bytes.
KEY_SIZE = 16

## Substitution table from FIPS-197. Read as a 16x16 grid: the left hex digit
## of the index picks the row, the right one the column.
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


##
## @brief Build the lookup table that undoes the given one.
##
## If table[a] == b then the result maps b back to a. Computing it instead of
## copying a second 256-value table removes any risk of a typo.
##
## @param table: a permutation of the 256 byte values
##
## @return The inverse table
##
def invert_table(table: bytes) -> bytes:
    inverted = [0] * 256

    for value, substitute in enumerate(table):
        inverted[substitute] = value

    return bytes(inverted)


## Substitution table used to decipher.
INV_SBOX = invert_table(SBOX)

## Coefficients of MixColumns. Circulant, so every output byte gets the same
## recipe applied at a different offset.
MIX_MATRIX = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2],
]

## Coefficients that undo MixColumns.
INV_MIX_MATRIX = [
    [14, 11, 13, 9],
    [9, 14, 11, 13],
    [13, 9, 14, 11],
    [11, 13, 9, 14],
]


##
## @brief Lay a 16-byte block out as the 4x4 AES state.
##
## Filled column by column as the subject requires: the first 4 bytes are the
## first column. The 2D shape is what lets ShiftRows mix across columns while
## MixColumns mixes inside them.
##
## @param block: exactly 16 bytes
##
## @return A list of 4 rows of 4 integers
##
def to_state(block: bytes) -> list:
    state = [[0] * 4 for _ in range(4)]

    for i in range(16):
        state[i % 4][i // 4] = block[i]

    return state


##
## @brief Read the state back into a 16-byte block, column by column.
##
## @param state: a 4x4 state matrix
##
## @return The 16 bytes of the block
##
def from_state(state: list) -> bytes:
    return bytes(state[i % 4][i // 4] for i in range(16))


##
## @brief SubBytes: replace every byte of the state through a lookup table.
##
## The only non-linear step of AES. Without it the cipher would reduce to a
## solvable linear system.
##
## @param state: a 4x4 state matrix
## @param table: SBOX to cipher, INV_SBOX to decipher
##
## @return A new state, the input left untouched
##
def substitute_bytes(state: list, table: bytes) -> list:
    return [[table[value] for value in row] for row in state]


##
## @brief Rotate a list to the left, wrapping around.
##
## @param row: the list to rotate
## @param shift: number of places to move left; negative rotates right
##
## @return A new rotated list
##
def rotate_left(row: list, shift: int) -> list:
    return row[shift:] + row[:shift]


##
## @brief ShiftRows: rotate row n left by n positions.
##
## Row 0 stays put. This is the only step carrying information between
## columns, so a byte of column 0 can end up influencing column 3.
##
## @param state: a 4x4 state matrix
##
## @return A new state
##
def shift_rows(state: list) -> list:
    return [rotate_left(state[n], n) for n in range(4)]


##
## @brief InvShiftRows: rotate row n right by n positions.
##
## @param state: a 4x4 state matrix
##
## @return A new state
##
def inv_shift_rows(state: list) -> list:
    return [rotate_left(state[n], -n) for n in range(4)]


##
## @brief Multiply a byte by 2 in GF(2^8).
##
## Doubling is a left shift. When the high bit was set the shift overflows the
## byte, and the overflowing bit is folded back with a XOR of 0x1B instead of
## being dropped. Dropping it would make half the values collide and the
## cipher impossible to undo.
##
## @param value: the byte to double
##
## @return The doubled byte
##
def xtime(value: int) -> int:
    doubled = (value << 1) & 0xFF

    if value & 0x80:
        doubled ^= 0x1B

    return doubled


##
## @brief Multiply two bytes in GF(2^8).
##
## Long multiplication in binary: one pass per bit of b, adding a (with a XOR,
## which is the addition of the field) whenever that bit is set, and doubling a
## between passes.
##
## @param a: first byte
## @param b: second byte
##
## @return The product, still a single byte
##
def gf_mul(a: int, b: int) -> int:
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1

    return result


##
## @brief Extract one column of the state.
##
## @param state: a 4x4 state matrix
## @param col: the column index, 0 to 3
##
## @return The 4 bytes of that column, top to bottom
##
def get_column(state: list, col: int) -> list:
    return [state[row][col] for row in range(4)]


##
## @brief Combine the 4 bytes of one column through the matrix.
##
## Each matrix row produces one output byte, as the sum of its coefficients
## multiplied by the column values. Addition is XOR, multiplication is gf_mul.
## Every output byte therefore depends on all four input bytes.
##
## @param column: 4 bytes
## @param matrix: MIX_MATRIX to cipher, INV_MIX_MATRIX to decipher
##
## @return The 4 mixed bytes
##
def mix_one_column(column: list, matrix: list) -> list:
    mixed = []

    for matrix_row in matrix:
        value = 0
        for coefficient, byte in zip(matrix_row, column):
            value ^= gf_mul(coefficient, byte)
        mixed.append(value)

    return mixed


##
## @brief MixColumns: mix each of the 4 columns of the state.
##
## @param state: a 4x4 state matrix
## @param matrix: MIX_MATRIX to cipher, INV_MIX_MATRIX to decipher
##
## @return A new state
##
def mix_columns(state: list, matrix: list) -> list:
    new_state = [[0] * 4 for _ in range(4)]

    for col in range(4):
        mixed = mix_one_column(get_column(state, col), matrix)
        for row in range(4):
            new_state[row][col] = mixed[row]

    return new_state


##
## @brief Apply the s-box to the 4 bytes of a single word.
##
## Same table as SubBytes, applied to a word of the key schedule instead of
## the whole state.
##
## @param word: 4 bytes
##
## @return The 4 substituted bytes
##
def substitute_word(word: list) -> list:
    return [SBOX[byte] for byte in word]


##
## @brief XOR two words of 4 bytes together.
##
## @param left: 4 bytes
## @param right: 4 bytes
##
## @return The 4 resulting bytes
##
def xor_words(left: list, right: list) -> list:
    return [a ^ b for a, b in zip(left, right)]


##
## @brief Build the round constants of the key expansion.
##
## Starts at 0x01 and doubles in GF(2^8), which is why the ninth value is 0x1B
## rather than 0x100.
##
## @param count: how many constants to produce
##
## @return The list of constants
##
def round_constants(count: int) -> list:
    constants = [0x01]

    while len(constants) < count:
        constants.append(xtime(constants[-1]))

    return constants


## One round constant per generated round key: 01 02 04 08 10 20 40 80 1b 36.
RCON = round_constants(10)


##
## @brief Expand a 16-byte key into the 11 round keys of AES-128.
##
## Words 0 to 3 are the key itself. Each later word is the word four places
## back, which sits at the same position in the previous round key, XORed with
## a transformation of the word just before it. Every fourth word gets the
## extra treatment that breaks any symmetry between round keys: a rotation,
## the s-box, and a round constant that differs each time.
##
## @param key: exactly 16 bytes
##
## @return A list of 11 round keys, each a list of 4 words of 4 bytes
##
def expand_key(key: bytes) -> list:
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]

    for i in range(4, 44):
        previous = list(words[i - 1])
        if i % 4 == 0:
            previous = substitute_word(rotate_left(previous, 1))
            previous[0] ^= RCON[i // 4 - 1]
        words.append(xor_words(words[i - 4], previous))

    return [words[i:i + 4] for i in range(0, 44, 4)]


##
## @brief AddRoundKey: XOR the state with a round key.
##
## The only step that uses the secret; the three others are public. Word n of
## the round key holds column n of the state, hence the crossed indices.
##
## @param state: a 4x4 state matrix
## @param round_key: 4 words of 4 bytes
##
## @return A new state
##
def add_round_key(state: list, round_key: list) -> list:
    new_state = [[0] * 4 for _ in range(4)]

    for row in range(4):
        for col in range(4):
            new_state[row][col] = state[row][col] ^ round_key[col][row]

    return new_state


##
## @brief Cipher one 16-byte block through the 10 AES rounds.
##
## A key is added before the first round, otherwise the first operation on the
## message would be public and the round would protect nothing. The last round
## has no MixColumns: being public, invertible and the last mixing step, an
## attacker could peel it off the ciphertext alone.
##
## @param block: exactly 16 bytes
## @param round_keys: the 11 round keys from expand_key
##
## @return The 16 ciphered bytes
##
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


##
## @brief Decipher one 16-byte block.
##
## The same steps undone backwards: round keys from 10 down to 0, and each
## operation replaced by its inverse.
##
## @param block: exactly 16 ciphered bytes
## @param round_keys: the 11 round keys from expand_key
##
## @return The 16 clear bytes
##
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


##
## @brief Reverse each group of 4 bytes.
##
## The subject writes keys and ciphered output as 32-bit little-endian numbers,
## so every word is stored backwards while the message keeps its natural order.
## Applying this at the edges keeps the cipher itself free of the convention.
##
## @param data: any number of bytes, a multiple of 4
##
## @return The data with each word reversed
##
def reverse_words(data: bytes) -> bytes:
    return b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))


##
## @brief Cipher a message with AES.
##
## @param data: the clear message
## @param key_bytes: the 16-byte key, as written on the command line
## @param block: True to treat only the first block
##
## @return The ciphered bytes, ready to be printed as hexadecimal
##
def cipher_aes(data: bytes, key_bytes: bytes, block: bool) -> bytes:
    round_keys = expand_key(reverse_words(key_bytes))
    result = b""

    for chunk in split_blocks(data, BLOCK_SIZE, block):
        result += reverse_words(cipher_block(chunk, round_keys))

    return result


##
## @brief Decipher a message with AES.
##
## @param data: the ciphered bytes
## @param key_bytes: the 16-byte key, as written on the command line
## @param block: True to treat only the first block
##
## @return The clear bytes
##
def decipher_aes(data: bytes, key_bytes: bytes, block: bool) -> bytes:
    round_keys = expand_key(reverse_words(key_bytes))
    result = b""

    for chunk in split_blocks(data, BLOCK_SIZE, block):
        result += decipher_block(reverse_words(chunk), round_keys)

    return result


##
## @brief Entry point of the "aes" crypto system.
##
## Validates the key, drops the trailing line feed of the message, then
## ciphers to hexadecimal or deciphers to raw bytes.
##
## @param mode: "-c" to cipher, "-d" to decipher
## @param key: the key in hexadecimal, 16 bytes once decoded
## @param block: True when -b was given
## @param data: the message read on the standard input
##
## @return 0 on success, 84 on error
##
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
