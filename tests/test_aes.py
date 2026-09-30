##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## unit tests for the aes module
##

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from util import capture_output

from aes import (INV_MIX_MATRIX, INV_SBOX, MIX_MATRIX, RCON, SBOX,
                 add_round_key, cipher_aes, cipher_block, decipher_aes,
                 decipher_block, expand_key, from_state, gf_mul,
                 inv_shift_rows, mix_columns, mix_one_column, reverse_words,
                 rotate_left, run_aes, shift_rows, substitute_bytes, to_state,
                 xtime)

# Vectors from the subject, page 5.
PDF_KEY = "57696e74657220697320636f6d696e67"
PDF_MESSAGE = b"All men must die"
PDF_CIPHERED = "744ce22c385958348f0df26eceb62eef"

# Vectors from the AES standard, FIPS-197 appendices A.1 and B.
FIPS_KEY = "2b7e151628aed2a6abf7158809cf4f3c"
FIPS_PLAIN = "3243f6a8885a308d313198a2e0370734"
FIPS_CIPHERED = "3925841d02dc09fbdc118597196a0b32"

# One vector per key size, FIPS-197 appendix C. Same plaintext for all three.
APPENDIX_C_PLAIN = "00112233445566778899aabbccddeeff"
APPENDIX_C = (
    ("000102030405060708090a0b0c0d0e0f",
     "69c4e0d86a7b0430d8cdb78070b4c55a", 11),
    ("000102030405060708090a0b0c0d0e0f1011121314151617",
     "dda97ca4864cdfe06eaf70a0ec0d7191", 13),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "8ea2b7ca516745bfeafc49904b496089", 15),
)


class TestState(unittest.TestCase):

    def test_round_trip_keeps_every_byte_in_place(self):
        block = bytes(range(16))
        self.assertEqual(from_state(to_state(block)), block)

    def test_matrix_is_filled_column_by_column(self):
        state = to_state(PDF_MESSAGE)
        self.assertEqual(state[0][0], ord("A"))
        self.assertEqual(state[2][1], ord("n"))
        self.assertEqual(state[3][2], ord("t"))


class TestSbox(unittest.TestCase):

    def test_table_holds_256_distinct_values(self):
        self.assertEqual(len(SBOX), 256)
        self.assertEqual(len(set(SBOX)), 256)

    def test_known_values_from_the_standard(self):
        self.assertEqual(SBOX[0x00], 0x63)
        self.assertEqual(SBOX[0x01], 0x7C)
        self.assertEqual(SBOX[0x53], 0xED)
        self.assertEqual(SBOX[0x97], 0x88)
        self.assertEqual(SBOX[0xFF], 0x16)

    def test_inverse_table_undoes_every_substitution(self):
        for value in range(256):
            self.assertEqual(INV_SBOX[SBOX[value]], value)


class TestSubstituteBytes(unittest.TestCase):

    def test_substituting_twice_with_both_tables_cancels_out(self):
        state = to_state(PDF_MESSAGE)
        once = substitute_bytes(state, SBOX)
        self.assertEqual(substitute_bytes(once, INV_SBOX), state)


class TestShiftRows(unittest.TestCase):

    def test_rotate_left_wraps_around(self):
        self.assertEqual(rotate_left([1, 2, 3, 4], 0), [1, 2, 3, 4])
        self.assertEqual(rotate_left([1, 2, 3, 4], 1), [2, 3, 4, 1])
        self.assertEqual(rotate_left([1, 2, 3, 4], 2), [3, 4, 1, 2])

    def test_negative_shift_rotates_right(self):
        self.assertEqual(rotate_left([1, 2, 3, 4], -1), [4, 1, 2, 3])

    def test_first_row_never_moves(self):
        state = to_state(PDF_MESSAGE)
        self.assertEqual(shift_rows(state)[0], state[0])

    def test_row_n_is_shifted_by_n(self):
        state = to_state(PDF_MESSAGE)
        for row in range(4):
            self.assertEqual(shift_rows(state)[row],
                             rotate_left(state[row], row))

    def test_inverse_restores_the_state(self):
        state = to_state(PDF_MESSAGE)
        self.assertEqual(inv_shift_rows(shift_rows(state)), state)


class TestFiniteField(unittest.TestCase):

    def test_doubling_without_overflow_is_a_plain_shift(self):
        self.assertEqual(xtime(0x57), 0xAE)

    def test_doubling_with_overflow_is_reduced(self):
        self.assertEqual(xtime(0x80), 0x1B)
        self.assertEqual(xtime(0xFF), 0xE5)

    def test_doubling_never_collides(self):
        self.assertEqual(len({xtime(value) for value in range(256)}), 256)

    def test_known_product_from_the_standard(self):
        self.assertEqual(gf_mul(0x57, 0x13), 0xFE)

    def test_neutral_and_absorbing_elements(self):
        self.assertEqual(gf_mul(0x57, 0x01), 0x57)
        self.assertEqual(gf_mul(0x57, 0x00), 0x00)


class TestMixColumns(unittest.TestCase):

    VECTORS = ((b"\xdb\x13\x53\x45", b"\x8e\x4d\xa1\xbc"),
               (b"\xf2\x0a\x22\x5c", b"\x9f\xdc\x58\x9d"),
               (b"\x01\x01\x01\x01", b"\x01\x01\x01\x01"),
               (b"\xd4\xd4\xd4\xd5", b"\xd5\xd5\xd7\xd6"))

    def test_known_column_vectors(self):
        for before, after in self.VECTORS:
            self.assertEqual(bytes(mix_one_column(list(before), MIX_MATRIX)),
                             after)

    def test_inverse_matrix_undoes_each_vector(self):
        for before, after in self.VECTORS:
            self.assertEqual(
                bytes(mix_one_column(list(after), INV_MIX_MATRIX)), before)

    def test_changing_one_input_byte_changes_all_four_outputs(self):
        first = mix_one_column([0xDB, 0x13, 0x53, 0x45], MIX_MATRIX)
        second = mix_one_column([0xDC, 0x13, 0x53, 0x45], MIX_MATRIX)
        for a, b in zip(first, second):
            self.assertNotEqual(a, b)

    def test_inverse_restores_the_state(self):
        state = to_state(PDF_MESSAGE)
        mixed = mix_columns(state, MIX_MATRIX)
        self.assertEqual(mix_columns(mixed, INV_MIX_MATRIX), state)


class TestKeyExpansion(unittest.TestCase):

    def test_round_constants_are_doubled_in_the_finite_field(self):
        self.assertEqual(RCON, [0x01, 0x02, 0x04, 0x08, 0x10,
                                0x20, 0x40, 0x80, 0x1B, 0x36])

    def test_produces_eleven_round_keys(self):
        self.assertEqual(len(expand_key(bytes.fromhex(FIPS_KEY))), 11)

    def test_first_round_key_is_the_key_itself(self):
        round_keys = expand_key(bytes.fromhex(FIPS_KEY))
        self.assertEqual(round_keys[0],
                         [[0x2B, 0x7E, 0x15, 0x16], [0x28, 0xAE, 0xD2, 0xA6],
                          [0xAB, 0xF7, 0x15, 0x88], [0x09, 0xCF, 0x4F, 0x3C]])

    def test_known_round_keys_from_the_standard(self):
        round_keys = expand_key(bytes.fromhex(FIPS_KEY))
        self.assertEqual(round_keys[1][0], [0xA0, 0xFA, 0xFE, 0x17])
        self.assertEqual(round_keys[10][3], [0xB6, 0x63, 0x0C, 0xA6])

    def test_one_flipped_key_bit_changes_the_last_round_key(self):
        first = expand_key(bytes.fromhex(FIPS_KEY))
        other = bytearray(bytes.fromhex(FIPS_KEY))
        other[0] ^= 0x01
        self.assertNotEqual(expand_key(bytes(other))[10], first[10])


class TestAddRoundKey(unittest.TestCase):

    def test_adding_the_same_key_twice_cancels_out(self):
        state = to_state(PDF_MESSAGE)
        round_keys = expand_key(bytes.fromhex(FIPS_KEY))
        once = add_round_key(state, round_keys[3])
        self.assertEqual(add_round_key(once, round_keys[3]), state)


class TestBlockCipher(unittest.TestCase):

    def test_known_block_from_the_standard(self):
        round_keys = expand_key(bytes.fromhex(FIPS_KEY))
        ciphered = cipher_block(bytes.fromhex(FIPS_PLAIN), round_keys)
        self.assertEqual(ciphered.hex(), FIPS_CIPHERED)

    def test_decipher_restores_the_block(self):
        round_keys = expand_key(bytes.fromhex(FIPS_KEY))
        plain = bytes.fromhex(FIPS_PLAIN)
        self.assertEqual(decipher_block(cipher_block(plain, round_keys),
                                        round_keys), plain)


class TestKeySizes(unittest.TestCase):

    def test_each_key_size_gives_the_right_number_of_round_keys(self):
        for key_hex, _, expected in APPENDIX_C:
            self.assertEqual(len(expand_key(bytes.fromhex(key_hex))), expected)

    def test_known_block_per_key_size(self):
        plain = bytes.fromhex(APPENDIX_C_PLAIN)
        for key_hex, ciphered, _ in APPENDIX_C:
            round_keys = expand_key(bytes.fromhex(key_hex))
            self.assertEqual(cipher_block(plain, round_keys).hex(), ciphered)

    def test_decipher_per_key_size(self):
        plain = bytes.fromhex(APPENDIX_C_PLAIN)
        for key_hex, ciphered, _ in APPENDIX_C:
            round_keys = expand_key(bytes.fromhex(key_hex))
            self.assertEqual(decipher_block(bytes.fromhex(ciphered),
                                            round_keys), plain)

    def test_cli_round_trip_for_every_key_size(self):
        message = b"All men must die"
        for key_hex, _, _ in APPENDIX_C:
            code, out, _ = capture_output(run_aes, "-c", key_hex, True,
                                          message + b"\n")
            self.assertEqual(code, 0)
            code, out, _ = capture_output(run_aes, "-d", key_hex, True, out)
            self.assertEqual(code, 0)
            self.assertEqual(out, message + b"\n")


class TestReverseWords(unittest.TestCase):

    def test_reverses_each_group_of_four_bytes(self):
        self.assertEqual(reverse_words(bytes.fromhex("01234567")),
                         bytes.fromhex("67452301"))

    def test_applying_it_twice_restores_the_data(self):
        block = bytes(range(16))
        self.assertEqual(reverse_words(reverse_words(block)), block)


class TestCipherAes(unittest.TestCase):

    def test_subject_vector(self):
        key = bytes.fromhex(PDF_KEY)
        self.assertEqual(cipher_aes(PDF_MESSAGE, key, True).hex(), PDF_CIPHERED)

    def test_decipher_gives_the_message_back(self):
        key = bytes.fromhex(PDF_KEY)
        ciphered = bytes.fromhex(PDF_CIPHERED)
        self.assertEqual(decipher_aes(ciphered, key, True), PDF_MESSAGE)

    def test_block_mode_matches_stream_mode_on_a_single_block(self):
        key = bytes.fromhex(PDF_KEY)
        self.assertEqual(cipher_aes(PDF_MESSAGE, key, True),
                         cipher_aes(PDF_MESSAGE, key, False))

    def test_stream_mode_pads_the_last_block_with_zeros(self):
        key = bytes.fromhex(PDF_KEY)
        message = b"Winter is coming"
        ciphered = cipher_aes(message + b"!", key, False)
        self.assertEqual(len(ciphered), 32)
        self.assertEqual(decipher_aes(ciphered, key, False),
                         message + b"!" + b"\x00" * 15)


class TestRunAes(unittest.TestCase):

    def test_cipher_writes_the_subject_vector(self):
        code, out, _ = capture_output(run_aes, "-c", PDF_KEY, True,
                                      PDF_MESSAGE + b"\n")
        self.assertEqual(code, 0)
        self.assertEqual(out, PDF_CIPHERED.encode() + b"\n")

    def test_decipher_writes_the_message_back(self):
        code, out, _ = capture_output(run_aes, "-d", PDF_KEY, True,
                                      PDF_CIPHERED.encode() + b"\n")
        self.assertEqual(code, 0)
        self.assertEqual(out, PDF_MESSAGE + b"\n")

    def test_non_hexadecimal_key_is_rejected(self):
        code, _, err = capture_output(run_aes, "-c", "zz", True, b"data")
        self.assertEqual(code, 84)
        self.assertIn("error", err)

    def test_key_of_wrong_length_is_rejected(self):
        for key_hex in ("5768", "00" * 20, "00" * 33):
            code, _, err = capture_output(run_aes, "-c", key_hex, True, b"data")
            self.assertEqual(code, 84)
            self.assertIn("error", err)

    def test_non_hexadecimal_ciphered_message_is_rejected(self):
        code, _, err = capture_output(run_aes, "-d", PDF_KEY, True, b"zz")
        self.assertEqual(code, 84)
        self.assertIn("error", err)


if __name__ == "__main__":
    unittest.main()
