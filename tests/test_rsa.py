##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## unit tests for the rsa module
##

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from util import capture_output

from rsa import (get_hex_from_int, get_int_from_hex, parse_key,
                 run_rsa, run_rsa_generate)

# Vectors from the subject, page 8.
P_SMALL = "d3"
Q_SMALL = "e3"
PUBLIC_SMALL = "public key: 0101-19bb\n"
PRIVATE_SMALL = "private key: 9d5b-19bb\n"

P_256 = ("4b1da73924978f2e9c1f04170e46820d648edbee12ccf4d4462af89b080c86e1")
Q_256 = ("bb3ca1e126f7c8751bd81bc8daa226494efb3d128f72ed9f6cacbe96e14166cb")
N_256 = ("c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de"
         "139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3")
D_256 = ("81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a1"
         "1d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209")
PUBLIC_256 = f"public key: 010001-{N_256}\n"
PRIVATE_256 = f"private key: {D_256}-{N_256}\n"


class TestHexConversions(unittest.TestCase):

    def test_parses_little_endian_numbers(self):
        self.assertEqual(get_int_from_hex("0101"), 257)
        self.assertEqual(get_int_from_hex("19bb"), 0xbb19)
        self.assertEqual(get_int_from_hex("9d5b"), 0x5b9d)

    def test_formats_little_endian_numbers(self):
        self.assertEqual(get_hex_from_int(257), "0101")
        self.assertEqual(get_hex_from_int(0xbb19), "19bb")
        self.assertEqual(get_hex_from_int(0x5b9d), "9d5b")

    def test_conversions_round_trip(self):
        random.seed(42)
        for _ in range(50):
            value = random.randrange(1, 1 << 512)
            self.assertEqual(get_int_from_hex(get_hex_from_int(value)), value)


class TestParseKey(unittest.TestCase):

    def test_parses_exponent_and_modulus(self):
        self.assertEqual(parse_key("0101-19bb"), (257, 47897))

    def test_rejects_missing_dash(self):
        with self.assertRaises(ValueError):
            parse_key("0101")

    def test_rejects_extra_dash(self):
        with self.assertRaises(ValueError):
            parse_key("0101-19bb-42")

    def test_rejects_invalid_hex(self):
        with self.assertRaises(ValueError):
            parse_key("zz-19bb")


class TestKeyGeneration(unittest.TestCase):

    def test_small_keys_match_the_subject(self):
        code, output, _ = capture_output(run_rsa_generate, P_SMALL, Q_SMALL)
        self.assertEqual(code, 0)
        self.assertEqual(output, (PUBLIC_SMALL + PRIVATE_SMALL).encode())

    def test_256_bit_keys_match_the_subject(self):
        code, output, _ = capture_output(run_rsa_generate, P_256, Q_256)
        self.assertEqual(code, 0)
        self.assertEqual(output, (PUBLIC_256 + PRIVATE_256).encode())

    def test_invalid_primes_exit_84(self):
        code, output, _ = capture_output(run_rsa_generate, "zz", Q_SMALL)
        self.assertEqual(code, 84)


class TestCipherDecipher(unittest.TestCase):

    def test_cipher_matches_the_subject(self):
        code, output, _ = capture_output(run_rsa, "-c", "0101-19bb", False,
                                      b"WF\n")
        self.assertEqual(code, 0)
        self.assertEqual(output, b"8f84\n")

    def test_decipher_matches_the_subject(self):
        code, output, _ = capture_output(run_rsa, "-d", "9d5b-19bb", False,
                                      b"8f84\n")
        self.assertEqual(code, 0)
        self.assertEqual(output, b"WF\n")

    def test_round_trip_with_256_bit_keys(self):
        message = b"The night is dark and full of terrors"
        code, ciphered, _ = capture_output(run_rsa, "-c", f"010001-{N_256}",
                                        False, message + b"\n")
        self.assertEqual(code, 0)

        code, deciphered, _ = capture_output(run_rsa, "-d", f"{D_256}-{N_256}",
                                          False, ciphered)
        self.assertEqual(code, 0)
        self.assertEqual(deciphered, message + b"\n")

    def test_invalid_key_exits_84(self):
        code, output, _ = capture_output(run_rsa, "-c", "0101", False, b"WF\n")
        self.assertEqual(code, 84)

    def test_invalid_ciphered_message_exits_84(self):
        code, output, _ = capture_output(run_rsa, "-d", "9d5b-19bb", False,
                                       b"zz\n")
        self.assertEqual(code, 84)


if __name__ == "__main__":
    unittest.main()
