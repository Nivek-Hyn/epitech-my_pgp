##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## unit tests for the elgamal module
##

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from util import capture_output

from elgamal import (parse_ciphertext, parse_elgamal_key, run_elgamal,
                     run_elgamal_generate)

# Hand-computed vector: p = 23, g = 5, x = 7 -> y = 17.
# k = 3, m = 2: c1 = 5^3 mod 23 = 10, c2 = 2 * 17^3 mod 23 = 5.
P = "17"
G = "05"
X = "07"
Y = "11"
K = "03"
PUBLIC_KEY = f"{Y}-{P}-{G}"
PRIVATE_KEY = f"{X}-{P}-{G}"
CIPHER_KEY = f"{K}:{PUBLIC_KEY}"
MESSAGE = b"\x02"
CIPHERED = b"0a-05\n"

# 256-bit prime from the subject appendix, page 12.
P_256 = ("4b1da73924978f2e9c1f04170e46820d648edbee12ccf4d4462af89b080c86e1")
X_256 = "deadbeef"
LONG_MESSAGE = b"All men must die"


class TestParsing(unittest.TestCase):

    def test_parses_three_key_components(self):
        self.assertEqual(parse_elgamal_key("11-17-05"), (17, 23, 5))

    def test_rejects_wrong_number_of_parts(self):
        for key in ("11-17", "11-17-05-42"):
            with self.assertRaises(ValueError):
                parse_elgamal_key(key)

    def test_rejects_invalid_hex(self):
        with self.assertRaises(ValueError):
            parse_elgamal_key("zz-17-05")

    def test_parses_ciphertext_pair(self):
        self.assertEqual(parse_ciphertext("0a-05"), (10, 5))

    def test_rejects_malformed_ciphertext(self):
        with self.assertRaises(ValueError):
            parse_ciphertext("0a")


class TestKeyGeneration(unittest.TestCase):

    def test_matches_hand_computed_vector(self):
        code, output, err = capture_output(run_elgamal_generate, P, G, X)
        self.assertEqual(code, 0)
        self.assertEqual(output, b"public key: 11-17-05\n"
                                b"private key: 07-17-05\n")

    def test_invalid_parameters_exit_84(self):
        code, output, err = capture_output(run_elgamal_generate, "zz", G, X)
        self.assertEqual(code, 84)
        self.assertIn("invalid", err)


class TestCipherDecipher(unittest.TestCase):

    def test_cipher_matches_hand_computed_vector(self):
        code, output, err = capture_output(run_elgamal, "-c", CIPHER_KEY,
                                           False, MESSAGE + b"\n")
        self.assertEqual(code, 0)
        self.assertEqual(output, CIPHERED)

    def test_decipher_matches_hand_computed_vector(self):
        code, output, err = capture_output(run_elgamal, "-d", PRIVATE_KEY,
                                           False, CIPHERED)
        self.assertEqual(code, 0)
        self.assertEqual(output, MESSAGE + b"\n")

    def test_c1_and_c2_follow_the_definitions(self):
        code, output, err = capture_output(run_elgamal, "-c", CIPHER_KEY,
                                           False, MESSAGE + b"\n")
        c1, c2 = parse_ciphertext(output.decode().strip())
        self.assertEqual(c1, pow(5, 3, 23))
        self.assertEqual(c2, (2 * pow(17, 3, 23)) % 23)

    def test_message_too_big_exits_84(self):
        code, output, err = capture_output(run_elgamal, "-c", CIPHER_KEY,
                                           False, b"\xff" * 23)
        self.assertEqual(code, 84)
        self.assertIn("too big", err)

    def test_round_trip_with_256_bit_prime(self):
        code, keys, err = capture_output(run_elgamal_generate, P_256, "05",
                                         X_256)
        self.assertEqual(code, 0)
        public = keys.decode().split("\n")[0].split("public key: ")[1]

        code, ciphered, err = capture_output(run_elgamal, "-c",
                                             f"03:{public}", False,
                                             LONG_MESSAGE + b"\n")
        self.assertEqual(code, 0)

        code, deciphered, err = capture_output(run_elgamal, "-d",
                                               f"{X_256}-{P_256}-05", False,
                                               ciphered)
        self.assertEqual(code, 0)
        self.assertEqual(deciphered, LONG_MESSAGE + b"\n")

    def test_two_k_values_give_two_ciphertexts_one_message(self):
        code, keys, err = capture_output(run_elgamal_generate, P_256, "05",
                                         X_256)
        public = keys.decode().split("\n")[0].split("public key: ")[1]

        code, first, err = capture_output(run_elgamal, "-c",
                                          f"03:{public}", False,
                                          LONG_MESSAGE + b"\n")
        code, second, err = capture_output(run_elgamal, "-c",
                                           f"2a:{public}", False,
                                           LONG_MESSAGE + b"\n")
        self.assertNotEqual(first, second)

        for ciphered in (first, second):
            code, deciphered, err = capture_output(run_elgamal, "-d",
                                                   f"{X_256}-{P_256}-05",
                                                   False, ciphered)
            self.assertEqual(deciphered, LONG_MESSAGE + b"\n")


class TestErrors(unittest.TestCase):

    def test_missing_colon_exits_84(self):
        code, output, err = capture_output(run_elgamal, "-c", "nocolon",
                                          False, MESSAGE + b"\n")
        self.assertEqual(code, 84)

    def test_invalid_public_key_exits_84(self):
        code, output, err = capture_output(run_elgamal, "-c", "03:11-17",
                                          False, MESSAGE + b"\n")
        self.assertEqual(code, 84)

    def test_invalid_private_key_exits_84(self):
        code, output, err = capture_output(run_elgamal, "-d", "07-17",
                                          False, CIPHERED)
        self.assertEqual(code, 84)

    def test_invalid_ciphertext_exits_84(self):
        code, output, err = capture_output(run_elgamal, "-d", PRIVATE_KEY,
                                           False, b"zz\n")
        self.assertEqual(code, 84)


if __name__ == "__main__":
    unittest.main()
