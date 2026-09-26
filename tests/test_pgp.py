##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## unit tests for the pgp module
##

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from util import capture_output

from pgp import run_pgp_aes, run_pgp_xor

# Vectors from the subject, pages 8 and 11.
SYMMETRIC_KEY = "57696e74657220697320636f6d696e67"
N_256 = ("c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de"
         "139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3")
D_256 = ("81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a1"
         "1d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209")
CIPHERED_SYM_KEY = ("97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e691"
                    "6afe5c5f9b9d6eaa0a870374b686f1a024f9bbb88c23c7666545793"
                    "39caf55afd149d41d")
MESSAGE = b"All men must die"
CIPHERED_MESSAGE = "32000a5411015504534e06024d050226"

PUBLIC_KEY = f"{SYMMETRIC_KEY}:010001-{N_256}"
PRIVATE_KEY = f"{CIPHERED_SYM_KEY}:{D_256}-{N_256}"


class TestPgpXor(unittest.TestCase):

    def test_cipher_block_mode_matches_the_subject(self):
        code, output = capture_output(run_pgp_xor, "-c", PUBLIC_KEY, True,
                                      MESSAGE + b"\n")
        self.assertEqual(code, 0)
        expected = (CIPHERED_SYM_KEY + "\n" + CIPHERED_MESSAGE + "\n").encode()
        self.assertEqual(output, expected)

    def test_decipher_block_mode_matches_the_subject(self):
        code, output = capture_output(run_pgp_xor, "-d", PRIVATE_KEY, True,
                                      (CIPHERED_MESSAGE + "\n").encode())
        self.assertEqual(code, 0)
        self.assertEqual(output, MESSAGE + b"\n")

    def test_stream_round_trip(self):
        random.seed(42)
        message = bytes(random.randrange(256) for _ in range(100))
        key_bytes = bytes.fromhex(SYMMETRIC_KEY)
        padded_len = ((len(message) + len(key_bytes) - 1)
                      // len(key_bytes)) * len(key_bytes)

        code, output = capture_output(run_pgp_xor, "-c", PUBLIC_KEY, False,
                                      message)
        self.assertEqual(code, 0)
        ciphered_key, ciphered_message = output.decode().strip().split("\n")

        code, deciphered = capture_output(run_pgp_xor, "-d",
                                          f"{ciphered_key}:{D_256}-{N_256}",
                                          False,
                                          (ciphered_message + "\n").encode())
        self.assertEqual(code, 0)
        self.assertEqual(deciphered[:len(message)], message)
        self.assertEqual(deciphered[len(message):padded_len],
                         b"\x00" * (padded_len - len(message)))


class TestPgpErrors(unittest.TestCase):

    def test_missing_colon_exits_84(self):
        code, output = capture_output(run_pgp_xor, "-c", "nocolon", True,
                                      MESSAGE + b"\n")
        self.assertEqual(code, 84)

    def test_invalid_symmetric_key_exits_84(self):
        code, output = capture_output(run_pgp_xor, "-c", f"zz:010001-{N_256}",
                                      True, MESSAGE + b"\n")
        self.assertEqual(code, 84)

    def test_invalid_rsa_key_exits_84(self):
        code, output = capture_output(run_pgp_xor, "-c",
                                       f"{SYMMETRIC_KEY}:bad-rsa",
                                       True, MESSAGE + b"\n")
        self.assertEqual(code, 84)

    def test_invalid_ciphered_message_exits_84(self):
        code, output = capture_output(run_pgp_xor, "-d", PRIVATE_KEY, True,
                                      b"zz\n")
        self.assertEqual(code, 84)

    def test_pgp_aes_reports_not_implemented(self):
        # To update when the aes module lands.
        code, output = capture_output(run_pgp_aes, "-c", PUBLIC_KEY, True,
                                      MESSAGE + b"\n")
        self.assertEqual(code, 84)


if __name__ == "__main__":
    unittest.main()
