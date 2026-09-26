##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## unit tests for the xor module
##

import os
import random
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from util import REPO_ROOT, capture_output

from xor import cipher_xor, decipher_xor, run_xor, split_blocks, xor

# Vectors from the subject, page 5.
PDF_KEY = "576861742069732064656164206d6179206e6576657220646965"
PDF_MESSAGE = b"You know nothing, Jon Snow"
PDF_CIPHERED = "20070f2700071c6a4449060a490515164e4e12190b190011063c"


class TestXorPrimitive(unittest.TestCase):

    def test_key_of_zeros_leaves_data_unchanged(self):
        self.assertEqual(xor(b"hello", b"\x00" * 5), b"hello")

    def test_xor_with_self_cancels_out(self):
        key = b"secret"
        self.assertEqual(xor(xor(b"attack", key), key), b"attack")


class TestSplitBlocks(unittest.TestCase):

    def test_pads_last_block_with_zeros(self):
        self.assertEqual(split_blocks(b"abc", 4, False), [b"abc\x00"])

    def test_exact_multiple_needs_no_padding(self):
        self.assertEqual(split_blocks(b"abcd", 4, False), [b"abcd"])

    def test_block_mode_keeps_only_first_block(self):
        self.assertEqual(split_blocks(b"abcdefgh", 3, True), [b"abc"])


class TestCipherVectors(unittest.TestCase):

    def test_pdf_block_cipher(self):
        result = cipher_xor(PDF_MESSAGE, bytes.fromhex(PDF_KEY), True)
        self.assertEqual(result.hex(), PDF_CIPHERED)

    def test_pdf_block_decipher(self):
        result = decipher_xor(bytes.fromhex(PDF_CIPHERED),
                              bytes.fromhex(PDF_KEY), True)
        self.assertEqual(result, PDF_MESSAGE)

    def test_stream_round_trip(self):
        random.seed(42)
        message = bytes(random.randrange(256) for _ in range(100))
        key = bytes(random.randrange(256) for _ in range(7))
        padded_len = ((len(message) + len(key) - 1) // len(key)) * len(key)

        ciphered = cipher_xor(message, key, False)
        self.assertEqual(len(ciphered), padded_len)

        deciphered = decipher_xor(ciphered, key, False)
        self.assertEqual(deciphered[:len(message)], message)
        self.assertEqual(deciphered[len(message):], b"\x00" * (padded_len - len(message)))


class TestRunXor(unittest.TestCase):

    def test_run_cipher_block_mode(self):
        code, output, _ = capture_output(run_xor, "-c", PDF_KEY, True,
                                      PDF_MESSAGE + b"\n")
        self.assertEqual(code, 0)
        self.assertEqual(output, (PDF_CIPHERED + "\n").encode())

    def test_run_decipher_block_mode(self):
        code, output, _ = capture_output(run_xor, "-d", PDF_KEY, True,
                                       (PDF_CIPHERED + "\n").encode())
        self.assertEqual(code, 0)
        self.assertEqual(output, PDF_MESSAGE + b"\n")

    def test_invalid_key_exits_84(self):
        code, output, err = capture_output(run_xor, "-c", "zz", False,
                                            b"data\n")
        self.assertEqual(code, 84)
        self.assertIn("invalid key", err)

    def test_empty_key_exits_84(self):
        code, output, _ = capture_output(run_xor, "-c", "", False, b"data\n")
        self.assertEqual(code, 84)

    def test_invalid_ciphered_message_exits_84(self):
        code, output, _ = capture_output(run_xor, "-d", PDF_KEY, False, b"zz\n")
        self.assertEqual(code, 84)


if __name__ == "__main__":
    unittest.main()
