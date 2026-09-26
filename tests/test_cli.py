##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## integration tests running the ./my_pgp binary
##

import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from util import REPO_ROOT

BINARY = os.path.join(REPO_ROOT, "my_pgp")

# Vectors from the subject, pages 5, 8 and 11.
XOR_KEY = "576861742069732064656164206d6179206e6576657220646965"
XOR_MESSAGE = b"You know nothing, Jon Snow\n"
XOR_CIPHERED = b"20070f2700071c6a4449060a490515164e4e12190b190011063c\n"

SYMMETRIC_KEY = "57696e74657220697320636f6d696e67"
N_256 = ("c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de"
         "139a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3")
D_256 = ("81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e56a1"
         "1d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3e209")
CIPHERED_SYM_KEY = ("97f2af4c1b712008c1e46935f446756443a8a700f20581d138e4e691"
                    "6afe5c5f9b9d6eaa0a870374b686f1a024f9bbb88c23c7666545793"
                    "39caf55afd149d41d")
PGP_MESSAGE = b"All men must die\n"
PGP_CIPHERED = (CIPHERED_SYM_KEY + "\n"
                + "32000a5411015504534e06024d050226" + "\n").encode()


def run_pgp(*args, data=b""):
    return subprocess.run([BINARY, *args], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def setUpModule():
    subprocess.run(["make"], cwd=REPO_ROOT, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True)


class TestUsage(unittest.TestCase):

    def test_help_exits_0_and_prints_usage(self):
        result = run_pgp("-h")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith(b"USAGE"))

    def test_no_arguments_exits_84(self):
        result = run_pgp()
        self.assertEqual(result.returncode, 84)


class TestArgumentErrors(unittest.TestCase):

    def test_unknown_crypto_system_exits_84(self):
        result = run_pgp("bad", "-c", "00", data=b"data\n")
        self.assertEqual(result.returncode, 84)
        self.assertNotEqual(result.stderr, b"")

    def test_unknown_mode_exits_84(self):
        result = run_pgp("xor", "-x", XOR_KEY, data=b"data\n")
        self.assertEqual(result.returncode, 84)

    def test_missing_key_exits_84(self):
        result = run_pgp("xor", "-c", data=b"data\n")
        self.assertEqual(result.returncode, 84)

    def test_unknown_option_exits_84(self):
        result = run_pgp("xor", "-c", "-z", XOR_KEY, data=b"data\n")
        self.assertEqual(result.returncode, 84)

    def test_generate_is_rsa_only(self):
        result = run_pgp("xor", "-g", "d3", "e3")
        self.assertEqual(result.returncode, 84)

    def test_generate_requires_two_primes(self):
        result = run_pgp("rsa", "-g", "d3")
        self.assertEqual(result.returncode, 84)


class TestXorCli(unittest.TestCase):

    def test_block_cipher_matches_the_subject(self):
        result = run_pgp("xor", "-c", "-b", XOR_KEY, data=XOR_MESSAGE)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, XOR_CIPHERED)

    def test_block_decipher_matches_the_subject(self):
        result = run_pgp("xor", "-d", "-b", XOR_KEY, data=XOR_CIPHERED)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, XOR_MESSAGE)


class TestRsaCli(unittest.TestCase):

    def test_generate_small_keys(self):
        result = run_pgp("rsa", "-g", "d3", "e3")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout,
                         b"public key: 0101-19bb\nprivate key: 9d5b-19bb\n")

    def test_cipher_then_decipher(self):
        ciphered = run_pgp("rsa", "-c", "0101-19bb", data=b"WF\n")
        self.assertEqual(ciphered.stdout, b"8f84\n")

        deciphered = run_pgp("rsa", "-d", "9d5b-19bb", data=ciphered.stdout)
        self.assertEqual(deciphered.returncode, 0)
        self.assertEqual(deciphered.stdout, b"WF\n")


class TestPgpXorCli(unittest.TestCase):
    def test_cipher_block_mode(self):
        result = run_pgp("pgp-xor", "-c", "-b",
                         f"{SYMMETRIC_KEY}:010001-{N_256}", data=PGP_MESSAGE)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, PGP_CIPHERED)

    def test_decipher_block_mode(self):
        result = run_pgp("pgp-xor", "-d", "-b",
                         f"{CIPHERED_SYM_KEY}:{D_256}-{N_256}",
                         data=b"32000a5411015504534e06024d050226\n")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, PGP_MESSAGE)


class TestElgamalCli(unittest.TestCase):

    def test_help_lists_elgamal(self):
        result = run_pgp("-h")
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"elgamal", result.stdout)

    def test_generate_matches_hand_computed_vector(self):
        result = run_pgp("elgamal", "-g", "17", "05", "07")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout,
                         b"public key: 11-17-05\nprivate key: 07-17-05\n")

    def test_generate_requires_three_operands(self):
        result = run_pgp("elgamal", "-g", "17", "05")
        self.assertEqual(result.returncode, 84)

    def test_cipher_then_decipher(self):
        ciphered = run_pgp("elgamal", "-c", "03:11-17-05", data=b"\x02\n")
        self.assertEqual(ciphered.returncode, 0)
        self.assertEqual(ciphered.stdout, b"0a-05\n")

        deciphered = run_pgp("elgamal", "-d", "07-17-05",
                             data=ciphered.stdout)
        self.assertEqual(deciphered.returncode, 0)
        self.assertEqual(deciphered.stdout, b"\x02\n")

    def test_message_too_big_exits_84(self):
        result = run_pgp("elgamal", "-c", "03:11-17-05",
                         data=b"\xff" * 23)
        self.assertEqual(result.returncode, 84)

    def test_rsa_generate_still_rejects_three_operands(self):
        result = run_pgp("rsa", "-g", "d3", "e3", "e9")
        self.assertEqual(result.returncode, 84)


if __name__ == "__main__":
    unittest.main()
