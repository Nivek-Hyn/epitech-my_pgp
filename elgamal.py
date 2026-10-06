##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## elgamal
##

import sys

from rsa import get_hex_from_int, get_int_from_hex


##
## @brief Parse an ElGamal key string into its three integer components.
##
## @param key: the key, "value-prime-generator" in little-endian hex; the
##             public key is "y-p-g", the private key "x-p-g"
##
## @return A (value, prime, generator) tuple
##
## @exception ValueError: wrong number of parts or invalid hexadecimal
##
def parse_elgamal_key(key: str) -> tuple:
    parts = key.split("-")
    if len(parts) != 3:
        raise ValueError("key must be formatted as value-prime-generator.")
    return (get_int_from_hex(parts[0]), get_int_from_hex(parts[1]),
            get_int_from_hex(parts[2]))


##
## @brief Parse a ciphered message into its two integer components.
##
## @param line: the ciphered message, "c1-c2" in little-endian hex
##
## @return A (c1, c2) tuple
##
## @exception ValueError: wrong number of parts or invalid hexadecimal
##
def parse_ciphertext(line: str) -> tuple:
    parts = line.split("-")
    if len(parts) != 2:
        raise ValueError("ciphered message must be formatted as c1-c2.")
    return get_int_from_hex(parts[0]), get_int_from_hex(parts[1])


##
## @brief Cipher a message number with the ElGamal algorithm.
##
## @param m: the message as an integer, must be smaller than p
## @param k: the ephemeral exponent chosen by the sender
## @param y: the public key value, g^x mod p
## @param p: the prime modulus
## @param g: the generator
##
## @return A (c1, c2) tuple, with c1 = g^k mod p and c2 = m * y^k mod p
##
def cipher_elgamal(m: int, k: int, y: int, p: int, g: int) -> tuple:
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return c1, c2


##
## @brief Decipher a ciphered message with the ElGamal algorithm.
##
## Both sides derive the same mask s: c1^x = (g^k)^x = (g^x)^k = y^k mod p,
## so dividing c2 by s recovers the message.
##
## @param c1: the first ciphered component, g^k mod p
## @param c2: the second ciphered component, m * y^k mod p
## @param x: the private exponent
## @param p: the prime modulus
##
## @return The clear message as an integer
##
def decipher_elgamal(c1: int, c2: int, x: int, p: int) -> int:
    s = pow(c1, x, p)
    return (c2 * pow(s, -1, p)) % p


##
## @brief Handle the "-c" mode of the ElGamal cryptosystem.
##
## @param key: the ciphering key, "k:y-p-g" in little-endian hex, where k
##             is the ephemeral exponent and y-p-g the public key
## @param data: the raw message read from the standard input
##
## @return 0 on success, 84 on error
##
def run_elgamal_cipher(key: str, data: bytes = None) -> int:
    parts = key.split(":", maxsplit=1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        print("error: invalid key.", file=sys.stderr)
        return 84

    try:
        k = get_int_from_hex(parts[0])
        y, p, g = parse_elgamal_key(parts[1])
    except ValueError:
        print("error: invalid key.", file=sys.stderr)
        return 84

    if data is None:
        data = sys.stdin.buffer.read()

    if data.endswith(b"\n"):
        data = data[:-1]
    m = int.from_bytes(data, "little")

    if m >= p:
        print("error: message is too big for the modulus.",
              file=sys.stderr)
        return 84

    c1, c2 = cipher_elgamal(m, k, y, p, g)
    print(f"{get_hex_from_int(c1)}-{get_hex_from_int(c2)}")
    return 0


##
## @brief Handle the "-d" mode of the ElGamal cryptosystem.
##
## @param key: the private key, "x-p-g" in little-endian hex
## @param data: the ciphered message read from the standard input, one
##              "c1-c2" line
##
## @return 0 on success, 84 on error
##
def run_elgamal_decipher(key: str, data: bytes = None) -> int:
    try:
        x, p, g = parse_elgamal_key(key)
    except ValueError:
        print("error: invalid ciphered message or key.", file=sys.stderr)
        return 84

    if data is None:
        data = sys.stdin.buffer.read()

    try:
        c1, c2 = parse_ciphertext(data.decode().strip())
        m = decipher_elgamal(c1, c2, x, p)
    except (ValueError, UnicodeDecodeError):
        print("error: invalid ciphered message or key.", file=sys.stderr)
        return 84

    byte_count = (m.bit_length() + 7) // 8
    sys.stdout.buffer.write(m.to_bytes(byte_count, "little") + b"\n")
    return 0


##
## @brief Cipher or decipher a message using the ElGamal algorithm.
##
## @param mode: the mode to run, "-c" to cipher or "-d" to decipher
## @param key: the ElGamal key, see run_elgamal_cipher and
##             run_elgamal_decipher for the expected formats
## @param block: unused, the data to cipher is always read on a single line
## @param data: the raw message read from the standard input
##
## @return 0 on success, 84 on error
##
def run_elgamal(mode: str, key: str, block: bool, data: bytes = None) -> int:
    if mode == "-c":
        return run_elgamal_cipher(key, data)
    if mode == "-d":
        return run_elgamal_decipher(key, data)
    return 0


##
## @brief Generate a public and private ElGamal key pair.
##
## Computes y = g^x mod p from the public parameters p and g and the
## private exponent x. Prints both keys in little-endian hex: the public
## key as "y-p-g" and the private key as "x-p-g".
##
## @param p_hex: the prime modulus, little-endian hex
## @param g_hex: the generator, little-endian hex
## @param x_hex: the private exponent, little-endian hex
##
## @return 0 on success, 84 on error
##
def run_elgamal_generate(p_hex: str, g_hex: str, x_hex: str) -> int:
    try:
        p = get_int_from_hex(p_hex)
        g = get_int_from_hex(g_hex)
        x = get_int_from_hex(x_hex)
        y = pow(g, x, p)
    except ValueError:
        print("error: invalid key parameters.", file=sys.stderr)
        return 84

    print(f"public key: {get_hex_from_int(y)}-"
          f"{get_hex_from_int(p)}-{get_hex_from_int(g)}")
    print(f"private key: {get_hex_from_int(x)}-"
          f"{get_hex_from_int(p)}-{get_hex_from_int(g)}")
    return 0
