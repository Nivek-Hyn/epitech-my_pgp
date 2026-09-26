##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## rsa
##
import sys

from math import lcm, gcd

## The Fermat primes, from the biggest to the smallest. The public exponent
## is the biggest one that satisfies the algorithm requirements.
FERMAT_PRIMES = [65537, 257, 17, 5, 3]


##
## @brief Cipher or decipher a message using the RSA algorithm.
##
## @param mode: the mode to run, "-c" to cipher or "-d" to decipher
## @param key: the RSA key, "exponent-modulus" in little-endian hex; the
##             public key (e-n) to cipher, the private key (d-n) to decipher
## @param block: unused, the data to cipher is always read on a single line
## @param data: the raw message read from the standard input
##
## @return 0 on success, 84 on error
##
def run_rsa(mode: str, key: str, block: bool, data: bytes) -> int:
    try:
        exponent, modulus = parse_key(key)
    except ValueError:
        print("error: invalid key.", file=sys.stderr)
        return 84

    if mode == "-c":
        if data.endswith(b"\n"):
            data = data[:-1]
        m = int.from_bytes(data, "little")
        c = pow(m, exponent, modulus)
        print(get_hex_from_int(c))
        return 0

    if mode == "-d":
        try:
            c = get_int_from_hex(data.decode().strip())
        except (ValueError, UnicodeDecodeError):
            print("error: invalid ciphered message.", file=sys.stderr)
            return 84
        m = pow(c, exponent, modulus)
        byte_count = (m.bit_length() + 7) // 8
        sys.stdout.buffer.write(m.to_bytes(byte_count, "little") + b"\n")
        return 0

    return 0


##
## @brief Parse an RSA key string into its two integer components.
##
## @param key: the key, "exponent-modulus" in little-endian hex
##
## @return An (exponent, modulus) tuple
##
## @exception ValueError: wrong number of parts or invalid hexadecimal
##
def parse_key(key: str) -> tuple:
    parts = key.split("-")
    if len(parts) != 2:
        raise ValueError("key must be formatted as exponent-modulus.")
    return get_int_from_hex(parts[0]), get_int_from_hex(parts[1])


##
## @brief Convert a little-endian hexadecimal string into an integer.
##
## @param hex_str: the hexadecimal string; its lowest byte comes first
##
## @return The integer value encoded by the string
##
## @exception ValueError: odd-length or non-hexadecimal string
##
def get_int_from_hex(hex_str: str) -> int:
    return int.from_bytes(bytes.fromhex(hex_str), "little")


##
## @brief Convert an integer into a little-endian hexadecimal string.
##
## @param value: the integer to convert
##
## @return The hexadecimal representation, lowest byte first; empty for 0
##
def get_hex_from_int(value: int) -> str:
    byte_count = (value.bit_length() + 7) // 8
    return value.to_bytes(byte_count, "little").hex()


##
## @brief Generate a public and private RSA key pair from two primes.
##
## Computes n = p*q, Carmichael's totient lambda(n) = lcm(p-1, q-1),
## the public exponent e as the biggest Fermat prime with 1 < e < lambda(n)
## and gcd(e, lambda(n)) = 1, and the private exponent d = e^-1 mod
## lambda(n). Prints both keys as "exponent-n" in little-endian hex.
##
## @param p_hex: the first prime, little-endian hex
## @param q_hex: the second prime, little-endian hex
##
## @return 0 on success, 84 on error
##
def run_rsa_generate(p_hex: str, q_hex: str) -> int:
    try:
        p_int = get_int_from_hex(p_hex)
        q_int = get_int_from_hex(q_hex)
    except ValueError:
        print("error: invalid prime numbers given.", file=sys.stderr)
        return 84

    n = p_int * q_int
    lambda_n = lcm(p_int - 1, q_int - 1)

    e = next(candidate for candidate in FERMAT_PRIMES
             if candidate < lambda_n and gcd(candidate, lambda_n) == 1)

    d = pow(e, -1, lambda_n)

    print(f"public key: {get_hex_from_int(e)}-{get_hex_from_int(n)}")
    print(f"private key: {get_hex_from_int(d)}-{get_hex_from_int(n)}")
    return 0
