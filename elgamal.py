##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## elgamal
##

import sys

from rsa import get_hex_from_int, get_int_from_hex


def parse_elgamal_key(key: str) -> tuple:
    parts = key.split("-")
    if len(parts) != 3:
        raise ValueError("key must be formatted as value-prime-generator.")
    return (get_int_from_hex(parts[0]), get_int_from_hex(parts[1]),
            get_int_from_hex(parts[2]))


def parse_ciphertext(line: str) -> tuple:
    parts = line.split("-")
    if len(parts) != 2:
        raise ValueError("ciphered message must be formatted as c1-c2.")
    return get_int_from_hex(parts[0]), get_int_from_hex(parts[1])


def run_elgamal(mode: str, key: str, block: bool, data: bytes) -> int:
    if mode == "-c":
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

        if data.endswith(b"\n"):
            data = data[:-1]
        m = int.from_bytes(data, "little")

        if m >= p:
            print("error: message is too big for the modulus.",
                  file=sys.stderr)
            return 84

        c1 = pow(g, k, p)
        c2 = (m * pow(y, k, p)) % p
        print(f"{get_hex_from_int(c1)}-{get_hex_from_int(c2)}")
        return 0

    if mode == "-d":
        try:
            x, p, g = parse_elgamal_key(key)
            c1, c2 = parse_ciphertext(data.decode().strip())
            s = pow(c1, x, p)
            m = (c2 * pow(s, -1, p)) % p
        except (ValueError, UnicodeDecodeError):
            print("error: invalid ciphered message or key.", file=sys.stderr)
            return 84

        byte_count = (m.bit_length() + 7) // 8
        sys.stdout.buffer.write(m.to_bytes(byte_count, "little") + b"\n")
        return 0

    return 0


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
