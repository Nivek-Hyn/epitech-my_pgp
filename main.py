##
## EPITECH PROJECT, 2026
## G-CNA-500-MAR-5-1-mypgp-8
## File description:
## main
##

import sys

SYSTEMS = {"xor", "aes", "rsa", "pgp-xor", "pgp-aes"}

USAGE = """USAGE
     ./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]

DESCRIPTION
Cipher or decipher MESSAGE using a given CRYPTO_SYSTEM. The MESSAGE is read from the standard input.

     CRYPTO_SYSTEM
        "xor"            computation using XOR algorithm
        "aes"            computation using AES algorithm
        "rsa"            computation using RSA algorithm
        "pgp-xor"        computation using both RSA and XOR algorithm
        "pgp-aes"        computation using both RSA and AES algorithm

     MODE
        -c               MESSAGE is clear and we want to cipher it
        -d               MESSAGE is ciphered and we want to decipher it
        -g P Q           RSA only: don't read a MESSAGE, but instead generate a public and private key
        pair from the prime number P and Q

     OPTIONS
        -b               for XOR, AES and PGP, only works on one block. The MESSAGE and the symmetric
        key must be the same size

     key                Key used to cipher/decipher MESSAGE (incompatible with -g MODE)"""

def help():
    print(USAGE)

def main(argv: list[str]) -> int:
    if len(argv) < 2:
        help()
        return 84

    if argv[1] == "-h":
        help()
        return 0

    if argv[1] not in SYSTEMS:
        print("error: Invalid argument.", file=sys.stderr)
        return 84

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
