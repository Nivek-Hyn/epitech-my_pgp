# my_pgp

A PGP-like cryptographic toolbox: several cipher systems behind a single
command line, from a one-time-pad XOR to the hybrid construction that gives
PGP its name — a symmetric cipher for the message, RSA to protect the key.

Built for the Epitech project G-CNA-500 (my_pgp).

## Crypto systems

| System | Kind | Status |
|---|---|---|
| `xor` | symmetric | done |
| `rsa` | asymmetric | done |
| `pgp-xor` | hybrid (RSA + XOR) | done |
| `elgamal` | asymmetric (bonus) | done |
| `aes` | symmetric | in progress |
| `pgp-aes` | hybrid (RSA + AES) | blocked on aes |

## Build and run

```
make            # builds ./my_pgp
make tests      # runs the 73 unit and integration tests
make clean      # removes caches
make fclean     # also removes the binary
```

Examples (all numbers are hexadecimal, little-endian):

```
$ ./my_pgp -h
$ ./my_pgp rsa -g d3 e3
public key: 0101-19bb
private key: 9d5b-19bb
$ echo "WF" | ./my_pgp rsa -c 0101-19bb
8f84
$ echo "8f84" | ./my_pgp rsa -d 9d5b-19bb
WF
$ echo "All men must die" | ./my_pgp pgp-xor -c -b 57696e74657220697320636f6d696e67:0101-...-...fb3
$ ./my_pgp elgamal -g 17 05 07
public key: 11-17-05
private key: 07-17-05
```

The message is always read on the standard input; the key comes as an
argument. See `./my_pgp -h` for the full usage.

## Architecture

```mermaid
flowchart TD
    CLI["./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]"]
    CLI --> MAIN["main.py — argument parsing and dispatch"]

    MAIN -->|xor| XOR["xor.py"]
    MAIN -->|aes| AES["aes.py (in progress)"]
    MAIN -->|rsa| RSA["rsa.py"]
    MAIN -->|elgamal| EG["elgamal.py (bonus)"]
    MAIN -->|pgp-xor / pgp-aes| PGP["pgp.py"]

    PGP -->|"symmetric key transport (RSA)"| RSA
    PGP -->|"message (pgp-xor)"| XOR
    PGP -.->|"message (pgp-aes)"| AES

    style AES stroke-dasharray: 5 5
    style EG stroke-dasharray: 5 5
```

Each system is one module with the same entry point signature
(`run_*(mode, key, block, data)`), dispatched by `main.py`. The PGP modes
are a single routine parameterized by the symmetric engine: cipher the
message with the symmetric key, cipher the symmetric key with the
recipient's RSA public key, print the ciphered key then the ciphered
message.

## Numbers

All numbers in arguments and outputs are hexadecimal in little-endian byte
order: the lowest byte comes first. `"19bb"` is 0xBB19 = 47897. The message
itself is a sequence of bytes, read as a little-endian number when an
algorithm needs a number.

## Tests and documentation

- `make tests` — 73 tests, including every example of the subject as a
  fixed vector.
- `docs/RSA.md`, `docs/ELGAMAL.md` — how each asymmetric algorithm works
  and its limits.
- `BONUS.md` — what was done beyond the mandatory scope.

## Authors

- Hugo Sorgues — RSA, pgp-xor, ElGamal, test suite, documentation
- Kévin Huynh — XOR, AES
