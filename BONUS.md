# Bonus

Work done on my_pgp that goes beyond the mandatory scope of the subject.

## Second asymmetric cryptosystem: ElGamal

The subject asks (page 9) for a second asymmetric cryptosystem, marked as a
"should". `elgamal.py` implements it end to end:

- key generation (`elgamal -g p g x`), ciphering (`elgamal -c k:y-p-g`)
  and deciphering (`elgamal -d x-p-g`), built on the discrete logarithm
  problem;
- unlike RSA, the mode is randomized: the ephemeral exponent k is part of
  the key parameter (same trade as the subject's "random" PGP key), so
  ciphering the same message twice with two different k values gives two
  different ciphertexts;
- an explicit check that the message fits the modulus (m < p): instead of
  silently ciphering a reduced number, the program reports an error and
  exits 84;
- CLI integration: `-g` accepts three operands for elgamal, two for rsa,
  and the usage text lists the new system.

## AES-192 and AES-256

The subject requires AES-128 and marks the two larger key sizes as a
"should". `aes.py` implements all three:

- the key expansion derives everything from the key length — 4, 6 or 8 words
  of key give 10, 12 or 14 rounds, hence 11, 13 or 15 round keys — and the
  round loop reads the count from the round keys, so one code path serves the
  three variants;
- AES-256 gets the extra s-box substitution its longer key schedule requires,
  halfway through each group of 8 words;
- each variant is checked against its reference vector from FIPS-197
  appendix C, ciphering and deciphering.

## Test suite

Not required by the subject. 120 unit and integration tests, run with
`make tests` (a dedicated Makefile rule):

- `tests/test_xor.py`, `tests/test_aes.py`, `tests/test_rsa.py`,
  `tests/test_pgp.py`, `tests/test_elgamal.py` — unit tests importing the
  modules directly, including every example of the subject as a fixed vector;
- the AES module is also checked against the official FIPS-197 vectors: the
  key expansion of appendix A.1, the ciphered block of appendix B, and one
  vector per key size from appendix C;
- `tests/test_cli.py` — integration tests building the binary and running
  `./my_pgp` as a real process: usage, argument errors, exit codes and
  exact outputs;
- randomized round-trips with fixed seeds, plus algebraic checks for
  ElGamal (c1 = g^k mod p, c2 = m * y^k mod p).

## Documentation

- Doxygen-like documentation blocks (`@brief`, `@param`, `@return`,
  `@exception`) above every function of `rsa.py`, `elgamal.py`, `aes.py` and
  `xor.py`;
- `docs/RSA.md`, `docs/ELGAMAL.md`, `docs/AES.md` and `docs/XOR.md`: how each
  algorithm works, diagrams of the pipelines, worked examples from the
  subject, and their limits (padding, malleability, key sizes, block mode,
  key reuse).

## Tooling

- `make tests` builds the binary if needed and runs the whole suite;
- `make clean` also removes the test caches.
