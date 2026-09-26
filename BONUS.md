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

## Test suite

Not required by the subject. 73 unit and integration tests, run with
`make tests` (a dedicated Makefile rule):

- `tests/test_xor.py`, `tests/test_rsa.py`, `tests/test_pgp.py`,
  `tests/test_elgamal.py` — unit tests importing the modules directly,
  including every example of the subject as a fixed vector;
- `tests/test_cli.py` — integration tests building the binary and running
  `./my_pgp` as a real process: usage, argument errors, exit codes and
  exact outputs;
- randomized round-trips with fixed seeds, plus algebraic checks for
  ElGamal (c1 = g^k mod p, c2 = m * y^k mod p).

## Documentation

- Doxygen-like documentation blocks (`@brief`, `@param`, `@return`,
  `@exception`) above every function of `rsa.py` and `elgamal.py`;
- `docs/RSA.md` and `docs/ELGAMAL.md`: how each algorithm works, diagrams
  of the pipelines, worked examples from the subject, and their limits
  (padding, malleability, key sizes).

## Tooling

- `make tests` builds the binary if needed and runs the whole suite;
- `make clean` also removes the test caches.
