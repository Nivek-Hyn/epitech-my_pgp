# RSA

RSA is the asymmetric part of my_pgp. Two keys are derived from two prime
numbers: a public key that anyone can use to cipher a message, and a private
key that reverses the operation. Knowing the public key does not reveal the
private one — the gap between the two rests on the difficulty of factoring a
large number into its two primes.

## Key generation (`rsa -g P Q`)

```
P, Q (primes given on the command line)
        |
        v
   n = P * Q                    the modulus, part of both keys
   lambda = lcm(P - 1, Q - 1)   Carmichael's totient of n
        |
        v
   e = biggest Fermat prime (65537, 257, 17, 5, 3)
       with 1 < e < lambda and gcd(e, lambda) = 1
        |
        v
   d = e^-1 mod lambda          the modular inverse of e
        |
   +----+--------------------+
   |                         |
   v                         v
public key: e-n         private key: d-n
(give it out)           (keep it secret)
```

Why lcm(P-1, Q-1): exponentiation mod P cycles with a period that divides
P-1, and likewise mod Q with Q-1. An exponent that is a multiple of both
cycles resets any message to itself mod n, and the smallest such exponent is
lcm(P-1, Q-1). Since e*d = 1 + k*lambda, raising to e then to d gives
m^(e*d) = m * (m^lambda)^k = m mod n.

The subject mandates Fermat primes for e. They are prime (so the coprimality
check is a single gcd), and their binary form 1000...0001 makes the
sender-side exponentiation cheap: 16 squarings and 2 multiplications for
65537. 65537 is also the de facto standard in TLS and PGP.

## Ciphering and deciphering

```
   clear message (one line of bytes)
        |
        v
   m = the message bytes read as a little-endian number
        |
        v
   c = m^e mod n                    (rsa -c with the public key)
        |
        v
   c printed as little-endian hex
        |
        v
   m = c^d mod n                    (rsa -d with the private key)
        |
        v
   m written back as little-endian bytes
```

The two directions use the same formula, only the exponent changes. The
public key ciphers what only the private key can read, and the private key
ciphers what everyone can verify with the public one — the latter is what
signatures are made of.

Worked example, with the small keys from the subject:

```
$ ./my_pgp rsa -g d3 e3
public key: 0101-19bb
private key: 9d5b-19bb

p = 0xd3 = 211, q = 0xe3 = 227
n = 211 * 227 = 47897 = 0xbb19 -> "19bb" (little endian)
lambda = lcm(210, 226) = 23730
e = 257 (65537 is bigger than lambda, 257 works)
d = 257^-1 mod 23730 = 23453 = 0x5b9d -> "9d5b"

$ echo "WF" | ./my_pgp rsa -c 0101-19bb
8f84
$ echo "8f84" | ./my_pgp rsa -d 9d5b-19bb
WF
```

## Limits

**m must be smaller than n.** RSA ciphers one number modulo n; anything
larger gets silently reduced and cannot be recovered. A message is therefore
capped at the size of the modulus, and RSA is slow on top of that. This is
why PGP exists: the hybrid modes cipher the message with XOR or AES and use
RSA only to protect the short symmetric key.

**No padding, so it is deterministic.** This project implements textbook
RSA: the same message under the same key always produces the same
ciphertext. An observer can see when the same message is sent twice, and
short message spaces (yes/no, a date, a name) can be brute forced by
ciphering every candidate and comparing. Real RSA uses padding schemes
(OAEP) that inject randomness before the modular exponentiation.

**Leading zero bytes disappear.** The message is converted to a number
before exponentiation, and numbers do not remember leading zeros. A
message starting with a 0x00 byte loses that byte on the round trip. The
same applies to the symmetric key in the PGP modes.

**It is malleable.** Without integrity checks, anyone can modify a
ciphertext in a predictable way: multiplying c by 2^e mod n produces the
ciphering of 2m. Encryption without authentication lets an attacker alter
content even when they cannot read it. Signatures are the usual answer.

**Small messages with small exponents wrap nothing.** If m^e is smaller
than n, no modular reduction happens at all and recovering m is just an
integer e-th root. This is another thing padding prevents, by scrambling
small messages into full-size numbers.

**Security is exactly as hard as factoring n.** Whoever factors n back into
P and Q recomputes lambda and then d, and reads everything. The 256-bit
primes from the appendix give a 512-bit modulus, which is breakable on a
laptop in hours; real deployments use 2048-bit moduli or more. The prime
inputs here are given, not generated, so key quality is out of this
program's hands (random prime generation is one of the suggested bonus
features).
