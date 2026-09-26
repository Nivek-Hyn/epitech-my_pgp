# ElGamal

ElGamal is the second asymmetric cryptosystem of my_pgp (bonus, subject page
9). Like RSA it lets anyone cipher with a public key what only the private
key can read, but it rests on a different hard problem: the discrete
logarithm. Computing g^x mod p from x is fast; recovering x from g^x mod p
is, for a large prime p, infeasible.

Unlike the RSA mode, ElGamal is randomized: ciphering the same message
twice gives two different ciphertexts, because the sender picks a fresh
ephemeral exponent k each time.

## Key generation (`elgamal -g p g x`)

```
p, g, x (prime, generator, private exponent)
        |
        v
   y = g^x mod p
        |
   +----+---------------------+
   |                          |
   v                          v
public key: y-p-g        private key: x-p-g
(give it out)           (keep it secret)
```

p and g are public parameters shared by both keys, exactly like n is shared
by the RSA keys. x is the secret, y is its masked form.

## Ciphering and deciphering

```
   clear message (one line of bytes)
        |
        v
   m = the message bytes read as a little-endian number (m < p)
        |
        v                    ciphering, with key k:y-p-g
   c1 = g^k mod p
   c2 = m * y^k mod p
        |
        v
   "c1-c2" printed as little-endian hex
        |
        v                    deciphering, with key x-p-g
   s  = c1^x mod p          same value as y^k, see below
   m  = c2 * s^-1 mod p
        |
        v
   m written back as little-endian bytes
```

Both sides reach the same mask s because exponents commute:

    c1^x = (g^k)^x = g^(k*x) = (g^x)^k = y^k    (all mod p)

so the sender hides m under y^k and the receiver pulls the same cover off
with c1^x. c1 is the "letter" g^k that lets the receiver recompute the mask,
c2 is the masked message.

Worked example, small enough to check by hand:

```
$ ./my_pgp elgamal -g 17 05 07
public key: 11-17-05
private key: 07-17-05

p = 23, g = 5, x = 7, y = 5^7 mod 23 = 17

$ printf '\x02' | ./my_pgp elgamal -c 03:11-17-05
0a-05
$ echo "0a-05" | ./my_pgp elgamal -d 07-17-05
<0x02>
```

c1 = 5^3 mod 23 = 10 = 0x0a, c2 = 2 * 17^3 mod 23 = 5 = 0x05. On decipher,
s = 10^7 mod 23 = 14, and 2 = 5 * 14^-1 mod 23.

## Where k comes from

Real ElGamal draws k at random for every message. This program takes it as
a parameter (`k:y-p-g`, mirroring the PGP `SYMMETRIC_KEY:RSA_KEY`
convention) so that outputs are deterministic and testable, the same trade
the subject makes everywhere else with its "random" keys.

## Limits

**k must never be reused.** Two messages ciphered with the same k leak the
ratio of their plaintexts: c2/c2' = m/m' mod p, and if one message is ever
guessed, the other falls with it. Real implementations generate k freshly
and never reuse it; taking it as a parameter makes reuse a caller error,
which is why this trade deserves its warning.

**m must be smaller than p.** Same constraint as RSA's m < n, checked
explicitly here: the program exits 84 instead of silently ciphering a
reduced value. As with RSA, this is why the hybrid PGP modes exist.

**No padding, but randomized anyway.** The random k already breaks the
determinism that makes textbook RSA observable (the same message twice gives
different ciphertexts). But ElGamal ciphertexts are still malleable:
multiplying c2 by t produces the ciphering of t*m, with no way to detect the
tampering.

**No e/d symmetry.** RSA's exponents are mutual inverses, which is what
would make signing free. ElGamal ciphering and deciphering are not inverse
operations of each other, so signing requires the separate ElGamal
signature scheme (not implemented here).

**Security is exactly as hard as discrete log mod p.** The 256-bit prime
from the appendix gives a toy-scale group; real deployments use 2048-bit
primes or more. p is assumed prime and g assumed a generator, in the same
spirit as the subject's "you may assume the numbers given with -g are
prime".

**Leading zero bytes disappear** on the round trip, same as RSA: numbers
do not remember leading zeros.
