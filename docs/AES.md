# AES

AES is the practical symmetric cipher of my_pgp. Unlike XOR it needs only a
short key — 16 bytes here — and still resists frequency analysis, because it
brews the block through ten rounds of substitution and mixing instead of
combining each byte with the key once. This implementation covers AES-128.

The goal of those rounds is the avalanche effect: every one of the 16 output
bytes depends on all 16 input bytes and on the whole key. Flip one bit of the
message and the entire ciphered block changes.

## The state

A block is 16 bytes, laid out in a 4x4 matrix, filled column by column as the
subject requires.

```
bytes:  b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15

state:   b0  b4  b8  b12        state[row][col] = block[col * 4 + row]
         b1  b5  b9  b13
         b2  b6  b10 b14
         b3  b7  b11 b15
```

The 2D shape is what allows mixing in two directions: ShiftRows works across
columns, MixColumns works inside them. A flat list could do neither.

A group of 4 bytes is called a word, and a word is exactly one column.

## The four operations

| Operation | What it does | Why it is there |
| --- | --- | --- |
| SubBytes | replaces each byte through the 256-entry s-box | the only non-linear step; without it the whole cipher is a solvable linear system |
| ShiftRows | rotates row n left by n positions | carries information between columns |
| MixColumns | replaces each column by a combination of its 4 bytes | carries information inside a column |
| AddRoundKey | XORs the state with a round key | injects the secret |

Only AddRoundKey uses the key. The s-box, the row shifts and the mixing matrix
are public and identical in every AES implementation, so anyone can undo them.
The three mixing steps exist to make that single XOR impossible to attack.

## The rounds

```
AddRoundKey(round key 0)          before the first round

rounds 1 to 9:
    SubBytes
    ShiftRows
    MixColumns
    AddRoundKey(round key n)

round 10:
    SubBytes
    ShiftRows
    AddRoundKey(round key 10)     no MixColumns here
```

Ten rounds, eleven key additions. The initial AddRoundKey matters: without it
the first operation on the message would be public, so the first round would
protect nothing.

The final round drops MixColumns on purpose. Being public, invertible and the
last mixing step before the output, an attacker holding the ciphertext could
peel it off alone — it adds no security. Omitting it also makes the decipher
path structurally symmetric with the cipher path.

Deciphering walks the same steps backwards with InvSubBytes, InvShiftRows and
the inverse mixing matrix, from round key 10 down to round key 0.

## GF(2^8): why the multiplication is unusual

MixColumns needs `2 x a0 + 3 x a1 + 1 x a2 + 1 x a3` over bytes, so it needs a
multiplication that keeps results inside one byte and stays reversible.
Ordinary multiplication truncated to 8 bits fails the second condition:

```
plain multiplication mod 256        GF(2^8) multiplication
   0x00 * 2 = 0x00                     0x00 * 2 = 0x00
   0x80 * 2 = 0x00   collision         0x80 * 2 = 0x1b
   128 distinct results out of 256     256 distinct results out of 256
```

Half of the values vanish, so the operation cannot be undone and the block
cannot be deciphered.

GF(2^8) is the arithmetic that avoids this. Addition is XOR, and doubling
shifts left then *folds* the overflowing bit back with a XOR of `0x1b` instead
of dropping it. Nothing is lost, only moved. `0x1b` is the reduction constant
chosen by the standard (the polynomial x^8 + x^4 + x^3 + x + 1).

`xtime` doubles, `gf_mul` multiplies by anything by doubling and adding, one
bit of the multiplier at a time.

## Key expansion

One 16-byte key becomes eleven round keys, 44 words in total.

```
words 0..3   = the key itself
word i       = word (i - 4)  XOR  f(word (i - 1))

f is the identity, except every 4th word where it is:
    rotate the word left by one byte
    substitute each byte through the s-box
    XOR the round constant into the first byte

round constants: 01 02 04 08 10 20 40 80 1b 36
                 (0x01 doubled in GF(2^8), hence the 1b)
```

Word `i - 4` sits at the same position in the previous round key, so each
round key is derived from the one before it, and therefore from the real key.
Flip one bit of the key and all eleven round keys change.

Reusing the same key eleven times would hand an attacker the repetition that
breaks XOR. The rotation, the s-box and a different constant per round are
what guarantee the eleven keys share no pattern.

## Byte order

The subject states that the key and the ciphered output are numbers written in
little endian, and its example is a 32-bit integer. For AES this applies per
word: **each group of 4 bytes is stored backwards**, not the 16 bytes as a
whole. The message stays in its natural order, being a sequence of bytes.

```
key as written:  57696e74 65722069 7320636f 6d696e67
key AES uses:    746e6957 69207265 6f632073 676e696d
```

This was established by testing every plausible reordering against the only
AES example in the subject; a single combination reproduces it, in both
directions. `reverse_words` applies it at the edges of `run_aes`, so the
cipher itself never knows the convention exists.

## Worked example

```
$ echo "All men must die" | ./my_pgp aes -c -b 57696e74657220697320636f6d696e67
744ce22c385958348f0df26eceb62eef
$ echo "744ce22c385958348f0df26eceb62eef" | ./my_pgp aes -d -b 57696e74657220697320636f6d696e67
All men must die
```

Without `-b` the message is cut into 16-byte blocks and the last one is padded
with zeros. Note that the AES block is always 16 bytes; it happens to equal
the key size in AES-128 only.

The unit tests also check the module against FIPS-197: the key expansion of
appendix A.1 and the ciphered block of appendix B.

## Limits

**Blocks are ciphered independently (ECB).** Two identical plaintext blocks
give two identical ciphered blocks, so structure leaks even though the bytes
are unreadable. Real deployments chain blocks (CBC) or derive a per-block
counter (CTR) so that repetition disappears.

**Zero padding cannot be removed.** The last block is completed with zeros at
cipher time and nothing records how many were added, so a round trip returns
the message followed by those zeros, and a message genuinely ending with 0x00
is ambiguous. A real scheme such as PKCS#7 encodes the padding length.

**No authentication.** The ciphertext carries no integrity check, so an
attacker who cannot read it can still alter it and the deciphering will
happily produce garbage instead of failing. Modern modes authenticate
(AES-GCM), and signing is one of the suggested bonus features.

**AES-128 only.** AES-192 and AES-256 need a longer key schedule and 12 or 14
rounds; the round loop and the expansion are hardcoded for 10 rounds and 44
words.

**Not constant-time.** The s-box lookups and the branch inside `xtime` take a
time that depends on the data, which leaks information through cache and
timing measurements. Production implementations use bitsliced code or the
AES-NI processor instructions to avoid it. Irrelevant here, worth knowing.
