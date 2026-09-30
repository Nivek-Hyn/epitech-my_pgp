# XOR

XOR is the simplest symmetric cipher of my_pgp, and the starting point of the
subject: the same key ciphers and deciphers, because applying XOR twice with
the same value cancels out.

```
a ^ a = 0        anything XORed with itself vanishes
a ^ 0 = a        XORing with zero changes nothing

m ^ k = c        cipher
c ^ k = m        decipher, same operation
```

Without the key, a ciphered message reveals nothing: XORing it with a wrong
guess produces noise. XOR is in fact unbreakable when the key is as long as
the message and used only once — the one-time pad. Both conditions are the
problem, and the Limits section comes back to them.

## Byte order

The subject splits data into two natures, and treats them differently:

| Data | Nature per the subject | Consequence |
| --- | --- | --- |
| the message | a sequence of bytes | natural order, untouched |
| the key | a number, little endian | written backwards |
| the ciphered output | a number, little endian | written backwards |

Endianness only exists for numbers, because only a number has bytes of
different weight. A sequence of bytes has no most or least significant end,
so there is no other order it could be in.

The two conventions are opposite, so one side has to be flipped to line the
bytes up. The flip sits on the message side, which is the one that is a
sequence of bytes:

```
cipher    message (bytes) --reverse--> XOR with key --> ciphered (number)
decipher  ciphered (number) --> XOR with key --reverse--> message (bytes)
```

Doing it the other way round would need two reversals — the key and the
output — instead of one.

## Blocks

The key length sets the block size. A message is cut into chunks of that
size, each chunk is XORed with the whole key, and the last chunk is padded
with zeros if it is short.

```
key of 4 bytes, message of 10 bytes

   [ chunk 1: 4 ][ chunk 2: 4 ][ chunk 3: 2 + 2 zeros ]
         ^              ^                ^
      XOR key        XOR key          XOR key

   -> 12 bytes of output
```

With `-b` only the first chunk is treated and the rest is dropped; the subject
guarantees message and key are the same size in that mode. `-b` is therefore
the stream mode with the loop removed, which is why it is the easiest case to
get right first.

## Worked example

```
$ echo "You know nothing, Jon Snow" | ./my_pgp xor -c -b 576861742069732064656164206d6179206e6576657220646965
20070f2700071c6a4449060a490515164e4e12190b190011063c
$ echo "20070f2700071c6a4449060a490515164e4e12190b190011063c" | ./my_pgp xor -d -b 576861742069732064656164206d6179206e6576657220646965
You know nothing, Jon Snow
```

The key decodes to the ASCII text "What is dead may never die" and the message
is 26 bytes, exactly one block. The first output byte is `0x20`, which is
`'w' ^ 'W'`: the *last* letter of the message against the *first* byte of the
key — the reversal at work.

The subject gives no stream-mode example for XOR, so the reading retained here
is that every block is treated exactly like a `-b` block, reversal included.
It is consistent with the one example provided (a single-block message gives
the same result with and without `-b`) and the round trip is stable, but it
cannot be proven against a reference.

## Limits

**A short key repeated is breakable without the key.** Each block reuses the
same key, so bytes at the same offset in different blocks are XORed with the
same key byte. An attacker splits the ciphertext by offset, tries the 256
possible values for each position and keeps the one producing readable text.
A 3-byte key means 3 x 256 tries instead of 16 million — instant. This is how
Vigenère ciphers have been broken since the 19th century, and it works because
text is not random: spaces and the letter e dominate.

**Reusing one key on two messages removes the key from the equation.**

```
c1 ^ c2 = (m1 ^ k) ^ (m2 ^ k) = m1 ^ m2 ^ (k ^ k) = m1 ^ m2
```

The key cancels itself. An attacker who intercepts both ciphertexts obtains
`m1 ^ m2` without ever knowing `k`: every zero byte tells them the two
messages agree at that position, and guessing any fragment of one message
yields the matching fragment of the other. Hence "used only once".

**A key as long as the message is impractical.** Fixing both weaknesses means
a key the size of the message, used once — which needs a secure channel able
to carry as many bytes as the message itself. If such a channel existed, the
message could travel through it directly. This is exactly why AES exists, and
why PGP uses RSA to carry a short symmetric key.

**Identical blocks give identical output.** Even with a full-length key, two
equal plaintext blocks produce two equal ciphered blocks, so repetition in the
message is visible in the ciphertext.

**Zero padding cannot be removed.** Nothing records how many zeros were added
to the last block, so a round trip returns the message followed by them.

**No authentication.** XOR is perfectly malleable: flipping a bit of the
ciphertext flips exactly the same bit of the deciphered message, with no way
to detect it. An attacker who cannot read the message can still modify it in a
controlled way.
