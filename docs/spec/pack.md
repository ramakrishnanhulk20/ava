# Ava packs: the bytes of an encrypted pack

A pack is one file a chair posts to a board. The chain records its SHA-256, its size, its epoch and
the time, and nothing else: no name, no type, no link. Everything a reader needs beyond that travels
inside the encrypted bytes. This page is the single source for those bytes. The code is
`packages/core/src/seal.ts` (the encryption) and `packages/web/lib/pack/format.ts` (the container).

## Layers

```
stored blob   = nonce (12) || AES-256-GCM ciphertext || tag (16)
plaintext     = container, or a bare file
container     = magic (8) || header length (2, big-endian) || header (JSON) || the file's bytes
```

The stored blob is what is uploaded, what `cipherHash` and `cipherSize` on chain describe, and what
a reader downloads. It is at most 26,214,400 bytes (25 MiB) and at least 28.

## Encryption

| Part | Value |
|---|---|
| Cipher | AES-256-GCM, 12-byte random nonce, 16-byte tag |
| Key | HKDF-SHA-256 with the epoch key (32 bytes) as input, `docRef` as salt, and `"ava-doc-v1" \|\| place \|\| epoch` as info |
| Additional data | `place \|\| epoch \|\| docRef` |
| `place` | `sha256(registry address (20 bytes) \|\| boardRef (32 bytes))` |
| `epoch` | 8 bytes, big-endian |
| `docRef` | 32 random bytes the chair's browser picks before encrypting, recorded on chain with the pack |

Each pack has its own key, so two devices of one chair never reuse a key and nonce pair. Because the
board, the epoch and the pack's own reference are all bound into the key and the additional data, a
ciphertext moved to another pack, epoch, board or registry does not decrypt.

A reader checks, in this order, before any key is used: the blob is exactly `cipherSize` bytes, then
its SHA-256 equals `cipherHash`. Both come from the registry's record of the pack.

## The container

```
41 56 41 50 41 43 4b 01      "AVAPACK" and the format version, 1
hh hh                        header length in bytes, big-endian, 2 to 1,300
{"name":"minutes.txt"}       the header: UTF-8 JSON, one object with one string field, name
...                          the file's own bytes, unchanged
```

- The name is cleaned before it is stored and again when it is read: the last path part only, no
  control characters, no direction or zero-width marks, none of `< > : " | ? *`, no leading or
  trailing dots or spaces, at most 200 bytes of UTF-8. Letters of any script are kept.
- A header that is cut short, longer than 1,300 bytes, not valid UTF-8 JSON, or not an object with a
  string `name` is an error. Nothing is guessed from it.
- Plaintext that does not start with the 8 magic bytes is a bare file with no name. The demo board's
  packs, which our server writes, are bare UTF-8 text.

## What a reader may do with the file

Decided from the file's bytes alone, never from its name:

| The bytes | The page |
|---|---|
| Start with the PNG or JPEG signature | Shows the image inside a frame with an empty `sandbox`, so nothing in it can run or reach the page |
| Valid UTF-8 with no control characters other than tab and line ends, not starting with `<`, not starting with `%PDF-` | Shows it as text |
| Anything else: HTML, SVG, XML, PDF, office files, archives, empty files | Offers a download under the cleaned name, as `application/octet-stream` |

This is threat model rule C20: decrypted content is never active content on the app's origin.

## A worked size

A 65-byte text file named `minutes-23-nov.txt`:

```
header    {"name":"minutes-23-nov.txt"}      29 bytes
container 8 + 2 + 29 + 65                    104 bytes
blob      12 + 104 + 16                      132 bytes
```

132 is the size the registry recorded for pack 1 of board 47 on testnet.

## Tests

`packages/web/lib/pack/format.test.ts` covers the container and the type decision.
`packages/core/test/seal.test.ts` covers the encryption, including that a ciphertext moved to another
pack, epoch, board or registry is refused.
