# Ava board actions: the exact bytes a chair signs

Every change to a board is authorised by one ML-DSA-87 signature from the board's chair, checked on
chain by QoreChain's `pqcVerify` precompile against the key `pqcKeyStatus` returns for the chair.
Anyone may submit the transaction; the sender grants nothing. This page is the single source for the
message format. The Solidity contract and the TypeScript library both build these bytes, and a shared
test vector proves they match byte for byte (threat model C4). A third implementation,
`packages/core/crosscheck/check_actions.py`, rebuilds the same vectors from this page alone.

## Message

```
message = abi.encode(
  bytes32 DOMAIN_TAG,   // keccak256("ava.board.v1") = 0x202301722596364529594a8773ff4f11aeb962e112437e042aa0166a90966a17
  uint256 chainId,      // block.chainid (9800 on qorechain-diana)
  address registry,     // the BoardRegistry contract address
  uint8   action,       // see the table below
  uint256 boardId,      // 0 for CREATE; boards are numbered from 1
  bytes32 paramsHash,   // keccak256 of the action's parameters, below
  uint64  nonce,        // CREATE: createNonces[chair]; every other action: the board's nonce
  uint64  deadline      // unix seconds; block.timestamp <= deadline <= block.timestamp + 3600
)
```

Eight 32-byte words, 256 bytes, fixed length. The first byte is 0x20, so no message can begin with any
QoreChain reserved signing prefix (all start with "q", 0x71). Signature: pure ML-DSA-87 (FIPS 204),
empty context, no prehash, 4,627 bytes.

## Actions and parameters

| Code | Action | paramsHash = keccak256(abi.encode(...)) | Epoch rule |
|---|---|---|---|
| 1 | CREATE | `address chair, bytes32 boardRef, bytes32 envelopeHash, uint32 envelopeSize` | new board starts at epoch 0 with the chair as its only member; boardRef is non-zero and unused in this registry |
| 2 | ADD | `address member, uint8 mode, bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter` | mode 0 SEAL_CURRENT: epochAfter equals the current epoch, the envelope is appended to it; mode 1 ROTATE: epochAfter equals current plus one |
| 3 | REMOVE | `address member, bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter` | epochAfter equals current plus one |
| 4 | ROTATE | `bytes32 envelopeHash, uint32 envelopeSize, uint64 epochAfter` | epochAfter equals current plus one |
| 5 | POST | `bytes32 docRef, bytes32 cipherHash, uint64 cipherSize, uint64 epoch` | epoch equals the current epoch when the transaction lands; docRef is unused on this board |
| 6 | TRANSFER | `address newChair` | no change |

`envelopeHash` and `cipherHash` are SHA-256 over the exact raw bytes stored in the blob store. Blob
URLs are built from that hash and the configured blob origin; the chain stores no URIs.

`docRef` is 32 random bytes the chair's browser picks before encrypting. The document key and the
AES-GCM associated data are bound to it (threat model C13, C14), because the contract's sequential
document number is not known until the transaction lands. The registry refuses a docRef already used
on that board.

`boardRef` is 32 random bytes the chair's browser picks before creating a board. The registry stores
it, refuses one already used, and returns it in `getBoard`. It exists because the board's sequential
id is not known when the first envelope is sealed; every ciphertext is bound to the board through it.

## Encryption layout (browser only)

- Place: `place = SHA-256(registry (20 bytes) || boardRef (32 bytes))`, the board's identity for all
  encryption. Read boardRef from `getBoard`, never from a link or a request.
- Epoch key: 32 random bytes from the platform's cryptographic source, new for every epoch.
- Epoch key envelope: QoreSeal `seal`, mode `mlkem`, never anonymous, chain id `qorechain-diana`,
  purpose `ava/<place lowercase hex, 64 characters>/<epoch>` (at most 89 characters), plaintext = 1
  version byte (0x01) + epoch as 8-byte big-endian + the 32-byte epoch key. Sealed to every
  recipient's ML-KEM-1024 key read from the chain with `qor_getKEMKey`.
- Document key: HKDF-SHA-256, input key the epoch key, salt the docRef, info
  `ava-doc-v1` + place (32 bytes) + epoch (8 bytes).
- Document ciphertext: 12-byte random nonce, then AES-256-GCM output (ciphertext and 16-byte tag),
  associated data = place (32 bytes) + epoch (8 bytes big-endian) + docRef (32 bytes).
- Opening an envelope and decrypting a document both take the SHA-256 recorded on chain and refuse
  bytes that do not match it, before any key is used (threat model C12).

## Nonces and replay

- Each board has one nonce shared by every action type. It must equal the stored value and goes up by
  one when the action succeeds.
- Board creation uses a per-chair creation nonce, because the board id is not known until the
  transaction lands.
- Replay protection never keys on signature bytes, because ML-DSA can produce many valid signatures
  for one message.

## Guest challenge (demo board only)

Before the demo chair bot admits a guest, the guest signs, with its own registered ML-DSA-87 key:

```
abi.encode(bytes32 keccak256("ava.challenge.v1"), uint256 chainId, address registry, uint256 boardId, address guest, bytes32 botNonce, uint64 expiry)
```

The first byte of that tag hash is 0x00. The bot issues `botNonce` and `expiry`, and never signs bytes
that arrive in a request.

## Guest leave request (demo board only)

A guest who wants to leave the demo board signs, with its own registered ML-DSA-87 key:

```
abi.encode(bytes32 keccak256("ava.leave.v1"), uint256 chainId, address registry, uint256 boardId, address guest, bytes32 botNonce, uint64 expiry)
```

It is 224 bytes, like the challenge, under its own tag, so a signature that admits can never remove
and a signature that removes can never admit. The tag hash starts 0xe6, 0x6f, which is not valid
UTF-8, and its first four bytes read as a length are far larger than the message. The bot issues
`botNonce` and `expiry` for this purpose only, checks the signature against the key the chain holds
for `guest`, and then removes that guest and nobody else.
