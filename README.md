# Ava

Ava, from the Tamil avai (அவை), the assembly where a council meets.

Board packs your directors can open today and nobody can open on Q-Day, and a director you remove
is locked out of the next one. Built on the QoreChain testnet for Build Before Q-Day (Encrypted Apps).

**Status: work in progress.** The contract is live and proven on testnet; the server pieces are
tested; the web app is not built yet. This README grows with the build.

## How it works, in four lines

- Each pack is encrypted in the browser and sealed with ML-KEM-1024 (QoreSeal) to the directors'
  encryption keys published on QoreChain. Servers only ever hold ciphertext.
- Every change to a board (members, key rotations, new packs) needs the chair's ML-DSA-87 signature,
  checked on chain by QoreChain's `pqcVerify` precompile against the chair's registered key. A stolen
  classical key cannot add anyone or post anything.
- Removing a director rotates the board's key to the remaining members only. The removed director
  keeps whatever they could already open, and Ava says so instead of pretending otherwise.
- Anyone may relay a signed action; the transaction sender grants nothing.

Details: [ARCHITECTURE.md](ARCHITECTURE.md), the exact signed bytes in
[docs/spec/actions.md](docs/spec/actions.md), and the
[threat model](docs/security/threat-model.md) written before any code.

## Live on QoreChain testnet (qorechain-diana, EVM chain id 9800)

| Contract | Address |
|---|---|
| BoardRegistry | `0x2bB34f60B29C7bC10f7ECC0B5050329E808DAcBa` |
| PqcProbe (first core-tech check) | `0x624b5C35E3665eB9ade6d75BBbca1218a09E00D1` |

Explorer: https://explore.qore.network (switch to Testnet). The deployed runtime code equals the
build byte for byte (the prove command checks it). Source verification is not available for this
chain: Sourcify does not list chain 9800, and the explorer has no verification API.

## Prove it

`packages/contracts`, with a funded deployer in `.env`:

```bash
npm run prove:registry
```

It walks a real board through its life on testnet (create, add two directors, post, remove one,
post again) and attacks it: a director signing as chair, replayed and tampered signatures, a
signature moved between boards, a pack posted under the old key after a removal, a deadline too far
ahead, sending value, and the chair's classical key on its own. Each attack must be refused. The
latest saved run is in `packages/contracts/deployments/`.

## Tests

- `packages/contracts`: `forge test` (unit, fuzz and invariant suites) and
  `FOUNDRY_PROFILE=realsig forge test` (real ML-DSA-87 signatures through FFI).

## Built with

QoreChain SDK 0.14.0, QoreSeal 0.1.0, qorechain-pqc 0.2.3, viem, Foundry, OpenZeppelin Contracts
5.6.1 (EnumerableSet). QoreChain kits and docs: https://docs.qorechain.io

## Licence

MIT. See [LICENSE](LICENSE).
