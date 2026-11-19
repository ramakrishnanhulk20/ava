# Ava attack suite

One live attack for each promise in [the threat model](../docs/security/threat-model.md), section C.
Each attack tries to break its promise against our own testnet contracts or our own server, prints
whether the defence held, and saves what it saw.

## What it attacks

| Group | Where | Promises (section C) |
|---|---|---|
| `attacks/contract.ts` | the live chain: refusals by `eth_call` of the exact transaction, broadcasts only where the effect is the point | C1 to C10, C12, C13, C16, C17 |
| `attacks/proxy.ts` | the dev server's chain REST proxy | C22, C23 |
| `attacks/uploads.ts` | the dev server's envelope and document uploads, and our live blob store | C28, C29, C30, C44 |
| `attacks/sponsor.ts` | the dev server's sponsor, on the live chain | C16, C27 |
| `attacks/relay.ts` | the dev server's relayer, on the live chain | C9, C24, C25, C40 |
| `attacks/demo.ts` | the dev server's demo bot, on the live chain | C15, C33 to C36, C41 to C43 |

`npx tsx run.ts --dry-run` lists every attack with the claim it tests and what it costs, the
promises that are proven by unit tests instead of attacked live (and why), and the promises with no
live attack here (and why).

## Scope: what it may touch, and nothing else

- Our two contracts only: BoardRegistry `0x2bB34f60B29C7bC10f7ECC0B5050329E808DAcBa` and PqcProbe
  `0x624b5C35E3665eB9ade6d75BBbca1218a09E00D1`, on the QoreChain testnet.
- Our own server handlers, run by `packages/server/scripts/dev-server.ts` on `127.0.0.1:8787`.
- Our own Upstash and Vercel Blob stores, only through those handlers. The one exception is the
  document token test: it uploads straight to our own blob store with a token our own handler just
  issued, exactly as a browser does, because that store's refusal is what it tests.
- Never mainnet, never any other contract or address, never QoreChain's own infrastructure beyond
  normal public reads and our own transactions.
- Before any transaction, every script checks that the EVM chain id is 9800 and the Cosmos chain id
  is `qorechain-diana`, and stops otherwise.
- Every transaction is signed by the security wallet or by a test identity it funds, all derived from
  `SECURITY_TESTNET_KEY`. Never by the drill account, the deployer, the relayer or the sponsor. The
  relayer and the sponsor only spend when our own handlers decide to, which is what is being tested.
- The drill's published key is used only to work out its address. Nothing is ever signed with it.
- The relayer's leak halt is never triggered live: it would stop the demo for the rest of the day.
  Its unit tests prove it instead.

`lib/guard.ts` enforces this: it replaces `fetch` with one that refuses every host except the testnet
RPC, REST and EVM JSON-RPC, the dev server, and reads from our blob origin; it refuses redirects; it
refuses any transaction target that is not one of the two contracts; and it refuses to start while
the shell holds another account's phrase or our stores' credentials.

## How to run it

You need Node 20 or later.

1. `npm install` in this folder.
2. `npx tsx new-wallet.ts` once. It writes a fresh 24-word phrase into `security/.env` as
   `SECURITY_TESTNET_KEY` and prints only the wallet's `qor1` and `0x` addresses. It refuses if the
   key is already there. The wallet for this project: `qor1jh3n0j857g7qnjg2ljrgs0zzqngrhzwna2t40w` /
   `0x95E337c8F4F23C09c90afC86883c4204d03B89D3`.
3. Add the other keys to `security/.env`, as `.env.example` describes: `BLOB_ORIGIN`, `DEMO_BOARD_ID`
   and `DEMO_SEEDED` with the same values as `packages/server/.env`, and `DRILL_PUBLISHED_KEY` once
   the drill's attack log is out.
4. `npx tsx run.ts --dry-run` and fund the wallet with the amount on its "Fund the wallet" line.
5. `npx tsx register-wallet.ts`. It registers the wallet's ML-DSA-87 key (with a proof of possession)
   and its ML-KEM-1024 key, and does nothing for a key the chain already holds.
6. Start the dev server in another terminal: `npx tsx scripts/dev-server.ts` in `packages/server`.
7. `npx tsx run.ts`. A full run takes about an hour: the uploads go first, and the last attack waits
   until 52 minutes after them, which is past the verify window; everything else runs in between.

Attacks whose input is missing report "not run" with the reason: the demo attacks without
`DEMO_BOARD_ID`, the blob checks without `BLOB_ORIGIN`, the drill-key attack until the key is
published. The three that fill a board to its cap (`C7-exceed-64`, `C41-full-board`,
`C42-bad-key-guest`) run only when the wallet holds what they cost, and say so otherwise.
`C41-full-board` also reserves up to about 5 QOR of the relayer's 8 QOR daily ceiling; run it on a
day judges are not using the demo.

## How to read a result

Each run writes `results/run-<UTC time>.md`, headed by the commit it ran against and whether the
code under `packages/` or `security/` had uncommitted changes. Its table has one row per attack:

- **held** `yes`: the attack was refused or had no effect. The evidence says by what: a revert name,
  an HTTP status and code, a transaction hash, or the state read back from the chain.
- **held** `NO`: the attack got through, or a control that should have passed did not. The failing
  lines come first, marked `NOT REFUSED`.
- **held** `no (not run)`: it could not run, and the evidence says why. It counts as not held.

The run stops at the first exception that is not a refusal and marks every later attack "not run".
It exits with code 0 only when every attack held.

The money lines say what was realised (burned in fees and gas) and what is unrealised (QOR still
held by the test identities). Our relayer's and sponsor's own spend is not measured here; their
transaction hashes are in the evidence.

## What it does not cover

- Anything in the browser (C18 to C21, C26, C38, C39) and the build grep of C32: the app is not built.
- Two server instances sharing state (C31): it would need a second server or a restart the suite does
  not control.
- The upstream misbehaving (a redirect, an oversized or non-JSON body, a timeout): the upstream is
  QoreChain's REST. `packages/server/test/proxy.test.ts` proves those.
- `C40-junk-flood` sends 30 junk requests, under the per-chair limit of 60, so it shows a real action
  still lands; that junk never counts against a chair is proven by
  `packages/server/test/relay.test.ts` with 60.

## What the board actions cost

Measured on the testnet on 17 Nov: creating a board uses about 417,000 gas (about 0.047 QOR),
adding a member about 323,000 to 359,000 (0.036 to 0.040 QOR), posting a document about 310,000 to
327,000 (0.035 to 0.037 QOR), and removing a member about 292,000 (0.033 QOR). Opening the EVM window
a sender needs costs 0.037 to 0.08 QOR more, once per window, not per action.
