# Ava attack suite

One attack for each promise in [the threat model](../docs/security/threat-model.md), section C.
Each attack tries to break its promise against our own testnet contracts or our own server, or, where
the promise lives in our shared library alone, offline against that library and the pinned QoreChain
SDK. Each prints whether the defence held and saves what it saw.

## What it attacks

| Group | Where | Promises (section C) |
|---|---|---|
| `attacks/offline.ts` | no network at all: `@ava/core` and the pinned `@qorechain/sdk` | C2, C3, C16, C33 |
| `attacks/contract.ts` | the live chain: refusals by `eth_call` of the exact transaction, broadcasts only where the effect is the point | C1 to C10, C12, C13, C16, C17 |
| `attacks/proxy.ts` | the dev server's chain REST proxy, and the cross-site check on all eight public endpoints | C22, C23 |
| `attacks/uploads.ts` | the dev server's envelope and document uploads, and our live blob store | C28, C29, C30, C44 |
| `attacks/sponsor.ts` | the dev server's sponsor, on the live chain | C16, C27 |
| `attacks/relay.ts` | the dev server's relayer, on the live chain | C9, C24, C25, C40, C44 |
| `attacks/demo.ts` | the dev server's demo bot, on the live chain; `C41-full-board` runs as its own group, `seats`, before any other attack joins the demo board | C15, C33 to C36, C41 to C43, C47 |

- `npx tsx run.ts --list` prints every attack id with the line of section C it tries to break, then
  each promise proven by unit tests instead, with the test file and the exact test names, and checks
  that each named test is still in its file.
- `npx tsx run.ts --dry-run` lists every attack with the claim it tests and what it costs, the
  promises proven by unit tests instead of attacked live (and why), and the promises with no live
  attack here (and why).
- `npx tsx run.ts --offline` runs only the offline attacks, and `npx tsx run.ts --offline C3-v1-framing`
  runs one by its id. They need no `.env`, no wallet and no dev server, and every network request is
  refused while they run. A live run runs them first, so their rows sit in the same results file.

## What the offline attacks prove

- `C3-v1-framing`: no app signature can be anything else. It builds every sign-bytes form the pinned
  `@qorechain/sdk` 0.14.0 exports (hybrid transaction v1 and v2, proof of possession, key rotation,
  key migration v1 and v2, bridge attestation v1 and v2, the three authenticator digests and the
  authenticator link) and the reserved prefixes section C names, at their natural size and at exactly
  256 and 224 bytes. `signAction` refuses each one, and none of 14 board actions and challenges (all
  six actions, ordinary and extreme field values) parses as any of those forms. Two facts carry it for
  every possible field value: each tag's first four bytes, read as a v1 body length, run past the
  message (539,165,042 and 13,538,117 bytes), and each tag is invalid UTF-8 within its own 32 bytes,
  so no text form can produce an Ava message. `C3-tag` checks live that the deployed registry uses
  that same tag.
- `C33-mirror`: no client signs bytes a server handed it. `signBoardAction` and `signChallenge` ignore
  a `paramsHash` or `message` passed beside the typed fields, and a ROTATE for another board handed in
  as a challenge answer comes out signed only as a 224-byte challenge.
- `C2-deadline`: `signBoardAction` refuses a deadline a year ahead and one at the latest block plus
  3,601 seconds, and signs one at plus 3,600.
- `C16-phrase`: a freshly generated phrase pasted with no-break spaces, ideographic spaces and a
  full-width letter gives the same account and keys as the phrase itself, through
  `identityFromMnemonic` and through this suite's own reader.

Offline, the latest block's timestamp is the computer's clock; the signers only compare a deadline
with it, so any plausible time tests the same rule.

## Scope: what it may touch, and nothing else

- Our two contracts only: BoardRegistry `0x2bB34f60B29C7bC10f7ECC0B5050329E808DAcBa` and PqcProbe
  `0x624b5C35E3665eB9ade6d75BBbca1218a09E00D1`, on the QoreChain testnet.
- Our own server handlers, run by `packages/server/scripts/dev-server.ts` on `127.0.0.1:8787`.
- Our own Upstash and Vercel Blob stores, only through those handlers. The one exception is a
  document's own upload, in the document token tests and in `C44-size-mismatch` and
  `C9-unknown-board`: it goes straight to our own blob store with a token our own handler just
  issued, exactly as a browser does, because that is how a document is stored and the token tests
  check that store's refusal.
- Never mainnet, never any other contract or address, never QoreChain's own infrastructure beyond
  normal public reads and our own transactions.
- Before any transaction, every script checks that the EVM chain id is 9800 and the Cosmos chain id
  is `qorechain-diana`, and stops otherwise.
- Every transaction is signed by the security wallet or by a test identity it funds, all derived from
  `SECURITY_TESTNET_KEY`. Never by the drill account, the deployer, the relayer or the sponsor. The
  relayer and the sponsor only spend when our own handlers decide to, which is what is being tested.
- The drill's published key is used only to work out its address. Nothing is ever signed with it.
- The relayer's leak halt is never triggered live: it has no expiry, so it would stop the relayer,
  and the demo with it, until an operator clears it. Its unit tests prove it instead.
- Every request to our server carries `x-ava: 1`, as our own app's requests do, and every upload also
  carries `content-type: application/octet-stream`. Our handlers refuse a request without that header,
  or with a `Sec-Fetch-Site` other than `same-origin`, with 403 `cross_site` before they count, read
  or send anything, and an upload of any other type with 415. `lib/dev.ts` adds the header to every
  request; only `C23-cross-site` leaves it out, on purpose.

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
7. `npx tsx run.ts`. A full run takes about an hour: the offline attacks take seconds, the uploads go
   next, and the last attack waits until 52 minutes after them, which is past the verify window;
   everything else runs in between.
8. After the last live run, `npx tsx recover.ts --dry-run` lists what the test identities still hold
   and what it would send back, with nothing sent. Then `npx tsx recover.ts` sends it all to the
   security wallet, keeping only each send's fee. It checks the chain ids first, like every script
   here, and sends to the wallet alone.

Attacks whose input is missing report "not run" with the reason: the demo attacks without
`DEMO_BOARD_ID`, the blob checks without `BLOB_ORIGIN`, the drill-key attack until the key is
published. `C33-no-kem-guest` asks our own sponsor to fund one fresh identity each run (indices 120
to 199), because the bot counts failed joins per address per UTC day; it reports "not run" when the
sponsor cannot. `C15-shared-kem-guest` does the same with indices 3,000 to 3,099: the fresh identity
registers its ML-DSA-87 key, then tries to register the seeded director Asha's published ML-KEM key
as its own with `MsgRegisterKEMKey`, and the attack records what the chain answers. The chain first
simulates the exact signed transaction, so a refusal costs nothing and is reported with the chain's
own error; a control simulation of the identity registering its own key must pass, so the refusal is
the copy's. If the chain takes the copy, the attack holds only when the bot then refuses the copier's
join with 403 `key_shared` and the board's members and nonce do not move.

The demo board keeps seats free on its own. A join never removes anyone: at a full board of 40 it
answers 503 `board_full` and nothing moves, and the dev server's background pressure pass removes
guests, key problems first and then the oldest, until the board is back at 34. An admission that
leaves more than 34 members starts a pass too. Every attack that joins the demo board goes through
`admit` in `lib/demo.ts`. On `board_full` it reads the board at once, waits up to three minutes for
the pass by reading the registry alone, then sends the same join again: the bot answers `board_full`
before it reads the challenge or counts anything, so the challenge is still there. Only when the bot
says the challenge is gone (409 `no_challenge` or 403 `challenge_expired`) does it ask for a fresh
one. After an admission that starts a pass it waits for that pass as well, so the next attack finds
the board still.

`C41-full-board` runs before every other attack that joins the demo board. When it finds the board at
its cap (an older server left board 15 at 40), it tests the `board_full` branch live: the 503 with
retry-after 30, the board unmoved, the pass bringing it to 34 within three minutes with the oldest
guests gone and never the judge, then the judge's same join admitted on its first challenge. Below
the cap the suite cannot fill the board, because each pass brings it back, so it makes the joins
that would fill it one at a time, and shows each one lands and each pass removes the oldest guest,
never the one just admitted. `board_full` is then not run live, and `C41-board-full` lists its unit
tests. The evidence names the path that ran.

Honest joins can no longer fill the board, because every admission that leaves more than 34 members
starts a pass, so `C41-full-board` normally takes its below-cap path. The at-cap path was last seen
live in `results/run-20261119T130133Z.md`, though not by `C41-full-board`: `C23-cross-site`'s
same-origin join met board 15 at 40 members and was answered 503 `board_full`, and the background pass
brought the board from 40 to 34 before `C41-full-board` ran, so it found 34 and took the below-cap path.

`C42-bad-key-guest` needs the board at 34 to 39 members, which is where `C41-full-board` leaves it. A
guest this run admitted that is not the oldest withdraws its ML-KEM key, a fresh judge's admission
takes the board to 35, and the pass that admission starts must remove the guest with no key, not the
oldest. When no such guest is on the board, it admits one of its own first.

`C7-exceed-64`, `C41-full-board` and `C42-bad-key-guest`, gated by budget, run only when the wallet
holds what they cost, and say so otherwise. `C41-full-board` reserves up to about 0.93 QOR of the demo
bot's share at a full board, about 1.5 QOR from a board at 34 and more from an emptier one, out of the
bot's 12 QOR of the relayer's 20 QOR day; run it on a day judges are not using the demo.

`C44-size-mismatch` uploads and verifies a 4,096-byte document through our own handlers, then relays
two posts the wallet signs as chair of its own board A: that document with a cipherSize one byte
larger, which must answer 422 `size_mismatch`, and a hash nobody uploaded, which must answer 422
`document_unverified`. Before each, the registry's own `eth_call` of the exact post must pass, so the
refusal is the server's size rule and not the registry's. The board's nonce and document count, and
the relayer's own nonce, must not move.

`C9-unknown-board` uploads and verifies a 4,096-byte document the same way before it posts that
document to a board id the registry never issued. The relay checks a post's verified size before its
pre-flight, so only a verified document reaches the registry's check, which must answer 422
`UnknownBoard`. Its addMember on that board needs no document and must answer the same.

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

Below the table, "Not run live, proven by unit tests instead" lists each promise this suite does not
attack live, each marked NOT RUN live with the test file and the exact names of the unit tests that
prove it, and why it is not run live: the leak halt and its failed-close retry, the relayer's nonce
check, the stored nonce's compare-and-set and the refused sends it catches, one action in flight per
nonce, the valid total counted last, a nonce mark giving way once its send is unknown to the chain,
the per-chair and demo budgets, the demo bot's own hourly relays, the full-board answer and the pass
that seats the judge after it, a pass stopping at its first refusal, the front-run copy of the bot's
addMember, the sweep's removal of a guest with a copied ML-KEM key, the admission mark's 150-second
life, the sponsor's mark given back when nothing was sent, an unreadable run forgotten once its
member is removed, the sweep cursor's compare-and-set, the document listing cursor, the two-hour
posted-only keep of documents, the daily bytes budget on posts, the deletion of a posted document of
the wrong size, the sweep's one-time hash of a document posted without a verify, the registry code
check, the IPv6 /48 count on every endpoint and every byte budget, and the upstream misbehaving.

The money lines say what was realised (burned in fees and gas) and what is unrealised (QOR still
held by the test identities). Our relayer's and sponsor's own spend is not measured here; their
transaction hashes are in the evidence.

## What it does not cover

- Anything in the browser (C18 to C21, C26, C38, C39) and the build grep of C32: the app is not built.
- Two server instances sharing state (C31): it would need a second server or a restart the suite does
  not control. The sweep cursor's compare-and-set is proven by `packages/server/test/envelopeSweep.test.ts`.
- The upstream misbehaving (a redirect, an oversized or non-JSON body, a timeout): the upstream is
  QoreChain's REST. `packages/server/test/proxy.test.ts` proves those.
- `C40-junk-flood` sends 30 junk requests and `C40-copies` 5 copies, both under the per-chair limit of
  60, so they show a real action still lands; that junk and copies never count against a chair is
  proven by `packages/server/test/relay.test.ts` with 60.
- `C40-copies` needs the copies to reach the relay while the first is pending. The relay answers only
  after the receipt, so they do; a copy that arrived after the first had landed would be refused by
  the pre-flight with 422 instead of 409, and the evidence says so.
- `C3-v1-framing` covers the sign-bytes forms of `@qorechain/sdk` 0.14.0 and the prefixes section C
  names. It does not cover a form a later SDK or chain version adds, or another contract on this
  chain that checks ML-DSA signatures over its own messages.
- `C33-no-kem-guest` sees the demo board move if a judge joins during its six joins; it then reports
  the change as not held. `C15-shared-kem-guest` reads the board around its one join the same way.
- `C15-shared-kem-guest` copies a key a seated director already published. It does not test a copier
  who publishes a judge's new key before the judge does, the known limit in section C, C42.
- The pass order that `C41-full-board` and `C42-bad-key-guest` check sees missing and shared ML-KEM
  keys only. The bot also takes first a guest whose key changed since its epoch was sealed, which only
  it can see by opening the envelopes; such a guest would show here as a removal out of order.
- `C41-full-board` and `C42-bad-key-guest` read the board while judges may be joining. A judge's join
  in those minutes moves the board and the pass order, and the attack then reports not held.
- `C23-cross-site`'s same-origin join expects 503 `board_full` when the demo board, read just before
  it, holds 40 members or more, and 400 `bad_body` otherwise. At a full board the bot answers before
  its per-IP count, so for that endpoint only the 403s show the cross-site requests were refused.

## What the board actions cost

Measured on the testnet on 17 Nov: creating a board uses about 417,000 gas (about 0.047 QOR),
adding a member about 323,000 to 359,000 (0.036 to 0.040 QOR), posting a document about 310,000 to
327,000 (0.035 to 0.037 QOR), and removing a member about 292,000 (0.033 QOR). Opening the EVM window
a sender needs costs 0.037 to 0.08 QOR more, once per window, not per action.
