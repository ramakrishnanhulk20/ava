# Runbook: the server's known limits and the demo chair's key

This file is for whoever runs Ava's server. It says what the server's defences do not stop, and the
exact steps for the one emergency that has a written answer: a leak of the demo chair's ML-DSA-87
key. The invariants it refers to (C23 to C25, C28, C31, C34, C37, C40 to C46) are in `docs/security/threat-model.md`.

## Known limits

### Totals anyone can reach without a signature

Every endpoint that answers without a signature counts each caller's IP address (as the hosting
platform reports it, never a header) and keeps a total for everyone. A request that a page on
another site could make a browser send (a beacon, an image, a form) is refused first and counts
against nothing, so a hostile page cannot spend these totals through its visitors (C23). An IPv6
caller is counted per /64 and also per /48, at four times the per-IP figure below. The same holds for the upload budgets (document tokens, envelope uploads and their bytes). The totals are
set high, so only an attacker with many addresses can reach them. Reaching one stops that endpoint for every
honest caller until its hour ends. That is the residual risk, endpoint by endpoint, per hour:

| Endpoint | Per IP address | Total | Addresses needed to reach the total | What reaching it costs us or blocks |
|---|---|---|---|---|
| Envelope upload | 20 uploads, and 2.2 MB (a /48 gets 4 times each) | 1,000 uploads | 50 | Blocks new envelopes for chairs. Up to 110 MB an hour of stored bytes, each deleted two hours after upload unless the registry names it. The demo bot's own uploads do not count here: they have their own allowance of 600 a day per kind (join, sweep), so this total cannot stop a judge joining. |
| Document upload token | 30 requests, 12 tokens | 1,500 requests | 50 | Blocks new document uploads. Each token allows exactly the size its request declared (up to 25 MiB), and that size is booked when the token is issued on two daily byte budgets: 25 MiB per client (a /48 gets four times that) and 1,250 MiB in total, fifty times the client figure. Past any of them, the request answers 429 `upload_bytes` and no token is issued, with `retry-after` set to 00:00 UTC. So at most 1,250 MiB of documents can be placed in a UTC day, however they are later posted. Each is deleted two hours after its upload unless a `DocumentPosted` event names its hash, so an attacker's bytes are held for two hours at most. Storage and transfer are billed meanwhile. |
| Document verify | 30 | 1,500 | 50 | Blocks verifies. Each verify reads at most one unverified blob of up to 25 MiB; a verified one is answered from its mark and never read again. |
| Demo guest challenge | 10 | 1,000 | 100 | Judges cannot get a challenge, so cannot join, until the hour ends. |
| Relay, request whose pre-flight fails | 20 (every request counts) | 3,000 rejected | 150 | Failed pre-flights are answered 429 instead of 422 past the total. Real actions are never blocked by them: an action whose signature the registry accepts is counted per chair, per board and in a separate valid-action total (C40). Each rejected request still costs one call to the public EVM RPC. |
| Chain REST proxy | 60 a minute | 300 a minute | 5 | Kept low on purpose (C23): every browser shares the server's own quota at the public REST, so a higher total would let one attacker spend that quota for everyone. Five addresses can stop the proxy for a minute at a time. |

The 50-address rule holds for the daily upload byte total too: it is fifty times the per-client figure, and a refused request books nothing. A daily total recovers at 00:00 UTC; an hourly one at the end of its hour.

A pressure pass on the demo board runs one at a time. While one is running, another answers refused `pass_running` and does nothing; this is normal and needs no action. The mark `demo:pass` expires on its own if a pass dies.

Two things no limit here stops:

- A flood of junk from many addresses still makes the server call the public EVM RPC and REST, and
  the server's own quota there is shared by the relay, the sponsor and the demo bot. When that
  quota runs out, those endpoints answer "chain unreachable" and refuse; nothing is sent wrongly.
- A real signed action can be submitted again until it lands. A byte-identical copy answers 409
  `duplicate` and counts against no chair, board or total (C46), so copies no longer use up a chair's
  hour. A different action signed at a nonce that already has one in flight answers 409
  `nonce_in_flight` and counts against nothing either (C40), so re-signed copies cannot starve other chairs.
  The per-board, per-chair and valid-action counters move last, under the send lock, after every refusal a caller can cause. A copy that is broadcast after the first lands, from outside our relay, reverts at the
  sender's cost, not ours.
- Both marks (the copy mark and the in-flight mark) give way. If the node refused a send, the chair may send the same bytes again, or cancel by landing a different action at that nonce: a mark that names a relayer transaction the chain does not know is taken by the next relay, and one that names no transaction yet blocks others only while its own relay is inside its 55 seconds. Known limit: a send that was lost but lands after its mark gave way can leave two actions at one nonce. One lands and the other reverts at its own cost.

### The relayer's money

The relayer may lose at most 20 QOR in a UTC day, all traffic together. Inside that:

| Share | Per day | What it pays for |
|---|---|---|
| Public chair relays, all chairs | 8 QOR | Actions from the app's chairs |
| One chair address | 1.5 QOR | Public relays by that one chair. About 37 actions at today's fees |
| Demo bot | 12 QOR | Admissions and scheduled removals on the demo board |

Window opens and closes count on the 20 QOR total only. The booking is done in `sendLedgers` in `relay.ts`, which uses `reserveOn` in `window.ts`. A send is booked at its worst case, then
settled to the real fee from its receipt; one with no receipt stays booked at the worst case. When
a share or the total is spent, relays answer 503 `daily_ceiling` (or 429 for the one chair) until
00:00 UTC. That is not a halt and needs no action. The demo bot's share is sized for 120 joins a day
at one relay each, plus up to as many removals in the background, about 8 QOR at today's fees.

A document token request states the file's size (`{ "sha256": ..., "size": ... }`, 1 byte to 25 MiB; anything else answers 400 `bad_size`). The size is booked on the day's upload byte budgets when the token is issued: 25 MiB per client, 1,250 MiB in total, answering 429 `upload_bytes` past any of them (C28, C44). Like `post_bytes`, it is not a halt and needs no action; it resets at 00:00 UTC. A refused request books nothing. A token whose name is still empty 10 minutes after issue plus a 1 hour grace gives its bytes back once, in the document sweep (up to 500 records a run) or when a verify finds the name empty, so the sweep must run often enough to settle them.

Posted documents are kept for good, so they have a bytes budget as well (C44). One chair may post
100 MiB in a UTC day and all chairs together 1 GiB. A post past either answers 429 `post_bytes`,
with `retry-after` set to 00:00 UTC. Like the money ceilings, it is not a halt and needs no action.
The bytes are reserved before the send and given back if nothing was broadcast. The budget books the
size the server verified, not the size the chair states. A post is relayed only when the document's
verified size equals the signed `cipherSize`. Two refusals are 422 and need no action from you:
`document_unverified` (the server holds no verified copy of that hash: the chair has not run verify,
or the blob is gone) and `size_mismatch` (it holds one of another size). Neither moves any counter.

### The demo bot

- Every sweep looks up the ML-KEM key of every member (up to 40) and downloads every envelope of
  the current epoch to check whom the epoch key was sealed to. A lookup that fails for a reason
  that says nothing about the member (a timeout, the network, a malformed answer) stops that sweep
  and it runs again on the next schedule. If the same member's lookup comes back unreadable on
  three sweeps in a row, that member becomes the removal target with the reason `key_unreadable`,
  and the sweep goes on. A sweep that finds a guest with a missing, invalid, changed or shared key removes
  that guest and leaves every such guest out of the new epoch; it removes one guest per run. The count
  of unreadable sweeps in a row moves only by compare-and-set, so a retried write cannot count twice,
  and only the scheduled sweep adds to it. When a member's removal lands, its count is forgotten.
- A guest with no valid ML-KEM key is refused before the bot does anything (`no_kem_key` or
  `bad_kem_key`): nobody is removed to make room for it, and the join takes nothing from the day.
  After a guest has signed its challenge, every refusal it caused (a 4xx other than 429) counts
  against its address. The sixth in a UTC day answers 429 `too_many_failures`. A 5xx or a 429 from
  our own side never counts, so a judge is not locked out by our trouble.
- Joins are capped at 120 a day in all and 3 an hour per IP address. A join is one add and never
  removes anyone (C41). Its relay comes from the bot's own room of 120 an hour, apart from the public
  limits. If the hour has none left, the join answers 503 `demo_busy` with `retry-after` set to the
  hour's end. Known limit: room taken for a join is not given back if the join stops later, so
  repeated failed joins can use up part of the 120 for the rest of the hour. The loss is bounded by
  that 120.
- A full board answers a join 503 `board_full` with `retry-after: 30`. Nothing is counted against the
  guest, nothing is taken from the day or the hour, and nobody is removed. The join does schedule a
  background pressure pass (`freeDemoSeats`). The board keeps `DEMO_FREE_SEATS` (6) seats free: the
  pass removes the oldest guests (a guest with a key problem first, reason `key_*`, otherwise reason
  `pressure`) until the board holds 34 members, and stops at the first refusal, at a removal whose
  receipt was not seen, or after six removals. Each removal is its own relay with its own hourly
  reservation, so a refused or failed removal costs no guest anything. A pass is also scheduled after
  any admitted join that leaves more than 34 members. The pass runs only if the host hands the demo
  handlers a background runner (`background` on the demo context; the dev server has one). Without it
  nothing is scheduled, and the scheduled `sweepDemoGuests` run is the only remover: after its own
  step it runs the same pass while the board holds more than 34 members, so the scheduled sweep alone
  frees seats. Run `freeDemoSeats` on the same schedule as a backstop if you like. The pass and every
  sweep read a fresh clock for each removal, so one that runs past the top of an hour books its next
  removal in the new hour.
- A join to a full board is refused before its challenge is used and before anything is counted, so
  the judge's retry reuses the same challenge. The check uses a board size at most 5 seconds old. In
  the rare case that the board fills between that check and the join lock, the join is refused after
  its challenge was used, and the web client then asks for a fresh one (C43).
- An admission mark names the transaction of its add. If that add was lost or reverted and the guest
  is not a member, the next join by that guest, or the scheduled sweep, releases the mark. A guest
  whose add is still pending keeps it and gets 503 `admission_unsettled` (retry-after 30), counted against nothing; so does a guest whose mark cannot be read yet or whose first join is still under way. Guests whose add was sent
  with no receipt seen are kept in a short list (`demo:unsettled`, at most 20) for the sweep to settle.
- A guest whose ML-KEM key is byte-equal to a current member's is refused with 403 `key_shared`
  (C42). The join compares only against members whose key lookup worked; a member whose lookup is
  unreadable is skipped, so one bad record cannot stop every join. If a copier is seated anyway, the
  next sweep or pressure pass marks it `key_shared` and removes it first, and leaves it out of the new epoch. The chain
  does accept a second account registering a key another account already holds (shown live on 19 Nov:
  it asks for no proof the registrant holds the private key), so this refusal is the only guard. Known
  limit: a copier who publishes a judge's new key first gets that judge refused `key_shared` until
  the copier's six hours end.
- A guest the bot seated is always dated. If a seat has no admission record (a failed write, or a
  front-run copy of the bot's `addMember` that landed first), the sweep dates it from the block of
  the latest envelope sealed to it, so every guest leaves within six hours of admission. The
  once-per-address admission mark lives 150 seconds until the join is about to send, then it is kept
  for good; a join that stops before the send takes it back, and one whose take-back fails still
  frees the address within 150 seconds.
- A problem with the chair's or a seeded director's key stops every sweep and every pressure pass,
  and logs a `demo_sweep_alert` line naming the member. Nobody is removed until it is fixed.
- If an admitted join's receipt is not seen within 30 seconds, the next pressure pass signs at the
  same board nonce. A pending action at that nonce gives way once the chain does not know its
  transaction (C40), so the pass is not stuck behind a lost send.
- A guest challenge can no longer be cancelled by a stranger: only a join that carries a valid
  signature over it consumes it (C43).

### Blob sweeps

- The sweeps are functions the host must call on a schedule. Nothing in this repository starts
  them, and until they run nothing is ever deleted. Schedule four:
  `sweepUnreferencedEnvelopes` (`packages/server/src/envelopeSweep.ts`), `sweepUnverified`
  (`packages/server/src/docupload.ts`) and, for guests, `sweepDemoGuests` (every few minutes; it
  removes one expired guest per run, settles admission marks whose add never landed, and frees seats
  while the board is above 34 members) and `freeDemoSeats` (`packages/server/src/demo.ts`; a backstop
  for the pressure pass, see "The demo bot"). Run the envelope scan
  every 30 minutes or so, and the document sweep after it. A run reads at most 50 pages of logs, so the first runs catch up from the deploy block in steps. The document sweep also keeps its place in the blob listing (`docsweep:cursor`) and goes on from it next run, so a large number of kept documents cannot hide a name from it for good. After a confirmed testnet reset, delete `docsweep:cursor` with the other keys below. The envelope scan is the one that
  matters most: it reads the registry's logs, writes a `posted:<registry>:<sha256>` mark for every posted
  document and moves the scan point `docsweep:marked-through:<registry>`. The document sweep deletes nothing
  until that scan point exists, and nothing newer than the scan point. If the scan is never
  scheduled, uploaded documents are never deleted.
- The document sweep runs under a lock (`docsweep:lock`, 300 seconds, no waiting). A second run
  started while one is going answers `busy` and does nothing. A run starts no new read or page after
  240 seconds. It answers `{ deleted, deferred, unreadable, outOfTime }`: `deferred` is the count of
  documents left for the next run because the 200 MiB hashing budget or the 240 seconds ran out, and
  `unreadable` lists the hashes of posted blobs it could not read back.
- The relay posts only a document it holds a verified copy of, at the signed size (C44), so a chair
  who posts through the relay cannot post an unverified one. One posted by calling the contract
  directly can still appear. The sweep hashes such a blob once. A match gets its
  verified mark and is never read again. A mismatch is deleted and logged `document_mismatch_deleted`.
  A blob that cannot be read is logged `document_read_failed` and is never deleted; if the same hash
  keeps appearing in `unreadable`, look at the blob store, not at the document.
- A posted blob whose stored size differs from the `cipherSize` its posted mark records is deleted and
  logged `document_size_mismatch`. A posted mark written before sizes were recorded has none, and
  such a blob is never deleted for its size.
- The `posted:`, `referenced:` and scan keys carry the registry address in their name. Keys from before
  that naming (`posted:<sha256>`, `referenced:<sha256>`, and scan keys without an address) are no
  longer read and can be deleted from the shared store; the scan rebuilds the current ones from the
  deploy block, and nothing hash-named is deleted until it has caught up.
- A listing the blob store refuses while a listing cursor is held resets the cursor to the start of
  the listing, so a stale cursor never stops the document sweep.
- The shared store must run with eviction off (`maxmemory_policy` set to `noeviction`). An evicted
  mark would make a kept envelope or document look unreferenced. Checked on 19 Nov 2026: the
  Upstash store reports `maxmemory_policy:noeviction`. Check again after any plan change, with
  `INFO memory`.
- A document that no `DocumentPosted` event names two hours after its upload is deleted, verified or
  not. A document posted on chain more than two hours after it was uploaded is therefore deleted
  first and cannot be read. The app posts a document right after verifying it, so this only bites a
  chair who signs late.
- The sweeps rebuild every keep decision from the registry's logs, from the deploy block. If the
  shared store is lost, the scan starts again from there, and the document sweep deletes nothing
  until the scan has read past each blob's two hours.
- An envelope whose action lands more than two hours after its upload is deleted first (C44). The
  app must upload an envelope right before the chair signs; a signature lives at most one hour.
- The envelope sweep deletes nothing on a run that has not read the registry's logs up to the
  latest block, and stops with an error if its cursor is past the latest block, which means the
  chain is not the one it was reading (a testnet reset, or a wrong node). After a confirmed reset,
  delete the shared-store keys `envsweep:next-block` and `docsweep:marked-through:<registry>` so the sweep
  starts again from the registry's deploy block. The cursor only moves by compare-and-set, so a run
  that finds it changed under it stops with an error and nothing is deleted; run it again.

## Relayer key rotation and clearing a halt

The relayer is the server account that pays gas for the chairs' signed actions. Its classical key
holds an open EVM window scoped to the registry. The server keeps the relayer's next nonce in the
shared store (`relayer:next-nonce:<address>`) and compares it with the chain before every window
open, close and send. The server also records the hash of every transaction it signs under that
transaction's nonce (`relayer:sent:<address>:<nonce>`) before it broadcasts, and the stored nonce
moves forward only when our hash at that nonce is seen on chain, by compare-and-set. If the chain is
past the stored nonce, every nonce in between must be one of ours. If one is not, or the gap is wider
than 8, someone else signed with the relayer's key, even if no window counter shows it, and
the server halts. A nonce of ours that is still waiting for a block does not halt: relays answer
503 `window_unavailable` until it lands. A halt closes the window if one is open and refuses every relay with 503
`halted`. It has no expiry. It ends only when you clear it.

Any script that signs with the relayer's key outside the relay trips the halt, even your own. Use
the relayer's key only through the server, with one exception: `register-relayer`, run once on a
new relayer before the server has relayed anything for it.

To replace the relayer after a suspected leak, do these in order. You need the machine with
`packages/server/.env`, Node 20 or later, and `npm install` run in `packages/server`.

1. In `packages/server/.env`, move the old `RELAYER_MNEMONIC` line somewhere safe. The next step
   refuses to run while the line exists.
2. In `packages/server`, run `npm run new-relayer`. It writes a new `RELAYER_MNEMONIC` to `.env`
   and prints the new `qor1` and `0x` addresses.
3. Send the new `qor1` address at least 0.5 QOR from the testnet faucet or another funded account.
4. Run `npm run register-relayer`. It registers the new account's post-quantum key. Wait for its
   last line to report the key as registered and proven.
5. In the hosting platform's server settings, replace `RELAYER_MNEMONIC` with the new phrase and
   redeploy. The new account must also not equal the sponsor's or the demo chair's: the server
   refuses to start if two roles share an address.
6. In `packages/server`, with the new phrase in `.env`, run `npx tsx scripts/clear-relayer-halt.ts`.
   Without `--confirm` it only shows what is set. Read it, then run
   `npx tsx scripts/clear-relayer-halt.ts --confirm`. It prints what it cleared. The next relay
   opens a window for the new account and adopts its nonce.
7. Send one test relay, or run `npm run live-relay-check`, and confirm it answers 202.

If the halt came from a false alarm and the key is safe, skip steps 1 to 5 and run step 6 alone.
If the old account still holds QOR, move it out with its own key before you retire it, from a
machine that is not the server.

## If the demo chair's ML-DSA key leaks

Why it matters: from 18 Nov the Q-Day Drill publishes the demo chair's secp256k1 key, so its
ML-DSA-87 key is the account's whole protection (C37). Anyone holding both can sign board actions
as the chair, open EVM windows, and rotate the key away from us. Whoever rotates first keeps the
account, so do these steps at once, in order.

Before you start: you need the machine that holds `packages/server/.env` with
`DEMO_CHAIR_MNEMONIC`, Node 20 or later, and `npm install` run in `packages/server`.

1. Turn the demo endpoints off. In the server's settings on the hosting platform, remove
   `DEMO_BOARD_ID` and redeploy. Every demo endpoint then answers 503 `not_ready`, so the bot signs
   nothing while the key is being replaced.
2. Dry run. In `packages/server`, run `npm run rotate-demo-chair`. It confirms the chain, builds
   the `MsgRotatePQCKey` with both signatures, checks them, and sends nothing. Read its lines:
   - `pqcKeyStatus: ... (the old key)` means the chain still holds our key. Go on.
   - `pqcKeyStatus: ... (not the old key)` or `no proven ML-DSA-87 key reported` means the key was
     already replaced. Stop and go to "If the rotation was lost" below.
   - `A live run would refuse now: the account holds under the 0.12 QOR fee` means the demo chair's
     `qor1` address (printed on the `demo chair:` line) needs at least 0.2 QOR first. Send it from
     the sponsor or the testnet faucet, then run the dry run again.
   - `A live run would send this now.` means go to step 3.
3. Live run. Run `npm run rotate-demo-chair -- --live` and type `ROTATE` when asked. Before it
   sends anything, it writes the phrase the new key comes from into `packages/server/.env` as
   `DEMO_CHAIR_PQC_MNEMONIC` and reads it back; without that phrase the account's new key would be
   lost. It then sends the rotation, hybrid-signed with the old key, and waits until pqcKeyStatus
   reports the new key. Its last line must read `pqcKeyStatus: <fingerprint>, registered, ML-DSA-87,
   possession proven: the new key`. Note the fingerprint on its `new key:` line.
   - If it stops with an error after `sent:`, the rotation may still land: go to step 4 before
     doing anything else.
   - If it stops before `sent:` and step 4 still shows the old key, delete the
     `DEMO_CHAIR_PQC_MNEMONIC` line from `.env` and go back to step 2.
4. Confirm with pqcKeyStatus yourself. In `packages/server`, replace `0xDEMO_CHAIR` with the 0x
   address on the script's `demo chair:` line and run:

   ```
   npx tsx -e "import { bytesToHex, sha256 } from 'viem'; import { evmClient } from './src/chain/evm.ts'; import { readKeyStatus } from './src/demoBoard.ts'; (async () => { const s = await readKeyStatus(evmClient(), '0xDEMO_CHAIR'); console.log({ registered: s.registered, algorithmId: s.algorithmId, possessionProven: s.possessionProven, bytes: s.pubkey.length, fingerprint: bytesToHex(sha256(s.pubkey, 'bytes').slice(0, 8)) }); })();"
   ```

   It must print `registered: true`, `algorithmId: 1`, `possessionProven: true`, `bytes: 2592`,
   and the fingerprint from the script's `new key:` line. From this point the leaked key signs
   nothing that counts: the registry checks every board action against the key pqcKeyStatus
   reports (C1), and the chain refuses hybrid transactions signed with the old key.
5. Keep the demo endpoints off for now. The bot still derives its signing key from
   `DEMO_CHAIR_MNEMONIC`, which now gives the old key, so every action it signed would be refused.
   It cannot load the new key until the server reads `DEMO_CHAIR_PQC_MNEMONIC`, which is a code
   change not yet made. When that change ships, add `DEMO_CHAIR_PQC_MNEMONIC` to the server's
   secrets, put `DEMO_BOARD_ID` back, and redeploy.
6. Back up `packages/server/.env` the way the other recovery phrases are backed up. It now holds two
   phrases for the demo chair, and both are needed.

### If the rotation was lost

If pqcKeyStatus reports a key that is not ours, someone else rotated first and the demo chair
account is theirs. Its board actions are now theirs too. Leave the demo endpoints off, seed a new
demo board under a new demo chair account with `scripts/seed-demo-board.ts`, set the new
`DEMO_BOARD_ID`, and say plainly on the docs page that the first demo board was taken. Its
documents were public by design, so nothing private was lost.
