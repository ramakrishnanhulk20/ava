# Runbook: the server's known limits and the demo chair's key

This file is for whoever runs Ava's server. It says what the server's defences do not stop, and the
exact steps for the one emergency that has a written answer: a leak of the demo chair's ML-DSA-87
key. The invariants it refers to (C23, C37, C40 to C44) are in `docs/security/threat-model.md`.

## Known limits

### Totals anyone can reach without a signature

Every endpoint that answers without a signature counts each caller's IP address (as the hosting
platform reports it, never a header) and keeps a total for everyone. The totals are set high, so
only an attacker with many addresses can reach them. Reaching one stops that endpoint for every
honest caller until its hour ends. That is the residual risk, endpoint by endpoint, per hour:

| Endpoint | Per IP address | Total | Addresses needed to reach the total | What reaching it costs us or blocks |
|---|---|---|---|---|
| Envelope upload | 20 uploads, and 2.2 MB | 1,000 uploads | 50 | Blocks new envelopes, so demo joins and chair actions that need one wait. Up to 110 MB an hour of stored bytes, each upload a parsed QoreSeal envelope, each deleted two hours after upload unless the registry names it. |
| Document upload token | 30 requests, 12 tokens | 1,500 requests | 50 | Blocks new document uploads. Each token places up to 25 MiB straight into the blob store, so 1,500 tokens an hour, from 125 addresses or more, can place about 37 GiB. Each is deleted at verify or within an hour by the document sweep unless it hashes to its name. Storage and transfer are billed meanwhile. |
| Document verify | 30 | 1,500 | 50 | Blocks verifies. Each verify reads at most one unverified blob of up to 25 MiB; a verified one is answered from its mark and never read again. |
| Demo guest challenge | 10 | 1,000 | 100 | Judges cannot get a challenge, so cannot join, until the hour ends. |
| Relay, request whose pre-flight fails | 20 (every request counts) | 3,000 rejected | 150 | Failed pre-flights are answered 429 instead of 422 past the total. Real actions are never blocked by them: an action whose signature the registry accepts is counted per chair, per board and in a separate valid-action total (C40). Each rejected request still costs one call to the public EVM RPC. |
| Chain REST proxy | 60 a minute | 300 a minute | 5 | Kept low on purpose (C23): every browser shares the server's own quota at the public REST, so a higher total would let one attacker spend that quota for everyone. Five addresses can stop the proxy for a minute at a time. |

Two things no limit here stops:

- A flood of junk from many addresses still makes the server call the public EVM RPC and REST, and
  the server's own quota there is shared by the relay, the sponsor and the demo bot. When that
  quota runs out, those endpoints answer "chain unreachable" and refuse; nothing is sent wrongly.
- A real signed action can be submitted again until it lands. Each copy passes the pre-flight, so it
  counts against that chair and board, and a copy that is broadcast after the first lands reverts
  at the relayer's cost. The per-chair limit (60 an hour) bounds this.

### The demo bot

- Every sweep looks up the ML-KEM key of every member (up to 40) and downloads every envelope of
  the current epoch to check whom the epoch key was sealed to. A lookup that fails for a reason
  that says nothing about the member (a timeout, the network, a malformed answer) stops that sweep
  and it runs again on the next schedule. A sweep that finds a guest with a missing, invalid or
  changed key removes that guest and leaves every such guest out of the new epoch; it removes one
  guest per run.
- A problem with the chair's or a seeded director's key stops every sweep and every full-board
  join, and logs a `demo_sweep_alert` line naming the member. Nobody is removed until it is fixed.
- A join at a full board relays two actions, the removal and then the admission. If the removal's
  receipt is not seen within 30 seconds, the join answers 503 busy and the judge tries again.
- A guest challenge can no longer be cancelled by a stranger: only a join that carries a valid
  signature over it consumes it (C43).

### Blob sweeps

- An envelope whose action lands more than two hours after its upload is deleted first (C44). The
  app must upload an envelope right before the chair signs; a signature lives at most one hour.
- The envelope sweep deletes nothing on a run that has not read the registry's logs up to the
  latest block, and stops with an error if its cursor is past the latest block, which means the
  chain is not the one it was reading (a testnet reset, or a wrong node). After a confirmed reset,
  delete the shared-store key `envsweep:next-block` so the sweep starts again from the registry's
  deploy block.

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
