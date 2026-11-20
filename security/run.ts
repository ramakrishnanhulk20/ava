import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { keccak256 } from "viem";
import { REGISTRY_CODE_KECCAK } from "../packages/server/src/config.ts";
import { attacks as contract } from "./attacks/contract.ts";
import { attacks as demo, seatAttacks as seats } from "./attacks/demo.ts";
import { attacks as offlineAttacks } from "./attacks/offline.ts";
import { attacks as proxy } from "./attacks/proxy.ts";
import { attacks as relay } from "./attacks/relay.ts";
import { attacks as sponsor } from "./attacks/sponsor.ts";
import { attacks as uploads, lateAttacks } from "./attacks/uploads.ts";
import { COST, NOT_RUN, SETUP, asAttack, type Attack, type Result, type SetupName } from "./lib/attack.ts";
import { balanceOf, formatQor, pqcStatus } from "./lib/chain.ts";
import { Ctx } from "./lib/context.ts";
import { dev, ownHeaders } from "./lib/dev.ts";
import { loadSuiteEnv } from "./lib/env.ts";
import { REGISTRY, assertNoForeignSecrets, assertServerTarget, assertTestnet, installFetchGuard, installOfflineGuard } from "./lib/guard.ts";
import { FILL_RANGE, FUND_FULL_UQOR } from "./lib/identities.ts";
import { KEM_FEE_EST_UQOR, MLDSA_FEE_UQOR, isOurProvenKey, kemOf } from "./lib/people.ts";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const RESULTS = fileURLToPath(new URL("./results/", import.meta.url));

interface Area {
  name: string;
  where: string;
  attacks: readonly Attack[];
}

/**
 * The run order. The offline proofs go first and take seconds. Uploads go next so C44's 50-minute
 * verify window runs out while everything else runs, and its last check goes at the end. C41 goes
 * before every other attack that joins the demo board, so a board an older server left full meets
 * its board_full check first, and after C7 so it can reuse C7's fill identities. The sponsor goes
 * before the relay because C40's guest is the identity C27 funds.
 */
const AREAS: readonly Area[] = [
  { name: "offline", where: "no network: @ava/core and the pinned QoreChain SDK", attacks: offlineAttacks.map(asAttack) },
  { name: "uploads", where: "dev server, live blob store", attacks: uploads },
  { name: "proxy", where: "dev server", attacks: proxy },
  { name: "contract", where: "live chain", attacks: contract },
  { name: "seats", where: "dev server, live chain", attacks: seats },
  { name: "sponsor", where: "dev server, live chain", attacks: sponsor },
  { name: "relay", where: "dev server, live chain", attacks: relay },
  { name: "demo", where: "dev server, live chain", attacks: demo },
  { name: "late", where: "dev server, live blob store", attacks: lateAttacks },
];

const SERVER_TESTS = "packages/server/test/";

interface NotRunLive {
  id: string;
  what: string;
  /** The unit tests that prove it, by file under packages/server/test and exact test name. */
  tests: readonly { file: string; names: readonly string[] }[];
  why: string;
}

/**
 * Shown by every run, dry run and list: what is not attacked live, the unit tests that prove it
 * instead, and why. `--list` checks that every named test is still in its file.
 */
const NOT_RUN_LIVE: readonly NotRunLive[] = [
  {
    id: "C25-leak-halt",
    what: "a relayer window spent outside our own sends halts the relayer and closes the window, a failed close is tried again, and the halt holds on every later day until an operator clears it (audit A4-3)",
    tests: [
      { file: "window.test.ts", names: ["halts the day and closes the window when the chain shows one more transaction or 1 uqor more than we sent", "on a halted day opens nothing, and still closes a live window it finds"] },
      { file: "relay.test.ts", names: ["on a halted day tries the failed close again before answering, and still holds the halt the next UTC day", "holds a leak halt on every later day until an operator clears it, then serves again"] },
    ],
    why: "triggering it live would stop the relayer, and the demo with it, until an operator clears it",
  },
  {
    id: "C24-nonce-leak",
    what: "a transaction signed with the relayer's key outside our server, landing between a window read and its renewal where no window counter sees it, is caught by the stored nonce: the relayer halts and closes (audit A4-2)",
    tests: [{ file: "relay.test.ts", names: ["halts and closes when a transaction lands between the window read and its renewal, where no window counter can see it"] }],
    why: "it needs the relayer's key used outside our server, and the halt it proves would then stop the relayer until an operator clears it",
  },
  {
    id: "C24-nonce-rule",
    what: "the relayer's stored nonce moves only by compare-and-set from the value read, and only once our recorded hash at that nonce is on chain: a send the node refused whose nonce a foreign transaction then took halts the relayer, one of ours the node called refused that lands after all does not, one still waiting for a block refuses without halting, a chain two nonces past with only the first ours halts, and a nonce or send record the store writes twice never leaves a nonce for a foreign transaction to hide in",
    tests: [
      {
        file: "relay.test.ts",
        names: [
          "halts on the next relay when a send the node refused lost its nonce to someone else's transaction",
          "does not halt when a send the node said it refused lands after all",
          "refuses, without halting or moving the stored nonce, while a send of ours still waits for a block, and serves once it lands",
          "halts when the chain is two nonces past the stored one and only the first is ours",
          "never moves the stored nonce twice for one write applied twice, so no nonce is skipped for a foreign transaction to hide in",
        ],
      },
      { file: "window.test.ts", names: ["counts a send record written twice by a retried store request once, so it never covers a transaction of someone else's"] },
    ],
    why: "each case needs a transaction signed with the relayer's key outside our server, a node refusal we cannot cause, or a store that applies one write twice, and the halt it proves would stop the relayer until an operator clears it",
  },
  {
    id: "C24-chair-budget",
    what: "one chair stops at its own 1.5 QOR day long before the chairs' share is gone, a second chair is still served, and the day's ledger settles to each receipt's real fee (audit A4-1)",
    tests: [{ file: "relay.test.ts", names: ["stops one chair at its own daily budget, long before the chairs' share is gone, and still serves a second chair", "settles the day's ledger down to each receipt's real fee, so ten adds cost what the chain charged"] }],
    why: "reaching one chair's day takes dozens of real relays that our relayer pays for",
  },
  {
    id: "C40-nonce-in-flight",
    what: "a second, different action at a board nonce or create nonce that already has one in flight answers 409 nonce_in_flight and moves no counter, the nonce is free again once a receipt is in, a revert included, and at once after a refusal before broadcast, and the valid total counts an action only once its pre-flight under the send lock passes",
    tests: [
      {
        file: "relay.test.ts",
        names: [
          "answers a second, different action at a board nonce or create nonce with one in flight 409 nonce_in_flight, and moves no counter",
          "frees the nonce once a receipt is in, even for a revert, and at once for a refusal before broadcast",
          "counts an action against the valid total only once its pre-flight under the send lock passes",
        ],
      },
    ],
    why: "an action stays in flight for a block or two, too short a moment to aim a second signed action at on purpose; C40-copies shows live that byte-identical copies are relayed once",
  },
  {
    id: "C40-valid-last",
    what: "the valid total and the per-board and per-chair counts move last, after the post bytes, the chair's daily ledger, the gas check and every other refusal a caller can cause, so 60 relays of one chair's refused action move none of them, and a relay its chair's hourly count refuses under the send lock gives the day's booking back",
    tests: [
      {
        file: "relay.test.ts",
        names: [
          "moves no per-board, per-chair or valid counter for 60 relays of one chair's action refused for its post bytes, its daily budget or its gas",
          "gives back the day's booking of a relay its chair's hourly count refuses under the send lock, after both of two relays passed the read before it",
        ],
      },
    ],
    why: "it needs one chair's post bytes or daily budget spent first: 100 MiB posted for good, or 1.5 QOR of relays our relayer pays",
  },
  {
    id: "C40-sent-only",
    what: "a relay refused under the send lock, by the nonce check while a send of ours still waits for a block (503 window_unavailable) or by the 45 s send cutoff (503 out_of_time), moves no per-board, per-chair or valid counter: those move only right before a send is recorded",
    tests: [
      {
        file: "relay.test.ts",
        names: [
          "moves no counter for a relay the nonce check refuses 503 window_unavailable while a send of ours still waits for a block",
          "moves no counter for a relay whose nonce check waits it past the 45 s send cutoff, answered 503 out_of_time",
        ],
      },
    ],
    why: "it needs one of our relayer's sends still waiting for a block, or a relay held past 45 s, at the moment the next relay arrives, and this suite can time neither from outside",
  },
  {
    id: "C40-mark-gives-way",
    what: "a board nonce mark gives way: once the send the node refused at that nonce is unknown to the chain, a different action may land there, so a chair can cancel by landing (C26), and the same bytes may be relayed again; a mark with no transaction yet holds only while its own relay is inside its deadline; a send that turns up before the next action reaches the send lock still refuses it 409 and moves no counter",
    tests: [
      {
        file: "relay.test.ts",
        names: [
          "lets a different action land at a board nonce once the send the node refused there is unknown to the chain, so a chair can cancel by landing (C26)",
          "relays the same bytes again once the send the node refused is unknown to the chain, and refuses copies and re-signed actions 409 while the chain holds it",
          "holds a mark that has no transaction yet only while its own relay is inside its deadline",
          "refuses a different action 409 nonce_in_flight, moving no counter, when the send the chain did not know turns up before that action reaches the send lock",
        ],
      },
    ],
    why: "each case needs the node to refuse our relayer's send, or a relay to stop between its mark and its broadcast, and this suite can cause neither from outside",
  },
  {
    id: "C40-reverted-mark",
    what: "a board nonce mark whose transaction reverted, with the board nonce unchanged, gives way to a different action or to the same bytes with no receipt seen, because the chain reader answers reverted from the receipt's own status",
    tests: [
      {
        file: "relay.test.ts",
        names: [
          "lets a different action, or the same bytes, take a nonce whose marked transaction reverted with the board nonce unchanged, with no receipt seen",
          "answers reverted for a transaction whose receipt says so, apart from one that landed, one pending and one the node does not know",
        ],
      },
    ],
    why: "it needs one of our relayer's sends to revert on chain after the registry's own pre-flight passed, which this suite cannot cause from outside",
  },
  {
    id: "C40-counted-once",
    what: "one signed action counts once an hour against its board, its chair and the valid total, even when its first send was lost and the same bytes were relayed again",
    tests: [{ file: "relay.test.ts", names: ["counts one action once against its board, its chair and the valid total, though its first send was lost and the same bytes were relayed again"] }],
    why: "it needs the node to lose one of our relayer's sends, which this suite cannot cause",
  },
  {
    id: "C41-demo-share",
    what: "the demo bot stops at its own share of the relayer's day and public chairs at theirs, each still served after the other's is spent (audit A5-3)",
    tests: [{ file: "relay.test.ts", names: ["stops the bot's relays, one per join and one per pass removal, at its own share, and a chair is still served after","stops public chair relays at the chairs' share, whatever a body says about scope, and the bot is still served after"] }],
    why: "spending either share live would use up the relayer's real day and stop judges",
  },
  {
    id: "C41-demo-hourly",
    what: "the demo bot takes each join's one relay, and each removal's one relay, from its own 120 an hour before anything is sealed or sent, so a join the hour cannot serve answers 503 demo_busy, sends nothing and counts nothing against the guest, two racing for the hour's last relay get one yes and one no, a sweep with none left removes no one, and the bot's relays never count against the public per-board, per-chair or valid limits",
    tests: [
      {
        file: "relay.test.ts",
        names: [
          "never counts the bot's relays per board, per chair or in the valid total, so a whole join lands while the public total refuses",
          "reserves the hour's demo relays one at a time, refuses any other count and the 121st, and starts afresh the next hour",
          "gives two relays racing for the hour's last demo relay one yes and one no, and fails closed on a store error",
        ],
      },
      {
        file: "demo.test.ts",
        names: [
          "reserves a join's one relay before anything is sealed or sent: an hour with none left answers 503 demo_busy, sends nothing and counts nothing against the guest",
          "removes no one when the hour has no demo relay left, and answers demo_busy",
        ],
      },
    ],
    why: "using up the hour's 120 demo relays live takes 60 joins at a board held at 34, each with its pass removal, inside one clock hour, each paid by our relayer, and stops judges joining for the rest of that hour",
  },
  {
    id: "C41-board-full",
    what: "a join at a full board answers 503 board_full: nothing sent, no one removed, nothing taken from the guest, the day or the hour, and a background pass scheduled, which seats the judge once it has freed seats; at a board nobody can be removed from, the mark is taken back and the pass removes no one and signs nothing",
    tests: [
      {
        file: "demo.test.ts",
        names: [
          "answers a join at a full board with 503 board_full: nothing sent, no one removed, nothing taken from the guest, the day or the hour, and a pressure pass scheduled",
          "seats a judge who met a full board once the pass it scheduled has freed seats, by the sweep's own removal, sealing the new epoch away from the guest removed",
          "answers board_full at a full board no one can be removed from, takes the admission mark back, and the pass it schedules removes no one and signs nothing",
        ],
      },
    ],
    why: "this suite cannot fill the board to its cap: every admitted join that leaves more than 34 members starts a pass that brings it back to 34, and only the demo chair can add a member. C41-full-board tests this branch live only on a run that finds the board already full, and its evidence names the path it ran",
  },
  {
    id: "C41-full-first",
    what: "a full board answers 503 board_full before the body is read, before any per-IP or hourly join count and before the challenge is used, so the judge's retry of the very same join is seated once the pass has run",
    tests: [{ file: "demo.test.ts", names: ["answers board_full before it reads the body, counts the IP or takes the challenge, so the judge's retry of the very same join is seated once the pass has run"] }],
    why: "as for C41-board-full, this suite cannot fill the board to its cap; C41-full-board sends the same join again live, on its first challenge, only on a run that finds the board already full",
  },
  {
    id: "C41-pressure-stops",
    what: "a pressure pass removes the oldest guests one relay each until the board is back to 34, stops at the first refused reservation or failed step, and a refused or failed pass leaves every guest seated and never adds to an unreadable run",
    tests: [
      {
        file: "demo.test.ts",
        names: ["removes the oldest guests one relay each until the board is back to 34, and stops at the first refused reservation", "leaves every guest seated when a pass is refused or fails, and never adds to an unreadable run"],
      },
    ],
    why: "a refusal mid-pass needs the hour's 120 demo relays spent, or the chain or the store to fail between two removals, and this suite causes neither",
  },
  {
    id: "C41-sweep-frees",
    what: "the scheduled sweep runs the pressure pass itself after its own expiry step, so a full board is brought back to 34 and a judge's retry is seated even with no background runner",
    tests: [{ file: "demo.test.ts", names: ["frees seats on a full board with no background runner: after its own expiry step it runs the pressure pass down to 34, so a judge's retry is seated"] }],
    why: "the dev server frees seats with its background runner, not the scheduled sweep, and this suite cannot fill the board to its cap",
  },
  {
    id: "C41-pass-clock",
    what: "a background pass reads the clock afresh for every removal, so a removal scheduled by a join is booked on the clock hour it runs in, and still frees a seat when that join took the last demo relay of the hour before",
    tests: [{ file: "demo.test.ts", names: ["books each removal on the clock hour it runs in, not the hour of the join that scheduled it"] }],
    why: "it needs a join to take the last of an hour's 120 demo relays seconds before the hour turns, and using up the hour live would stop judges joining for the rest of it",
  },
  {
    id: "C34-front-run-copy",
    what: "when a copy of the bot's own addMember lands first and the bot's reverts, the guest keeps its once-only mark, dated now, and a guest member with no record is dated from its EnvelopeGranted block and removed after six hours (audit A5-4)",
    tests: [{ file: "demo.test.ts", names: ["keeps the admission mark, dated now, when the bot's addMember reverts but the board shows the guest a member", "dates a guest member with no admission record from its latest EnvelopeGranted block, stores that time, and removes it once six hours have passed"] }],
    why: "it needs a race won against our own relayer in the public mempool, and the removal it proves comes six hours later",
  },
  {
    id: "C42-key-shared-sweep",
    what: "a guest whose ML-KEM key is byte-equal to a seeded director's is removed by the sweep first, whatever its age, and left out of the reseal, so no envelope holds one key under two accounts and the board never freezes; such a guest's join is refused 403 key_shared before any removal, even while another member's lookup is unreadable",
    tests: [
      {
        file: "demo.test.ts",
        names: [
          "removes a guest that published a seeded director's ML-KEM key first, then the expired guest, so no reseal holds one key twice",
          "refuses with 403 key_shared a guest whose ML-KEM key a current member published, before the day, the lock or any removal, and counts it against the guest",
          "admits a guest while another member's key lookup is unreadable, and still refuses a guest whose key a readable member published",
        ],
      },
    ],
    why: "the sweep case needs a copier already seated on the demo board, which takes the chain accepting a copied key and the join's own check missing it; C15-shared-kem-guest tests live whether the chain accepts the copy, and the join refusal when it does",
  },
  {
    id: "C34-admission-mark",
    what: "a join's once-per-guest mark lives only the lock's 150 s until the addMember is about to be relayed, so a failed join whose release is lost locks no one out",
    tests: [{ file: "demo.test.ts", names: ["holds the admission mark only for the lock's lifetime until the addMember is about to be relayed, so a failed join whose release is lost locks no one out"] }],
    why: "it needs a join to fail after its mark and the mark's release to be lost, a store failure this suite cannot cause",
  },
  {
    id: "C34-dead-add",
    what: "an admission mark whose addMember can no longer land gives way: a guest whose add, answered 202 without a receipt, the chain does not know or holds reverted may join again, and the scheduled sweep releases such a mark; an add still pending, or a mark that cannot be read yet, answers 503 admission_unsettled and keeps the mark, a landed one keeps its mark, and a mark write the store applied but whose reply was lost reads back as the join's own and locks no one out",
    tests: [
      {
        file: "demo.test.ts",
        names: [
          "frees a guest whose addMember, answered 202 without a receipt, the chain does not know or holds reverted, and still holds one whose addMember is pending",
          "keeps the mark of a guest whose addMember the receipt shows landed, even once that guest is no longer a member",
          "lets the scheduled sweep release the mark of a guest whose unseen addMember the chain does not know, and keep one still pending",
        ],
      },
      { file: "model/invariants.test.ts", names: ["every admission mark belongs to a member, a guest once seated, or an add still pending, and none survives a sweep once its add is dead"] },
    ],
    why: "it needs the bot's addMember to be lost or to revert after a 202, or the store to lose the reply to a write it applied, and this suite can cause none of them",
  },
  {
    id: "C27-sponsor-mark",
    what: "the sponsor gives an address its one chance back when the day's counters refuse or fail after the mark, because nothing was sent, and takes the mark back after a send only when the node refused it before any block",
    tests: [{ file: "sponsor.test.ts", names: ["gives the address's one chance back when the day's counters refuse or fail after the mark, because nothing was sent", "takes the address's mark back only when the node refused the send before any block"] }],
    why: "it needs the sponsor's day of 100 sends or 25 QOR spent, a store failure after the mark, or the node refusing a send, and this suite causes none of them",
  },
  {
    id: "C42-run-forgotten",
    what: "a member's run of unreadable key lookups is forgotten once its removal lands, so a guest admitted again later does not carry it back in",
    tests: [{ file: "demo.test.ts", names: ["forgets a removed member's unreadable run once its removal lands"] }],
    why: "it needs a member whose key lookup is unreadable on three sweeps in a row, a failure of the chain's KEM lookup this suite cannot cause, and the scheduled sweep, which the dev server does not run",
  },
  {
    id: "C31-cursor-cas",
    what: "the envelope sweep's cursor never moves past an unread block when two runs overlap, and a cursor write the store applies twice counts as one move",
    tests: [
      {
        file: "envelopeSweep.test.ts",
        names: [
          "never moves the cursor past an unread block when a run outlives its lock and another overlaps it",
          "counts a cursor write the store applied twice, after a client retry, as one move",
          "starts from the deploy block when no cursor is stored, even when that first write is applied twice",
        ],
      },
    ],
    why: "it needs two sweep runs to overlap or the store to apply one write twice, and this suite controls neither",
  },
  {
    id: "C31-listing-cursor",
    what: "the document sweep keeps its blob listing cursor across runs, written by compare-and-set, so a name behind 5,000 kept documents is reached, and starts over after the last page",
    tests: [{ file: "docupload.test.ts", names: ["keeps its listing cursor across runs, so a name behind 5,000 kept documents is reached, and starts over after the last page"] }],
    why: "it needs thousands of kept documents ahead of one blob in the store's listing, and the scheduled sweep, which the dev server does not run",
  },
  {
    id: "C31-listing-reset",
    what: "the document sweep starts again from the first page when the blob store refuses the listing cursor it holds, so a cursor the store will not take never stops every later run",
    tests: [{ file: "docupload.test.ts", names: ["starts again from the first page once the blob store refuses the listing cursor it holds, so that cursor never stops every later run"] }],
    why: "it needs the blob store to refuse a listing cursor it issued, which this suite cannot cause, and the scheduled sweep, which the dev server does not run",
  },
  {
    id: "C44-posted-only-keep",
    what: "a document is kept past two hours only if a DocumentPosted names it, through a wiped store too",
    tests: [
      {
        file: "docupload.test.ts",
        names: [
          "deletes verified documents no DocumentPosted names once two hours have passed, and keeps a posted one",
          "keeps a document the scan has not read two hours past, however old, until the scan passes it",
          "keeps every posted document through a wiped store, while the scan rebuilds its marks from the deploy block",
        ],
      },
    ],
    why: "the rule acts two hours after upload and this suite posts none of its documents on chain; C44-mark-only shows a verified one is still served at 52 minutes",
  },
  {
    id: "C44-post-bytes",
    what: "a post is refused 429 post_bytes once the chair's posted bytes for the UTC day plus the new document would pass 100 MiB, or the day's posts across all chairs would pass 1 GiB, and its bytes are given back when nothing was broadcast",
    tests: [
      {
        file: "relay.test.ts",
        names: [
          "refuses a chair's post 429 post_bytes once its bytes posted today plus the new one pass 100 MiB, and still serves another chair",
          "refuses any post 429 post_bytes once the day's posts would pass 1 GiB, whichever chair sends it",
          "gives a post's bytes back when nothing was broadcast",
        ],
      },
    ],
    why: "reaching 100 MiB live means posting four 25 MiB documents on chain, each kept for good at our own cost",
  },
  {
    id: "C44-posted-size",
    what: "the posted mark holds the cipherSize of every DocumentPosted naming a document, a posted document whose stored size is none of them is deleted and logged, verified or not, and one whose mark was written before marks held sizes is deleted only for a hash mismatch",
    tests: [
      {
        file: "docupload.test.ts",
        names: [
          "finds in each posted mark the cipherSize of every DocumentPosted naming the document, up to POSTED_SIZES_MAX of them",
          "deletes a posted document whose size is no posted cipherSize, verified or not, reading only the unverified, and logs it",
          "keeps a posted document whose mark was written before marks held sizes, deleting it only for a hash mismatch",
        ],
      },
      { file: "envelopeSweep.test.ts", names: ["reads the cipherHash and cipherSize of each DocumentPosted log of the registry, and refuses a log that is not one"] },
    ],
    why: "it needs a document posted on chain at a size other than the one stored, which the relay now refuses (C44-size-mismatch shows that live), and the scheduled sweep, which the dev server does not run",
  },
  {
    id: "C44-token-bytes",
    what: "a document token is issued for exactly the size its request declares and lets in no byte more, and a token request is refused 429 upload_bytes with no token once the declared bytes of the UTC day would pass 25 MiB for one client, four times that for its IPv6 /48, or fifty times that for every client together; a refused request books nothing and an unused token gives its bytes back",
    tests: [{ file: "docupload.test.ts", names: ["issues each token for exactly the size its request states, and refuses 429 upload_bytes with no token past 25 MiB a client, its /48 at four times that, or fifty times that in all, in a UTC day"] }],
    why: "reaching 100 MiB live means four 25 MiB tokens from one client in a day, and 1 GiB forty, each booked against the real day's budget; C28-token-size shows live that a token declaring 25 MiB lets in no byte more and that a declared size over the cap is refused 400 bad_size",
  },
  {
    id: "C44-registry-marks",
    what: "the posted and referenced marks are named for the registry, like the scan keys, so marks no scan of this registry wrote keep nothing, and the scan rebuilds its own from the deploy block before anything named by a hash is deleted",
    tests: [{ file: "docupload.test.ts", names: ["names the posted and referenced marks for the registry, so marks no scan of it wrote keep nothing, and rebuilds its own from the deploy block before it deletes anything named by a hash"] }],
    why: "it needs marks another registry's scan left in our store, which only a redeploy would leave, and the scheduled sweep, which the dev server does not run",
  },
  {
    id: "C28-posted-rehash",
    what: "a document posted on chain without a verify is hashed once by the sweep: bytes that match their name get the verified mark and are never read again, bytes that do not are deleted and logged, and one run hashes at most its byte budget and leaves the rest for the next",
    tests: [
      {
        file: "docupload.test.ts",
        names: [
          "deletes one whose bytes do not hash to its name, and logs it",
          "keeps one whose bytes hash to its name, marks it verified, and never reads it again",
          "hashes at most SWEEP_HASH_BYTES a run and leaves the rest, a mismatch included, unhashed for the next run",
        ],
      },
    ],
    why: "it needs a document posted on chain whose stored bytes differ from its name, and this suite posts none of its documents on chain",
  },
  {
    id: "C9-registry-code",
    what: "the relay checks the registry's code against the deploy record and answers every relay 503 registry_mismatch, moving no counter, when the address holds other code or none",
    tests: [{ file: "relay.test.ts", names: ["answers every relay 503 registry_mismatch and moves no counter when the registry address holds other code or none, or the code cannot be checked", "targets the registry recorded at deploy, with the code hash recorded there"] }],
    why: "it needs other code at the registry's address, which only a redeploy could put there; every live run checks that code hash itself before its first attack",
  },
  {
    id: "C23-per-48",
    what: "the relay, the demo join and the sponsor all count an IPv6 client through the one countClient rule: per /64, and every /64 of one /48 together at 4 times the per-IP limit, so the 81st request from one /48 is refused",
    tests: [
      { file: "ratelimit.test.ts", names: ["counts per IP under limit's own keys and per IPv6 /48 at 4 x perIp, with no total, and fails closed", "count all 65,536 /64s of one /48 together, refused after 4 x perIp, and leave other /48s alone"] },
      { file: "relay.test.ts", names: ["counts every /64 of one IPv6 /48 together at 4 times the per-IP limit, so the 81st relay from one /48 is refused"] },
      { file: "demo.test.ts", names: ["counts joins per IPv6 /48 too, so 81 /64s of one /48 hit the limit at 4 times the per-IP figure"] },
      { file: "sponsor.test.ts", names: ["counts requests per IPv6 /48 too, so 81 /64s of one /48 hit the limit at 4 times the per-IP figure"] },
    ],
    why: "the dev server listens on 127.0.0.1 and takes the client IP from the socket, so this suite can only speak from IPv4 loopback addresses; IPv6 has one loopback address, so no second /64 of a /48 exists to send from",
  },
  {
    id: "C23-budget-per-48",
    what: "the per-IP byte and token budgets, document tokens and envelope upload bytes, also count every /64 of one IPv6 /48 together at 4 times one IP's budget",
    tests: [{ file: "ratelimit.test.ts", names: ["counts every /64 of one IPv6 /48 together at 4 x max, so 10 /64s get at most 4 x one IP's document tokens or upload bytes an hour"] }],
    why: "as for C23-per-48: the dev server takes the client IP from its socket on 127.0.0.1, so this suite speaks from IPv4 loopback addresses only",
  },
  {
    id: "C22-upstream",
    what: "an upstream redirect, a body over 1 MiB or not JSON, the 8-second timeout, and no client header forwarded",
    tests: [
      {
        file: "proxy.test.ts",
        names: ["refuses an upstream redirect without following it", "refuses an upstream body over 1 MiB and a body that is not JSON", "gives up after 8 seconds with 504", "forwards no request header: Cookie, Authorization and X-Forwarded-For stay behind"],
      },
    ],
    why: "the upstream is QoreChain's public REST, which this suite does not control and does not attack",
  },
  {
    id: "C40-model",
    what: "sixteen properties of the relay, the demo bot and the document path, checked after every command of randomised runs against the real handlers and stores. Requests overlap at every store and chain call, the chain can be slow, lose a transaction, lose or falsify a receipt, or have its nonce used by a foreign key, and the store loses replies on most writes, increments included, with hour and day boundaries crossed. Among them: every handler answers; counters match the distinct actions handed to the node; no join removes anyone; admission marks stay true and none outlives a dead add; spend, shares and byte budgets hold; a write retried after a lost reply never understates a ledger; one action is in flight per nonce; a join refused for a full board or a busy bot leaves nothing behind",
    tests: [
      {
        file: "model/invariants.test.ts",
        names: [
          "every handler answers and none throws",
          "each per-board, per-chair and valid hourly counter holds no more than the distinct actions handed to the node in its window, and no fewer than those handed over there for the first time",
          "no join removes anyone, even one that meets a board another join filled while it waited for the lock, and every removal is a sweep's or a pressure pass's, of a guest",
          "every admission mark belongs to a member, a guest once seated, or an add still pending, and none survives a sweep once its add is dead",
          "every day's booked spend covers the real fees of what was handed over that day by the world clock, and is never negative",
          "the relayer halts exactly when a foreign transaction used its nonce, and never otherwise",
          "post bytes booked equal the verified sizes of posts handed to the node; no kept document differs from a posted cipherSize; every posted document and referenced envelope survives every sweep; token bytes stay under their daily caps",
          "once every transaction handed over at a board nonce is unknown to the chain or reverted, neither a different action there nor the same bytes again is refused 409",
          "a write retried after a lost reply never makes a ledger or byte budget show less than was booked and not given back",
          "two different actions at one board nonce, or two copies of one action, are never both handed to the node while the first is pending",
          "a join answered board_full or demo_busy reserves no demo relay, takes nothing from the day, sends nothing and leaves no mark; one that met a board already full takes no hourly join and keeps its challenge",
          "no removal takes the demo board below DEMO_GUEST_CAP minus DEMO_FREE_SEATS members unless its guest was due anyway: six hours old, or with a KEM key gone wrong",
          "each share of the day's spend, as the code booked it, stays at or under its ceiling",
          "a relay that moved the per-board, per-chair or valid hourly counters handed a transaction to the node, or was refused by one of those counters",
          "a dead add's mark never refuses its guest",
          "a guest never sent an add is never refused already_admitted or admission_unsettled, unless another join of it ran at the same time",
        ],
      },
    ],
    why: "it drives thousands of orderings, lost replies and clock edges that a live run would meet only by chance; in packages/server it runs with npx vitest run test/model",
  },
];

const testsText = (p: NotRunLive): string => p.tests.map((t) => `${SERVER_TESTS}${t.file}: ${t.names.map((n) => `"${n}"`).join(", ")}`).join(", and ");
const notRunLine = (p: NotRunLive): string => `${p.id}: ${p.what}. Proven by ${testsText(p)}. Why not live: ${p.why}.`;

/** C-numbers the backend upholds that no live attack here covers, each with the reason. */
const NO_LIVE_ATTACK: readonly { c: string; why: string }[] = [
  { c: "C11", why: "fresh epoch keys are randomness inside @ava/core's newEpochKey; nothing outside can push on it or see it; core's tests cover the source" },
  { c: "C14", why: "one key and a fresh nonce per document happen inside encryptDocument; not observable from outside; core's tests cover it" },
  { c: "C18, C19, C20, C21", why: "browser invariants (stored identity, CSP, rendering, strangers' boards); the app is not built yet" },
  { c: "C26", why: "the browser treats a relay hash as a claim until the receipt; the app is not built yet" },
  { c: "C31", why: "showing state is shared needs two server instances or a restart of the dev server, which this suite does not control; C27-second-request and C43-replay show the once-only records hold across requests, and C31-cursor-cas above is proven by unit tests" },
  { c: "C32", why: "its proof is a grep of the built app's bundles, pages and server-component payload, which do not exist yet" },
  { c: "C37", why: "the demo chair's key is attacked through C33 (no signing oracle) and C36 (the drill key); its rotation step is the runbook's own dry run, which reads the demo chair's phrase and so stays outside this suite" },
  { c: "C38, C39", why: "the exposure ledger runs in the browser; not built yet" },
];

const allAttacks = (): { area: Area; attack: Attack }[] => AREAS.flatMap((area) => area.attacks.map((attack) => ({ area, attack })));

function setupCost(): { names: SetupName[]; uqor: bigint } {
  const names = [...new Set(allAttacks().flatMap(({ attack }) => attack.needs ?? []))];
  return { names, uqor: names.reduce((s, n) => s + SETUP[n].costUqor, 0n) };
}

const q = (uqor: bigint): string => `${formatQor(uqor)} QOR`;

function dryRun(): void {
  const all = allAttacks();
  const setup = setupCost();
  const prerequisite = MLDSA_FEE_UQOR + KEM_FEE_EST_UQOR;
  const attacksUqor = all.reduce((s, { attack }) => s + attack.costUqor, 0n);
  const serverUqor = all.reduce((s, { attack }) => s + (attack.serverUqor ?? 0n), 0n);
  const gated = all.filter(({ attack }) => attack.id === "C7-exceed-64" || attack.id === "C41-full-board" || attack.id === "C42-bad-key-guest");
  const gatedUqor = gated.reduce((s, { attack }) => s + attack.costUqor, 0n);
  const total = setup.uqor + attacksUqor + COST.windowClose;
  console.log("Ava attack suite, dry run. Nothing is sent and nothing is read from the network.");
  console.log(`Scope: BoardRegistry ${REGISTRY} and PqcProbe on chain 9800 / qorechain-diana, and our own handlers on the dev server at 127.0.0.1:8787.`);
  console.log(`\nPrerequisite, once: npx tsx register-wallet.ts registers the wallet's ML-DSA-87 and ML-KEM-1024 keys, about ${q(prerequisite)}.`);
  console.log("\nSetup, paid once a run by the first attack that needs it, and nothing when the chain already has it:");
  for (const n of setup.names) console.log(`  ${n.padEnd(8)} ${q(SETUP[n].costUqor).padStart(13)}  ${SETUP[n].what}`);
  console.log("\nAttacks, in run order. Cost is test QOR from the security wallet; server is what our own relayer or sponsor spends.");
  for (const { area, attack } of all) {
    const server = attack.serverUqor === undefined ? "" : `, server ${q(attack.serverUqor)}`;
    console.log(`  ${attack.id}  [${area.name}: ${area.where}; wallet ${q(attack.costUqor)}${server}]`);
    console.log(`      ${attack.claim}`);
    if (attack.costNote !== undefined) console.log(`      cost: ${attack.costNote}`);
  }
  console.log(`\n${all.length} attacks in ${AREAS.length} groups.`);
  console.log(
    `Total from the security wallet: ${q(total)} (setup ${q(setup.uqor)}, attacks ${q(attacksUqor)}, the window close at the end ${q(COST.windowClose)}). ` +
      `Of that, ${q(gatedUqor)} is the three budget-gated attacks (${gated.map(({ attack }) => attack.id).join(", ")}), which report "not run" with their cost when the wallet cannot cover them: ${q(total - gatedUqor)} without them.`,
  );
  console.log(`Fund the wallet with at least ${q(prerequisite + total + 300_000n)} for everything (prerequisite, total and the 0.3 QOR floor the wallet never goes below), or ${q(prerequisite + total - gatedUqor + 300_000n)} without the gated three.`);
  console.log(`Our own relayer and sponsor would spend about ${q(serverUqor)} more, from their own accounts.`);
  console.log(
    `Realised versus unrealised: most of the total is QOR sent to test identities (${FILL_RANGE.count} of them for the fills). Their two registrations burn up to ${q(prerequisite)} each, realised; ` +
      `at least ${q(FUND_FULL_UQOR - prerequisite)} each stays on them, unrealised.`,
  );
  console.log("\nNot run live, proven by unit tests instead:");
  for (const p of NOT_RUN_LIVE) console.log(`  ${notRunLine(p)}`);
  console.log("\nC-numbers the backend upholds with no live attack here:");
  for (const n of NO_LIVE_ATTACK) console.log(`  ${n.c}: ${n.why}.`);
}

const THREAT_MODEL = "docs/security/threat-model.md";

/** Section C's invariants by C-number, read from the threat model's own `- C<n>. ` lines. */
function threatLines(): Map<string, string> {
  const lines = new Map<string, string>();
  const path = `${ROOT}${THREAT_MODEL}`;
  if (!existsSync(path)) return lines;
  for (const m of readFileSync(path, "utf8").matchAll(/^- (C\d+)\. (.+)$/gm)) lines.set(m[1]!, m[2]!.trim());
  return lines;
}

/** The invariant's own first sentence, which states it; the rest of its line is detail and proof. */
const headline = (line: string): string => {
  const end = line.search(/\.(\s|$)/);
  return end < 0 ? line : line.slice(0, end + 1);
};

/** Every attack id with the threat-model line it tries to break, then the promises proven by unit tests, each test checked against its file. */
function list(): void {
  const lines = threatLines();
  const lineOf = (id: string): string => {
    const c = /^C\d+/.exec(id)?.[0] ?? id;
    const line = lines.get(c);
    return line === undefined ? `${c}: NOT IN SECTION C OF ${THREAT_MODEL}` : `${c}. ${headline(line)}`;
  };
  console.log(`Ava attack suite: every attack id and the line of ${THREAT_MODEL}, section C, that it tries to break.${lines.size === 0 ? ` ${THREAT_MODEL} WAS NOT FOUND.` : ""}`);
  for (const area of AREAS) {
    console.log(`\n${area.name} (${area.where})`);
    for (const attack of area.attacks) console.log(`  ${attack.id.padEnd(26)} ${lineOf(attack.id)}`);
  }
  console.log("\nNot run live, proven by unit tests instead");
  let missing = 0;
  for (const p of NOT_RUN_LIVE) {
    console.log(`  ${p.id.padEnd(26)} ${lineOf(p.id)}`);
    for (const t of p.tests) {
      const path = `${ROOT}${SERVER_TESTS}${t.file}`;
      const source = existsSync(path) ? readFileSync(path, "utf8") : "";
      for (const name of t.names) {
        const found = source.includes(`"${name}"`);
        if (!found) missing++;
        console.log(`      ${SERVER_TESTS}${t.file}: "${name}"${found ? "" : "  NOT FOUND IN THE FILE"}`);
      }
    }
  }
  const offlineCount = AREAS.find((a) => a.name === "offline")?.attacks.length ?? 0;
  const total = allAttacks().length;
  console.log(`\n${total} attacks (${offlineCount} offline, ${total - offlineCount} live) and ${NOT_RUN_LIVE.length} promises proven by unit tests${missing === 0 ? ", every named test found in its file" : `; ${missing} NAMED TESTS NOT FOUND`}.`);
  if (missing > 0) process.exitCode = 1;
}

interface Row {
  id: string;
  claim: string;
  held: boolean;
  notRun: boolean;
  evidence: string;
}

function git(args: string[]): string {
  try {
    return execFileSync("git", args, { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "";
  }
}

const cell = (s: string): string => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
const short = (s: string, n: number): string => (s.length > n ? `${s.slice(0, n - 3)}...` : s);
/** Always yes or no; "no (not run)" when the attack could not run. */
const heldCell = (r: Row): string => (r.held ? "yes" : r.notRun ? "no (not run)" : "NO");

function writeResults(stamp: string, header: string[], rows: Row[], footer: string[]): string {
  mkdirSync(RESULTS, { recursive: true });
  const name = `run-${stamp}.md`;
  const table = ["| id | claim | held | evidence |", "|---|---|---|---|", ...rows.map((r) => `| ${r.id} | ${cell(r.claim)} | ${heldCell(r)} | ${cell(r.evidence)} |`)];
  const unitTested = ["## Not run live, proven by unit tests instead", "", ...NOT_RUN_LIVE.map((p) => `- NOT RUN live: ${notRunLine(p)}`)];
  const none = ["## C-numbers with no live attack here", "", ...NO_LIVE_ATTACK.map((n) => `- ${n.c}: ${n.why}.`)];
  writeFileSync(`${RESULTS}${name}`, [...header, "", ...table, "", ...footer, "", ...unitTested, "", ...none, ""].join("\n"), "utf8");
  return `security/results/${name}`;
}

async function live(): Promise<number> {
  const startedAt = Date.now();
  const stamp = new Date(startedAt).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  assertNoForeignSecrets();
  const env = loadSuiteEnv();
  installFetchGuard(env.blobOrigin === undefined ? {} : { blobOrigin: env.blobOrigin });
  assertServerTarget();
  const chain = await assertTestnet();
  const ctx = await Ctx.create(env, startedAt);
  const code = await ctx.client.getCode({ address: REGISTRY });
  if (code === undefined || keccak256(code) !== REGISTRY_CODE_KECCAK) throw new Error(`The code at ${REGISTRY} is not the BoardRegistry recorded at deploy. Stopping before any attack.`);
  const [pqc, kem] = await Promise.all([pqcStatus(ctx.wallet.qor1), kemOf(ctx.wallet.evm)]);
  if (!isOurProvenKey(pqc, ctx.wallet) || kem === undefined) throw new Error("The security wallet's keys are not registered. Run: npx tsx register-wallet.ts");
  const ping = await dev({ method: "GET", path: "/api/security-suite-ping", from: ctx.ips.fresh() }).catch(() => undefined);
  if (ping === undefined || ping.status !== 404 || ping.error !== "not_found" || !ownHeaders(ping)) {
    throw new Error("The dev server is not answering at 127.0.0.1:8787. In packages/server run: npx tsx scripts/dev-server.ts");
  }
  const commit = git(["rev-parse", "HEAD"]) || "unknown";
  const dirty = git(["status", "--porcelain", "--", "packages", "security"]);
  const startBalance = await balanceOf(ctx.wallet.qor1);

  ctx.log(`Ava attack suite, live run. Started ${new Date(startedAt).toISOString()}.`);
  ctx.log(`chain:    ${chain.cosmos} and EVM ${chain.evm} confirmed; registry code hash matches the deploy record`);
  ctx.log(`wallet:   ${ctx.wallet.qor1} / ${ctx.wallet.evm}, ${q(startBalance)}`);
  ctx.log(`code:     commit ${commit}${dirty === "" ? "" : " with uncommitted changes under packages/ or security/"}`);

  const rows: Row[] = [];
  let stopped: string | undefined;
  try {
    for (const { area, attack } of allAttacks()) {
      if (stopped !== undefined) {
        rows.push({ id: attack.id, claim: attack.claim, held: false, notRun: true, evidence: `${NOT_RUN}the run stopped at ${stopped}` });
        continue;
      }
      ctx.log(`\n${attack.id} (${area.name}): ${attack.claim}`);
      try {
        await ctx.prepare(attack.needs);
        const result = await attack.run(ctx);
        const notRun = result.evidence.startsWith(NOT_RUN);
        rows.push({ id: attack.id, claim: attack.claim, held: result.held, notRun, evidence: result.evidence });
        ctx.log(`  ${notRun ? "NOT RUN" : result.held ? "held" : "NOT HELD"}: ${result.evidence}`);
      } catch (err) {
        stopped = attack.id;
        const message = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
        rows.push({ id: attack.id, claim: attack.claim, held: false, notRun: false, evidence: `UNEXPECTED EXCEPTION, the run stopped here: ${message.slice(0, 600)}` });
        ctx.log(`  UNEXPECTED EXCEPTION, stopping: ${message.slice(0, 600)}`);
      }
    }
  } finally {
    try {
      const closed = await ctx.lane.close();
      ctx.log(`\nwindow:   ${closed === undefined ? "the wallet holds no live window" : `the wallet's window closed in ${closed}`}`);
    } catch (err) {
      ctx.log(`\nwindow:   the close failed (${err instanceof Error ? err.message.slice(0, 200) : String(err)}); close it before the next run`);
    }
  }

  const endBalance = await balanceOf(ctx.wallet.qor1).catch(() => undefined);
  const funded = ctx.people.fundedUqor.reduce((s, f) => s + f.uqor, 0n);
  const identityFees = ctx.people.fees.filter((f) => !f.what.startsWith("fund ")).reduce((s, f) => s + f.uqor, 0n);
  const held = rows.filter((r) => r.held).length;
  const notRunCount = rows.filter((r) => r.notRun).length;
  const footer: string[] = ["## Money", ""];
  if (endBalance === undefined) {
    footer.push("- The wallet's end balance could not be read.");
  } else {
    const spent = startBalance - endBalance;
    footer.push(`- Realised: ${q(spent - funded + identityFees)} burned in fees and gas (the wallet's own ${q(spent - funded)}, the test identities' registrations ${q(identityFees)}).`);
    footer.push(`- Unrealised: ${q(funded - identityFees)} sent to test identities this run and still held by them.`);
    footer.push(`- The wallet went from ${q(startBalance)} to ${q(endBalance)}. Our relayer's and sponsor's spend is not measured here; the hashes are in the evidence.`);
  }
  const header = [
    `# Attack run ${stamp}`,
    "",
    `- Code: commit ${commit}${dirty === "" ? "" : " (with uncommitted changes under packages/ or security/)"}`,
    `- Chain: ${chain.cosmos}, EVM ${chain.evm}; BoardRegistry ${REGISTRY}, code hash checked against the deploy record`,
    `- Server: packages/server/scripts/dev-server.ts on 127.0.0.1:8787`,
    `- Wallet: ${ctx.wallet.qor1} / ${ctx.wallet.evm}`,
    `- Started ${new Date(startedAt).toISOString()}, ended ${new Date().toISOString()}`,
    `- Result: ${held} of ${rows.length} held, ${notRunCount} not run, ${rows.length - held - notRunCount} not held${stopped === undefined ? "" : `; stopped at ${stopped} by an unexpected exception`}`,
  ];
  const path = writeResults(stamp, header, rows, footer);

  console.log("\n| id | claim | held | evidence |");
  for (const r of rows) console.log(`| ${r.id} | ${short(r.claim, 90)} | ${heldCell(r)} | ${short(r.evidence, 160)} |`);
  console.log(`\n${header.at(-1)!.slice(2)}`);
  for (const line of footer.slice(2)) console.log(line);
  console.log(`report:   ${path}`);
  return held === rows.length ? 0 : 1;
}

/**
 * Runs every offline attack, or only the ones named, with every network request refused and no
 * wallet, key or server in use. Exit code 0 only when each one held.
 */
async function offlineRun(ids: readonly string[]): Promise<number> {
  installOfflineGuard();
  const unknown = ids.filter((id) => !offlineAttacks.some((a) => a.id === id));
  if (unknown.length > 0) throw new Error(`No offline attack is named ${unknown.join(", ")}. The offline attacks are ${offlineAttacks.map((a) => a.id).join(", ")}.`);
  const chosen = ids.length === 0 ? offlineAttacks : offlineAttacks.filter((a) => ids.includes(a.id));
  console.log("Ava attack suite, offline run. Every network request is refused; no wallet, key or server is used.");
  let held = 0;
  for (const attack of chosen) {
    console.log(`\n${attack.id}: ${attack.claim}`);
    let result: Result;
    try {
      result = await attack.run();
    } catch (err) {
      result = { held: false, evidence: `UNEXPECTED EXCEPTION: ${err instanceof Error ? `${err.name}: ${err.message}` : String(err)}` };
    }
    console.log(`  ${result.held ? "HELD" : "NOT HELD"}`);
    for (const line of result.evidence.split("; ")) console.log(`  - ${line}`);
    if (result.held) held++;
  }
  console.log(`\n${held} of ${chosen.length} offline attacks held.`);
  return held === chosen.length ? 0 : 1;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--dry-run")) {
    dryRun();
    return;
  }
  if (args.includes("--list")) {
    list();
    return;
  }
  if (args[0] === "--offline") {
    process.exitCode = await offlineRun(args.slice(1));
    return;
  }
  process.exitCode = await live();
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
