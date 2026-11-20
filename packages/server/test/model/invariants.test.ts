// A randomised model of the relay, the demo bot and the document path. Each run builds a fresh
// world (the real MemoryStore on a clock the model moves, the real MemoryBlobBackend, and one stub
// chain that can be slow, lose transactions, lose receipts, lie in receipts and see foreign use of
// the relayer's key), drives the real handlers with up to 60 commands, and checks every promise
// below after every command, each from the model's own record of what it sent, when, and what the
// chain did, never from the store's log of what the code wrote. Most commands run one request; an
// overlap runs two or three at once, with fast-check's scheduler picking the next step at every
// store call, chain call and wait, and locks that wait and run out on the world's clock. Each
// command also draws how its store writes meet lost replies: none, a few by ordinal, every one, or
// each with probability 0.3; such a write (setIfAbsent, compareAndSet, delete or increment) lands
// and answers as the client's retry would. Some worlds hold the bot to three demo relays an hour,
// so demo_busy is reached. MODEL_RUNS, MODEL_COMMANDS and MODEL_SEED change the run, MODEL_ONLY
// picks invariants by number, MODEL_STOP_AT_FIRST ends at the first failing one and MODEL_TRACE
// prints every answer. A failure prints its seed, its path and the shrunk command list with its
// replay path (and, for an overlap, the turns each request took); MODEL_SEED, MODEL_PATH and
// MODEL_REPLAY set to those replay it against the same code. A property that fails is reported and
// left out of the next round, so every failing property gets its own shrunk counterexample.
//
// Not covered here: the live chain, the real Upstash store and the real blob store. A store that
// fails outright is not modelled, and the lock's own acquire and release never lose a reply. The
// stub chain gives each send the next free relayer nonce, so two senders signing one nonce, which
// a send lock run out under its holder would allow, is not modelled. The deadline helper races its
// work against a real timer, so an overlap in which a request has almost no time left may answer
// out_of_time by real time and replay differently. Invariant 1 allows the count of a relay whose
// own 55 s ran out after its counters moved; invariant 15 is the one that reports it. A request
// that straddles UTC midnight may book on either day (the code books on its own arrival time); a
// day further off is a failure. Board and transaction reads never fail outright (KEM lookups do),
// so a failed one is reached only through a request's time running out. Public boards carry fake signatures that the stub registry
// reads; only the demo bot's ML-DSA signatures are real. createBoard and transferChair are never
// relayed, fee quotes never spike, gas estimates never pass a ceiling, the sponsor and the chain
// proxy are not driven, and native window opens and closes never revert once committed. The
// browser's own receipt checks (C26) belong to the web app and are not here.
import fc from "fast-check";
import { hexToBytes } from "viem";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import * as config from "../../src/config.ts";
import { admittedKey } from "../../src/demo.ts";
import * as docupload from "../../src/docupload.ts";
import { DOCUMENT_KEEP_MS } from "../../src/docupload.ts";
import { clientKey } from "../../src/ratelimit.ts";
import { HALT_KEY, ledgerFor } from "../../src/window.ts";
import { HandlerThrew, commandArbs, worldInitArb, type Harness } from "./commands.ts";
import { DEMO_BOARD, PUBLIC_CHAIRS, T0, World, makeCast, utcDay, type Cast, type ChainTx } from "./world.ts";

// The bot derives the demo chair's keys from its phrase on every join and removal. The same
// derivation, cached, gives the same keys and keeps the model's thousands of runs inside minutes.
vi.mock("@ava/core", async (importOriginal) => {
  const real = await importOriginal<typeof import("@ava/core")>();
  const derived = new Map<string, ReturnType<typeof real.identityFromMnemonic>>();
  return {
    ...real,
    identityFromMnemonic: (phrase: string) => {
      const known = derived.get(phrase) ?? real.identityFromMnemonic(phrase);
      derived.set(phrase, known);
      return known;
    },
  };
});

// A world may tighten the demo bot's hourly relays so demo_busy is reached. The relay reads the
// constant on every reservation, so a getter lets each run set its own figure.
const knobs = vi.hoisted(() => ({ demoRelaysPerHour: 120 }));
vi.mock("../../src/config.ts", async (importOriginal) => {
  const real = await importOriginal<typeof import("../../src/config.ts")>();
  return {
    ...real,
    get DEMO_RELAYS_PER_HOUR() {
      return knobs.demoRelaysPerHour;
    },
  };
});

const RUNS = Number(process.env.MODEL_RUNS ?? 300);
/** Set for the planted-bug runs: the first property that fails ends the check. */
const STOP_AT_FIRST = process.env.MODEL_STOP_AT_FIRST !== undefined;
const MAX_COMMANDS = Number(process.env.MODEL_COMMANDS ?? 60);
const SEED = process.env.MODEL_SEED === undefined ? Date.now() % 2_147_483_647 : Number(process.env.MODEL_SEED);
/** A printed counterexample replays exactly with its seed, its path and its command replay path. */
const PATH = process.env.MODEL_PATH;
const REPLAY = process.env.MODEL_REPLAY;
/** A deep run of thousands can take an hour; a failing one also shrinks. */
const BUDGET_MS = 4 * 3_600_000;

interface Invariant {
  id: number;
  title: string;
  /** What is wrong, or undefined when the promise holds. */
  check(h: Harness): Promise<string | undefined>;
}

class InvariantBroken extends Error {
  readonly id: number;

  constructor(id: number, message: string) {
    super(message);
    this.name = "InvariantBroken";
    this.id = id;
  }
}

const lower = (s: string): string => s.toLowerCase();
const t2s = (t: ChainTx): string => `${t.what} ${t.action ?? ""} ${t.hash.slice(0, 12)} (command #${t.seq}, ${t.state})`;
/** The relayer's spend ledgers by day: the total, the two shares and one chair's own, never the settled counters beside them. */
const SPEND_LEDGER = /^relayer:spend:\d{4}-\d{2}-\d{2}(?::chairs|:demo|:chair:0x[0-9a-f]{40})?$/;
/** The ledgers a run may start with spend already on, written straight into the store, so not in its log. */
const PRESPEND_KEYS = [ledgerFor("total", T0).key, ledgerFor("chairs", T0).key, ledgerFor("demo", T0).key, ledgerFor("chair", T0, PUBLIC_CHAIRS[0]).key];

function ceilingOf(key: string): bigint {
  if (key.endsWith(":chairs")) return config.CHAIRS_DAILY_CEILING_UQOR;
  if (key.endsWith(":demo")) return config.DEMO_DAILY_CEILING_UQOR;
  if (key.includes(":chair:")) return config.PER_CHAIR_DAILY_UQOR;
  return config.RELAYER_DAILY_CEILING_UQOR;
}
const count = async (h: Harness, key: string): Promise<bigint> => BigInt((await h.world.store.inner.get(key)) ?? "0");
/** A counter as the code meant it, without what increments retried after a lost reply added. */
const meant = (h: Harness, key: string): Promise<bigint> => h.world.store.intended(key);
/**
 * Every counter that books something with a twin it is given back on: the relayer's spend ledgers
 * and post byte ledgers (":settled"), and the document token byte budgets (":returned").
 */
const BOOKED = /^(?:relayer:spend:\d{4}-\d{2}-\d{2}(?::chairs|:demo|:chair:0x[0-9a-f]{40})?|relayer:posts:\d{4}-\d{2}-\d{2}(?::chair:0x[0-9a-f]{40})?|budget:docbytes.*)$/;
const givenBackKey = (key: string): string => (key.startsWith("budget:docbytes") ? `${key}:returned` : `${key}:settled`);

// Read by name and only if present, so a figure renamed or added in config is checked as it stands.
const configured = (name: string, fallback: number): number => (Object.keys(config).includes(name) ? Number((config as Record<string, unknown>)[name]) : fallback);
/** How long after a token ends its bytes may still be held for an upload begun in its last second. */
const GRACE_MS = Number((docupload as Record<string, unknown>).UNUSED_TOKEN_GRACE_MS ?? 3_600_000);

/** The document token byte caps, read from config so a change there is checked as it stands. */
function tokenCaps(): { client: number; net48: number; total: number } {
  const client = configured("DOC_BYTES_PER_CLIENT_DAY", 104_857_600);
  return { client, net48: configured("DOC_BYTES_PER_NET48_DAY", 4 * client), total: configured("DOC_BYTES_TOTAL_DAY", 1_073_741_824) };
}

/** The ledgers a transaction of ours books its worst case on, for one UTC day. */
function ledgerKeys(t: ChainTx, day: string): string[] {
  const noon = Date.parse(`${day}T12:00:00Z`);
  if (t.kind === "native") return [ledgerFor("total", noon).key];
  if (t.scope === "demo") return [ledgerFor("demo", noon).key, ledgerFor("total", noon).key];
  return [ledgerFor("chair", noon, t.chair).key, ledgerFor("chairs", noon).key, ledgerFor("total", noon).key];
}

/** The day's byte buckets one token counts in: its client, its IPv6 /48 if it has one, and everyone's total, each with its cap. */
function tokenBuckets(t: { clientIp: string; day: string }, caps: ReturnType<typeof tokenCaps>): [string, number][] {
  const client = clientKey(t.clientIp) ?? t.clientIp;
  const net48 = t.clientIp.includes(":") ? `${t.clientIp.split(":").slice(0, 3).join(":")}::/48` : undefined;
  return [[`${t.day} ${client}`, caps.client], ...(net48 === undefined ? [] : [[`${t.day} ${net48}`, caps.net48] as [string, number]]), [`${t.day} all`, caps.total]];
}

const INVARIANTS: Invariant[] = [
  {
    id: 0,
    title: "every handler answers and none throws",
    check: async () => undefined,
  },
  {
    id: 1,
    title: "each per-board, per-chair and valid hourly counter holds no more than the distinct actions handed to the node in its window, and no fewer than those handed over there for the first time",
    check: async (h) => {
      const w = h.world;
      const handed = [...w.txs.values()].filter((t) => t.what === "send" && t.scope === "public").sort((a, b) => a.logIndex - b.logIndex);
      const firstAt = new Map<string, number>();
      for (const t of handed) if (t.data !== undefined && !firstAt.has(t.data)) firstAt.set(t.data, t.logIndex);
      for (const [key, start] of w.store.windowStart) {
        const named = /^rate:relay:(?:board:(\d+)|chair:(0x[0-9a-f]{40})|valid)$/.exec(key);
        if (named === null) continue;
        const raw = await w.store.inner.get(key);
        if (raw === null) continue;
        const [, board, chair] = named;
        const mine = handed.filter((t) => t.logIndex > start.index && (board !== undefined ? t.boardId === BigInt(board) : chair !== undefined ? lower(t.chair ?? "") === chair : true));
        const distinct = new Set(mine.map((t) => t.data)).size;
        // An action counted once is not counted again while its counted mark lives (countOnce), even
        // when its lost send is repeated after the hour; so only a first hand-over must be in this window's count.
        const first = new Set(mine.filter((t) => t.data !== undefined && firstAt.get(t.data) === t.logIndex).map((t) => t.data)).size;
        // A retried increment overstates, the safe side; what the code itself counted must hold the bound.
        const counted = Number(await meant(h, key));
        // The increment is the check, and the counters are taken most specific first: a relay that a
        // counter refused keeps its count on that one and on each it passed before. So a relay answered
        // 429 rate_limited in this window may have added one; nothing else may.
        const inScope = (boardId: bigint): boolean => (board !== undefined ? boardId === BigInt(board) : chair !== undefined ? lower(w.board(boardId).chair) === chair : true);
        // A relay whose own 55 s ran out after its counters moved is invariant 15's to report.
        const refusedHere = h.relays.filter((r) => (r.error === "rate_limited" || r.tookMs > config.RELAY_DEADLINE_MS) && r.logEnd > start.index && inScope(r.boardId)).length;
        if (counted > distinct + refusedHere || counted < first) {
          const doubled = Number(raw) - counted;
          return `${key} holds ${raw}${doubled > 0 ? ` (${doubled} of it from increments retried after a lost reply)` : ""}, so ${counted} counted, but ${distinct} distinct public actions (${mine.length} sends, ${first} of them first sends) were handed to the node in its window, which began ${Math.round((w.now - start.at) / 1000)} s ago, and ${refusedHere} relays there were refused rate_limited`;
        }
      }
      return undefined;
    },
  },
  {
    id: 2,
    title: "no join removes anyone, even one that meets a board another join filled while it waited for the lock, and every removal is a sweep's or a pressure pass's, of a guest",
    check: async (h) => {
      const w = h.world;
      // A removal is placed by the request that handed it over, so a join's own, however it met a
      // full board, is named here as a join's.
      const protectedMembers = [w.cast.chair.evm, ...w.cast.seeded.map((s) => s.evm)].map(lower);
      for (const r of w.removals) {
        if (r.command !== "sweep" && r.command !== "pressure") return `a removeMember of ${r.member} was handed to the node during a ${r.command} (command #${r.seq})`;
        if (protectedMembers.includes(lower(r.member))) return `a removeMember of ${r.member}, the chair or a seeded director, was handed to the node during a ${r.command} (command #${r.seq})`;
      }
      const missing = protectedMembers.filter((m) => !w.isMember(DEMO_BOARD, m));
      return missing.length > 0 ? `the chair or a seeded director is no longer on the demo board: ${missing.join(", ")}` : undefined;
    },
  },
  {
    id: 3,
    title: "every admission mark belongs to a member, a guest once seated, or an add still pending, and none survives a sweep once its add is dead",
    check: async (h) => {
      const w = h.world;
      for (const [i, guest] of w.cast.guests.entries()) {
        const key = admittedKey(hexToBytes(guest.evm));
        const mark = await w.store.inner.get(key);
        if (mark === null || w.isMember(DEMO_BOARD, guest.evm)) continue;
        const adds = [...w.txs.values()].filter((t) => t.what === "send" && t.action === "add" && t.member !== undefined && lower(t.member) === lower(guest.evm));
        // Seated once and removed since: one admission per address is the design (C34).
        if (adds.some((t) => t.state === "landed") || adds.some((t) => t.state === "pending")) continue;
        if (adds.length === 0) {
          const left = w.store.lifeLeft(key);
          if (left !== undefined && left <= config.DEMO_LOCK_TTL_SECONDS * 1000) continue;
          return `guest ${i} holds an admission mark "${mark}" that lives ${left === undefined ? "for an unknown time" : `${Math.round(left / 1000)} s more`}, but no add of it was ever handed to the node`;
        }
        const dead = Math.max(...adds.map((t) => t.deadSeq ?? 0));
        const states = adds.map((t) => `${t.hash.slice(0, 10)} ${t.state}`).join(", ");
        const swept = h.sweeps.find((r) => r.seq > dead && r.settled);
        if (swept !== undefined) return `guest ${i} is not a member and every add of it is dead (${states}) since command #${dead}, yet its admission mark "${mark}" survived the sweep at command #${swept.seq}`;
      }
      return undefined;
    },
  },
  {
    id: 4,
    title: "every day's booked spend covers the real fees of what was handed over that day by the world clock, and is never negative",
    check: async (h) => {
      const w = h.world;
      const keys = new Set([...w.store.log.filter((op) => op.op === "incr").map((op) => op.key), ...PRESPEND_KEYS].filter((key) => SPEND_LEDGER.test(key)));
      const landed = [...w.txs.values()].filter((t) => t.state === "landed" || t.state === "reverted");
      for (const key of keys) {
        if ((await w.store.inner.get(key)) === null) continue;
        // As the code meant them: a lost reply's own harm is invariant 8's to report.
        const booked = await meant(h, key);
        const settled = await meant(h, `${key}:settled`);
        if (settled > booked) return `${key} has ${settled} settled against ${booked} booked: a negative spend`;
      }
      // From the model's own clock: a fee belongs to the ledgers of the UTC day its transaction was
      // handed over, or, for a request that straddled midnight, to one of its two days. Today's and
      // yesterday's ledgers always outlive their day, so those two are checked.
      const today = utcDay(w.now);
      const yesterday = utcDay(w.now - 86_400_000);
      const spentOf = async (key: string): Promise<bigint> => (await meant(h, key)) - (await meant(h, `${key}:settled`));
      const sure = new Map<string, { fees: bigint; last: ChainTx }>();
      const straddling = new Map<string, { a: string; b: string; fees: bigint; last: ChainTx }>();
      for (const t of landed) {
        if (t.what === "foreign" || t.fee === 0n) continue;
        const [first, last] = t.days;
        if (first === undefined) continue;
        if (last === undefined) {
          if (first !== today && first !== yesterday) continue;
          for (const key of ledgerKeys(t, first)) sure.set(key, { fees: (sure.get(key)?.fees ?? 0n) + t.fee, last: t });
          continue;
        }
        if (first !== yesterday || last !== today) continue;
        const later = ledgerKeys(t, last);
        ledgerKeys(t, first).forEach((a, i) => {
          const b = later[i] ?? a;
          const held = straddling.get(`${a}|${b}`);
          straddling.set(`${a}|${b}`, { a, b, fees: (held?.fees ?? 0n) + t.fee, last: t });
        });
      }
      for (const [key, { fees, last }] of sure) {
        const spent = await spentOf(key);
        if (spent < fees) return `${key} holds ${spent} uqor, under the ${fees} uqor of real fees our transactions handed over on its day by the world clock paid (the latest ${t2s(last)})`;
      }
      for (const { a, b, fees, last } of straddling.values()) {
        const spent = (await spentOf(a)) + (await spentOf(b));
        const need = fees + (sure.get(a)?.fees ?? 0n) + (sure.get(b)?.fees ?? 0n);
        if (spent < need) return `${a} and ${b} together hold ${spent} uqor, under the ${need} uqor of real fees of what landed on those two days (the latest straddling midnight ${t2s(last)})`;
      }
      return undefined;
    },
  },
  {
    id: 5,
    title: "the relayer halts exactly when a foreign transaction used its nonce, and never otherwise",
    check: async (h) => {
      const w = h.world;
      const halt = await w.store.inner.get(HALT_KEY);
      if (halt !== null && w.foreignSeq === undefined) return `the relayer is halted ("${halt}") though no foreign transaction ever used its nonce`;
      const after = w.broadcastAfterForeign[0];
      if (after !== undefined) return `a foreign transaction used the relayer's nonce at command #${w.foreignSeq}, yet the relayer broadcast its own ${t2s(after)} instead of halting`;
      return undefined;
    },
  },
  {
    id: 6,
    title: "post bytes booked equal the verified sizes of posts handed to the node; no kept document differs from a posted cipherSize; every posted document and referenced envelope survives every sweep; token bytes stay under their daily caps",
    check: async (h) => {
      const w = h.world;
      const today = utcDay(w.now);
      const yesterday = utcDay(w.now - 86_400_000);
      const posts = [...w.txs.values()].filter((t) => t.what === "send" && t.scope === "public" && t.action === "post");
      for (const day of [yesterday, today]) {
        const onDay = posts.filter((t) => t.requestDay === day);
        const noon = Date.parse(`${day}T12:00:00Z`);
        const ledgers = [{ key: ledgerFor("posts", noon).key, of: onDay }, ...PUBLIC_CHAIRS.map((chair) => ({ key: ledgerFor("chair_posts", noon, chair).key, of: onDay.filter((t) => lower(t.chair ?? "") === lower(chair)) }))];
        for (const { key, of } of ledgers) {
          const spent = (await meant(h, key)) - (await meant(h, `${key}:settled`));
          const verified = of.reduce((sum, t) => sum + (t.cipherSize ?? 0n), 0n);
          if (spent !== verified) return `${key} holds ${spent} bytes, but the posts handed to the node that day state ${verified} verified bytes (${of.length} sends)`;
        }
      }
      const sweep = h.docSweeps.at(-1);
      if (sweep !== undefined) {
        const posted = w.events.filter((e) => e.kind === "posted");
        for (const [pathname, bytes] of w.blobs.blobs) {
          const hex = /^document\/([0-9a-f]{64})$/.exec(pathname)?.[1];
          const uploaded = w.blobs.uploadedAt.get(pathname) ?? 0;
          // Only a document the last sweep could decide: past its two hours, and read past by the log scan.
          if (hex === undefined || uploaded + DOCUMENT_KEEP_MS >= sweep.at || sweep.scanTime === undefined || uploaded + DOCUMENT_KEEP_MS > sweep.scanTime) continue;
          const sizes = posted.filter((e) => lower(e.cipherHash ?? "") === `0x${hex}`).map((e) => e.cipherSize);
          if (!sizes.includes(BigInt(bytes.length))) {
            return `document ${hex.slice(0, 12)} of ${bytes.length} bytes is kept after the sweep, but the chain's posts of it state ${sizes.length === 0 ? "no size at all" : sizes.join(", ")}`;
          }
        }
      }
      const lost = h.lostBlobs[0];
      if (lost !== undefined) return lost;
      for (const [pathname, doc] of w.docs) {
        if (!doc.honest || w.blobs.blobs.has(pathname)) continue;
        const hex = pathname.slice("document/".length);
        // The registry's own record decides: a post at the document's size, in a block within its two hours.
        const kept = w.events.some((e) => e.kind === "posted" && lower(e.cipherHash ?? "") === `0x${hex}` && e.cipherSize === BigInt(doc.size) && w.blockTimeMs(e.block) <= doc.uploadedAt + DOCUMENT_KEEP_MS);
        if (kept) return `document ${hex.slice(0, 12)} of ${doc.size} bytes was posted at its own size within two hours of its upload, yet it is gone from the store`;
      }
      const caps = tokenCaps();
      const issued = new Map<string, number>();
      // A token counts while it can still let bytes in, or while the document under its name is kept:
      // the bytes the store can be made to hold in a day. An unused token past its grace, or one whose
      // document a sweep deleted, may have its bytes given back.
      for (const t of w.tokens.filter((t) => w.now < t.validUntil + GRACE_MS || w.blobs.blobs.has(t.pathname))) {
        for (const [key, cap] of tokenBuckets(t, caps)) {
          const total = (issued.get(key) ?? 0) + t.maxBytes;
          issued.set(key, total);
          if (total > cap) return `document tokens issued for ${key} that can still let bytes in or whose document is kept allow ${total} bytes, over the daily cap of ${cap}`;
        }
      }
      return undefined;
    },
  },
  {
    id: 7,
    title: "once every transaction handed over at a board nonce is unknown to the chain or reverted, neither a different action there nor the same bytes again is refused 409",
    check: async (h) => {
      // A relay that overlapped another may meet that one's mark while it is still inside its deadline.
      const blocked = h.relays.find((r) => r.seq === h.world.seq && !r.concurrent && r.status === 409 && !r.liveAtNonce);
      return blocked === undefined
        ? undefined
        : `board ${blocked.boardId} nonce ${blocked.nonce}: no transaction handed to the node there is pending or landed, yet a relay there was answered 409 ${blocked.error ?? ""}`;
    },
  },
  {
    id: 8,
    title: "a write retried after a lost reply never makes a ledger or byte budget show less than was booked and not given back",
    check: async (h) => {
      const w = h.world;
      const keys = new Set(w.store.log.filter((op) => op.op === "incr" && BOOKED.test(op.key)).map((op) => op.key));
      for (const key of keys) {
        const back = givenBackKey(key);
        const shown = (await count(h, key)) - (await count(h, back));
        const kept = (await meant(h, key)) - (await meant(h, back));
        if (shown < kept) {
          return `${key} shows ${shown} booked and not given back, ${kept - shown} less than the ${kept} the code booked and kept: a give-back on ${back} was retried after a lost reply and counted twice`;
        }
      }
      return undefined;
    },
  },
  {
    id: 9,
    title: "two different actions at one board nonce, or two copies of one action, are never both handed to the node while the first is pending",
    check: async (h) => h.world.doubleHanded[0],
  },
  {
    id: 10,
    title: "a join answered board_full or demo_busy reserves no demo relay, takes nothing from the day, sends nothing and leaves no mark; one that met a board already full takes no hourly join and keeps its challenge",
    check: async (h) => {
      const w = h.world;
      for (const j of h.joins) {
        if (j.seq !== w.seq || j.status !== 503 || (j.error !== "board_full" && j.error !== "demo_busy") || j.flow === undefined) continue;
        const ops = w.store.log.slice(j.logFrom).filter((op) => op.flow === j.flow && op.wrote);
        const what = `guest ${j.guest}'s join answered 503 ${j.error} at command #${j.seq}`;
        const reserved = ops.find((op) => op.key.startsWith("rate:relay:demo:"));
        if (reserved !== undefined) return `${what} still reserved a demo relay (${reserved.key})`;
        if (ops.some((op) => op.key.startsWith("demo:join:count:"))) return `${what} still took a join from the day`;
        const sent = [...w.txs.values()].find((t) => t.flow === j.flow);
        if (sent !== undefined) return `${what} still handed ${t2s(sent)} to the node`;
        const guest = w.cast.guests[j.guest % w.cast.guests.length];
        const mark = guest === undefined ? undefined : admittedKey(hexToBytes(guest.evm));
        const lastMark = ops.filter((op) => op.key === mark).at(-1);
        if (!j.concurrent && lastMark !== undefined && lastMark.op !== "delete") return `${what} left its admission mark in place`;
        if (j.error === "board_full" && j.fullAtArrival) {
          const counted = ops.find((op) => op.key.startsWith("rate:demo-join:"));
          if (counted !== undefined) return `${what} met a board already full when it arrived, yet took an hourly join (${counted.key})`;
          const used = ops.find((op) => op.key.startsWith("demo:challenge:"));
          if (used !== undefined) return `${what} met a board already full when it arrived, yet used up its challenge (${used.op})`;
        }
      }
      return undefined;
    },
  },
  {
    id: 11,
    title: "no removal takes the demo board below DEMO_GUEST_CAP minus DEMO_FREE_SEATS members unless its guest was due anyway: six hours old, or with a KEM key gone wrong",
    check: async (h) => h.world.belowFloor[0],
  },
  {
    id: 14,
    title: "each share of the day's spend, as the code booked it, stays at or under its ceiling",
    check: async (h) => {
      const w = h.world;
      const keys = new Set([...w.store.log.filter((op) => op.op === "incr").map((op) => op.key), ...PRESPEND_KEYS].filter((key) => SPEND_LEDGER.test(key)));
      for (const key of keys) {
        const spent = (await meant(h, key)) - (await meant(h, `${key}:settled`));
        if (spent > ceilingOf(key)) return `${key} holds ${spent} uqor as the code booked it, over its ceiling of ${ceilingOf(key)}`;
      }
      return undefined;
    },
  },
  {
    id: 15,
    title: "a relay that moved the per-board, per-chair or valid hourly counters handed a transaction to the node, or was refused by one of those counters",
    check: async (h) => {
      const w = h.world;
      const COUNTER = /^rate:relay:(?:board:\d+|chair:0x[0-9a-f]{40}|valid)$/;
      for (const r of h.relays) {
        if (r.seq !== w.seq || r.flow === undefined || r.error === "rate_limited") continue;
        const moved = w.store.log.find((op) => op.flow === r.flow && op.op === "incr" && COUNTER.test(op.key));
        if (moved === undefined || [...w.txs.values()].some((t) => t.flow === r.flow && t.what === "send")) continue;
        return `a relay at board ${r.boardId} nonce ${r.nonce} moved ${moved.key}, then answered ${r.status} ${r.error ?? ""} with nothing handed to the node, after ${Math.round(r.tookMs / 1000)} s of its own time`;
      }
      return undefined;
    },
  },
  {
    id: 12,
    title: "a dead add's mark never refuses its guest",
    check: async (h) => {
      const w = h.world;
      for (const [i, guest] of w.cast.guests.entries()) {
        if (w.isMember(DEMO_BOARD, guest.evm)) continue;
        const adds = [...w.txs.values()].filter((t) => t.what === "send" && t.action === "add" && t.member !== undefined && lower(t.member) === lower(guest.evm));
        if (adds.length === 0 || adds.some((t) => t.state === "landed" || t.state === "pending")) continue;
        const dead = Math.max(...adds.map((t) => t.deadSeq ?? 0));
        // A join refused for its own reason before it reaches the mark (no KEM key, say) leaves the mark idle, not in the guest's way.
        const refused = h.joins.find((j) => j.seq > dead && j.seq === w.seq && j.guest === i && j.error === "already_admitted");
        if (refused !== undefined) {
          const states = adds.map((t) => `${t.hash.slice(0, 10)} ${t.state}`).join(", ");
          return `guest ${i} is not a member and every add of it is dead (${states}) since command #${dead}, yet its join at command #${refused.seq} was refused 409 already_admitted`;
        }
      }
      return undefined;
    },
  },
  {
    id: 13,
    title: "a guest never sent an add is never refused already_admitted or admission_unsettled, unless another join of it ran at the same time",
    check: async (h) => {
      const w = h.world;
      for (const j of h.joins) {
        // A join under way holds the guest's mark, so a second one at the same time may meet it.
        if (j.seq !== w.seq || j.concurrent || (j.error !== "already_admitted" && j.error !== "admission_unsettled")) continue;
        const guest = w.cast.guests[j.guest % w.cast.guests.length];
        if (guest === undefined || w.isMember(DEMO_BOARD, guest.evm)) continue;
        const ever = [...w.txs.values()].some((t) => t.what === "send" && t.action === "add" && t.member !== undefined && lower(t.member) === lower(guest.evm));
        if (!ever) return `guest ${j.guest} was refused ${j.status} ${j.error} at command #${j.seq}, though no add of it was ever handed to the node`;
      }
      return undefined;
    },
  },
];

/** How often each invariant's interesting case came up across the clean runs, so a pass is never a pass over nothing. */
const coverage = new Map<string, number>();

async function tally(h: Harness): Promise<void> {
  const w = h.world;
  const txs = [...w.txs.values()];
  const add = (what: string, n: number): void => void coverage.set(what, (coverage.get(what) ?? 0) + n);
  add("runs", 1);
  add("commands", w.seq);
  add("1: public sends handed to the node", txs.filter((t) => t.what === "send" && t.scope === "public").length);
  add("1: public refusals after the pre-flight passed", h.relays.filter((r) => r.status === 429 || r.status === 503).length);
  add("2: removals relayed", w.removals.length);
  add("3: adds that died (unknown or reverted)", txs.filter((t) => t.action === "add" && (t.state === "unknown" || t.state === "reverted")).length);
  add("3: joins answered 202", h.joins.filter((j) => j.status === 202).length);
  add("4: our transactions in a block with a real fee", txs.filter((t) => (t.state === "landed" || t.state === "reverted") && t.what !== "foreign").length);
  add("4: window opens", txs.filter((t) => t.what === "open").length);
  add("5: foreign uses of the relayer's nonce", w.foreignSeq === undefined ? 0 : 1);
  add("5: runs that ended halted", (await w.store.inner.get(HALT_KEY)) === null ? 0 : 1);
  add("6: posts handed to the node", txs.filter((t) => t.action === "post" && t.what === "send").length);
  add("6: document sweeps that ran to the end", h.docSweeps.length);
  add("6: documents past their two hours at a sweep", h.docSweeps.reduce((sum, s) => sum + s.due, 0));
  add("6: tokens issued", w.tokens.length);
  add("6: tokens refused upload_bytes", h.answers.filter((a) => a.startsWith("document token: 429 upload_bytes")).length);
  add("4: our transactions whose request straddled UTC midnight", txs.filter((t) => t.days.length > 1).length);
  add("6: honest documents posted at their size within two hours", [...w.docs].filter(([p, d]) => d.honest && w.events.some((e) => e.kind === "posted" && lower(e.cipherHash ?? "") === `0x${p.slice(9)}`)).length);
  add("6: referenced envelopes present at an envelope sweep", h.envelopesChecked);
  const caps = tokenCaps();
  const filled = new Map<string, number>();
  for (const t of w.tokens) for (const [key] of tokenBuckets(t, caps)) filled.set(key, (filled.get(key) ?? 0) + t.maxBytes);
  const reached = (kind: "client" | "net48" | "total"): number =>
    [...filled].filter(([key, n]) => (kind === "total" ? key.endsWith(" all") : kind === "net48" ? key.endsWith("::/48") : !key.endsWith(" all") && !key.endsWith("::/48")) && n + 26_214_400 > caps[kind]).length;
  add("6: token caps reached per client", reached("client"));
  add("6: token caps reached per IPv6 /48", reached("net48"));
  add("6: token caps reached for everyone together", reached("total"));
  add("7: relays at a nonce where every earlier transaction is dead", h.relays.filter((r) => !r.liveAtNonce && txs.some((t) => t.boardId === r.boardId && t.signedNonce === r.nonce && t.what === "send")).length);
  add("9: relays answered 409 duplicate or nonce_in_flight", h.relays.filter((r) => r.status === 409).length);
  add("10: joins answered board_full", h.joins.filter((j) => j.error === "board_full").length);
  add("10: joins answered board_full that met a board full on arrival", h.joins.filter((j) => j.error === "board_full" && j.fullAtArrival).length);
  add("2: joins answered board_full that arrived at a board with room", h.joins.filter((j) => j.error === "board_full" && !j.fullAtArrival).length);
  add("10: joins answered demo_busy", h.joins.filter((j) => j.error === "demo_busy").length);
  add("10: passes and sweeps refused demo_busy", h.answers.filter((a) => (a.startsWith("sweep demo:") || a.startsWith("pressure:")) && a.includes("demo_busy")).length);
  add("11: removals landed with the board at or under its floor", w.floorRemovals);
  add("store writes applied twice", w.store.retried);
  for (const [op, n] of Object.entries(w.store.retriedBy)) add(`2: lost replies on ${op}`, n);
  add("2: lost replies after a command's fortieth write", w.store.retriedLate);
  add("overlap: commands", new Set(w.ran.filter((r) => w.ran.filter((o) => o.seq === r.seq).length > 1).map((r) => r.seq)).size);
  add("overlap: switches between requests at a turn", w.switches);
  add("overlap: lock calls that waited for a holder", w.store.lockWaits);
  add("overlap: locks taken while an earlier holder still ran", w.store.lockTakeovers);
}

let cast: Cast;
const outcomes = new Map<number, string>();
const ran: string[] = [];
let modelError: string | undefined;

function property(active: ReadonlySet<number>) {
  return fc.asyncProperty(worldInitArb, fc.commands(commandArbs, { maxCommands: MAX_COMMANDS, size: "max", replayPath: REPLAY }), async (init, cmds) => {
    knobs.demoRelaysPerHour = init.demoRelaysPerHour;
    const world = await World.create(cast, init);
    const h: Harness = {
      world,
      history: [],
      relays: [],
      joins: [],
      sweeps: [],
      answers: [],
      nextSalt: 1,
      docSweeps: [],
      lostBlobs: [],
      envelopesChecked: 0,
      strictThrows: active.has(0),
      after: async (command) => {
        for (const inv of INVARIANTS) {
          if (inv.id === 0 || !active.has(inv.id)) continue;
          const broken = await inv.check(h);
          if (broken !== undefined) {
            const order = command.startsWith("overlap(") && h.lastSchedule !== undefined ? `\n  turns taken: ${h.lastSchedule}` : "";
            throw new InvariantBroken(inv.id, `${broken}\n  after command #${world.seq}: ${command}${order}\n  last answers:\n    ${h.answers.slice(-10).join("\n    ")}`);
          }
        }
      },
    };
    await fc.asyncModelRun(() => ({ model: {}, real: h }), cmds);
    await tally(h);
    if (process.env.MODEL_TRACE !== undefined) console.log(`run ${JSON.stringify(init)}\n  ${String(cmds)}\n  ${h.answers.join("\n  ")}`);
  });
}

function report(details: fc.RunDetails<[unknown, unknown]>, title: string): string {
  const [init, cmds] = details.counterexample ?? [undefined, undefined];
  const error = details.errorInstance instanceof Error ? details.errorInstance.message : String(details.errorInstance);
  return [
    `${title}`,
    `  seed ${details.seed}, path "${details.counterexamplePath}", failed on run ${details.numRuns}, shrunk ${details.numShrinks} times${details.interrupted ? " (shrinking cut short)" : ""}`,
    `  start: ${JSON.stringify(init)}`,
    `  commands: ${String(cmds)}`,
    `  ${error}`,
  ].join("\n");
}

beforeAll(async () => {
  cast = await makeCast(6, 36);
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
  const only = process.env.MODEL_ONLY?.split(",").map(Number);
  const active = new Set(INVARIANTS.map((i) => i.id).filter((id) => only === undefined || only.includes(id) || id === 0));
  const started = Date.now();
  for (let round = 0; active.size > 0 && Date.now() - started < BUDGET_MS; round++) {
    let details: fc.RunDetails<[unknown, unknown]>;
    try {
      details = (await fc.check(property(active), { numRuns: RUNS, seed: SEED + round, ...(PATH !== undefined && round === 0 ? { path: PATH } : {}) })) as fc.RunDetails<[unknown, unknown]>;
    } catch (error) {
      // A path recorded against other code no longer leads anywhere; fast-check throws rather than answer.
      modelError = `the run could not start: ${error instanceof Error ? error.message : String(error)}`;
      break;
    }
    if (!details.failed) {
      ran.push(`round ${round + 1}: seed ${details.seed}, ${details.numRuns} runs, invariants ${[...active].join(",")} held`);
      break;
    }
    const error = details.errorInstance;
    const id = error instanceof InvariantBroken ? error.id : error instanceof HandlerThrew ? 0 : undefined;
    if (id === undefined) {
      modelError = report(details, "the model itself stopped on an error it did not expect");
      break;
    }
    const title = INVARIANTS.find((i) => i.id === id)?.title ?? String(id);
    outcomes.set(id, report(details, `invariant ${id} (${title}) does not hold`));
    ran.push(`round ${round + 1}: seed ${details.seed}, invariant ${id} failed on run ${details.numRuns}`);
    active.delete(id);
    if (STOP_AT_FIRST) break;
  }
  const seenText = [...coverage].map(([what, n]) => `${what}: ${n}`).join("\n    ");
  console.log(`model: ${RUNS} runs a round, up to ${MAX_COMMANDS} commands each, base seed ${SEED}\n  ${ran.join("\n  ")}\n  seen across every run that ended:\n    ${seenText}`);
}, BUDGET_MS + 600_000);

beforeEach(() => {
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("the relay, demo and document model", () => {
  it("runs without an error the model did not expect", () => {
    if (modelError !== undefined) throw new Error(modelError);
    expect(ran.length).toBeGreaterThan(0);
  });

  for (const inv of INVARIANTS) {
    it(`invariant ${inv.id}: ${inv.title}`, () => {
      const failure = outcomes.get(inv.id);
      if (failure !== undefined) throw new Error(failure);
    });
  }
});
