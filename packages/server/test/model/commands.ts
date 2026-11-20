import { challengeMessage, sha256, signAction, toHex } from "@ava/core";
import fc from "fast-check";
import { bytesToHex, encodeFunctionData, type Hex } from "viem";
import { boardRegistryAbi } from "../../src/abi/boardRegistry.ts";
import { DEMO_DEADLINE_MS, DEMO_GUEST_CAP, REGISTRY_ADDRESS } from "../../src/config.ts";
import { freeDemoSeats, handleDemoChallenge, handleDemoJoin, sweepDemoGuests, type PressureOutcome } from "../../src/demo.ts";
import { DOCUMENT_CAP, DOCUMENT_KEEP_MS, POSTED_SCAN_KEY, handleDocumentToken, handleDocumentVerify, parsePostedScan, sweepUnverified } from "../../src/docupload.ts";
import { sweepUnreferencedEnvelopes } from "../../src/envelopeSweep.ts";
import { handleRelay } from "../../src/relay.ts";
import {
  CLIENT_IPS,
  DAY,
  DEMO_BOARD,
  HOUR,
  ORIGIN,
  PUBLIC_BOARDS,
  appRequest,
  fakeSignature,
  postBody,
  rotateBody,
  utcDay,
  type LostMode,
  type NativeFate,
  type PublicBody,
  type TxFate,
  type World,
  type WorldInit,
} from "./world.ts";

/** Every request a command sent, so a later command can send it again, byte for byte. */
export type Sent =
  | { kind: "relay"; body: PublicBody; ip: string; boardId: bigint; nonce: bigint; salt: number }
  | { kind: "junk"; body: unknown; ip: string }
  | { kind: "challenge" | "join"; body: unknown; ip: string; guest: number }
  | { kind: "token" | "verify"; body: unknown; ip: string };

/** One public relay: the nonce it acted at, what the chain held at that nonce, and the answer. */
export interface RelayRecord {
  seq: number;
  boardId: bigint;
  nonce: bigint;
  /** Whether, before the relay or after it, a transaction handed to the node at this board nonce was pending or landed. */
  liveAtNonce: boolean;
  /** Sent while other requests overlapped it, so another relay may have held a mark for a moment. */
  concurrent: boolean;
  /** The store's write log length once it was answered, to place it against counter windows. */
  logEnd: number;
  /** The request that sent it, and how long it ran on the world's clock. */
  flow?: number;
  tookMs: number;
  status: number;
  error?: string;
}

/** One demo join answered: who, what came back, the request that sent it, and what invariants 3 and 9 need about its arrival. */
export interface JoinRecord {
  seq: number;
  guest: number;
  status: number;
  error?: string;
  flow?: number;
  /** The demo board held DEMO_GUEST_CAP members or more when the request arrived. */
  fullAtArrival: boolean;
  /** Sent while other requests overlapped it. */
  concurrent: boolean;
  /** The store's write log length when the join request began, so its own writes can be told from its challenge request's. */
  logFrom: number;
}

/** What the commands drive and what the invariants read: the world, plus what was sent and answered. */
export interface Harness {
  world: World;
  history: Sent[];
  relays: RelayRecord[];
  /** What the handlers answered, newest last, for the failure report. */
  answers: string[];
  nextSalt: number;
  /** Every demo join answered, by command, so a mark that refused its guest can be told apart from one that sat idle. */
  joins: JoinRecord[];
  /** Each demo sweep, and whether it got far enough to settle the marks joins left. */
  sweeps: { seq: number; settled: boolean }[];
  /** The scheduler's order of the last overlap, for the failure report. */
  lastSchedule?: string;
  /** Referenced envelopes a sweep deleted, as the model sees them, and how many it was checked against. */
  lostBlobs: string[];
  envelopesChecked: number;
  /** Each document sweep that ran to its end: when, and how far the registry log scan had read by then. */
  docSweeps: { at: number; scanTime?: number; due: number }[];
  /** False once "no handler throws" has failed and been reported, so the run goes on to the other promises. */
  strictThrows: boolean;
  /** Runs every invariant still in play; throws on the first one that does not hold. */
  after(command: string): Promise<void>;
}

/** A handler threw instead of answering, which no handler is meant to do. */
export class HandlerThrew extends Error {
  constructor(where: string, cause: unknown) {
    super(`${where} threw instead of answering: ${cause instanceof Error ? `${cause.name}: ${cause.message}` : String(cause)}`);
    this.name = "HandlerThrew";
  }
}

type Model = Record<string, never>;
export type Step = fc.AsyncCommand<Model, Harness>;

interface Chaos {
  latency: number;
  fates: TxFate[];
  nativeFates: NativeFate[];
  lost: LostMode;
}

function lostText(lost: LostMode): string {
  switch (lost.kind) {
    case "none":
      return "";
    case "at":
      return `twice=[${lost.ordinals.join(",")}]`;
    case "every":
      return "lost=every";
    case "chance":
      return `lost=0.3/${lost.seed}`;
  }
}

const chaosText = (c: Chaos): string =>
  [c.latency > 0 ? `latency=${c.latency}` : "", c.fates.length > 0 ? `fates=[${c.fates.join(",")}]` : "", c.nativeFates.length > 0 ? `natives=[${c.nativeFates.join(",")}]` : "", lostText(c.lost)]
    .filter((s) => s !== "")
    .join(" ");

const named = (head: string, parts: string[]): string => `${head}(${parts.filter((p) => p !== "").join(" ")})`;

async function answerOf(response: Response): Promise<{ status: number; error?: string; body: Record<string, unknown> }> {
  const body = (await response.json().catch(() => ({}))) as Record<string, unknown>;
  return { status: response.status, error: typeof body.error === "string" ? body.error : undefined, body };
}

/** Runs one command's work as one request inside the world's bookkeeping, then every invariant. */
async function step(h: Harness, kind: string, name: string, chaos: Partial<Chaos> & { guest?: string; unreadable?: Hex[] }, work: () => Promise<void>): Promise<void> {
  h.world.begin(kind, chaos);
  try {
    await h.world.runFlow(kind, chaos.guest, work);
  } catch (error) {
    if (!(error instanceof HandlerThrew) || h.strictThrows) throw error;
    h.answers.push(error.message);
  } finally {
    h.world.end();
  }
  await h.after(name);
}

async function guarded<T>(where: string, work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    throw new HandlerThrew(where, error);
  }
}

/** One command: its name as the counterexample prints it, and its work. */
function command(name: string, work: (h: Harness) => Promise<void>): Step {
  return { check: () => true, run: (_m, h) => work(h), toString: () => name };
}

/** Whether the chain holds a transaction handed over at this board nonce that is pending or landed: the only thing a 409 may stand on. */
const liveAt = (w: World, boardId: bigint, nonce: bigint): boolean =>
  [...w.txs.values()].some((t) => t.what === "send" && t.boardId === boardId && t.signedNonce === nonce && (t.state === "pending" || t.state === "landed"));

/** Sends one public relay and records what the chain held at its nonce before and after. */
async function relayPublic(h: Harness, body: PublicBody, ip: string, meta: { boardId: bigint; nonce: bigint; salt: number }): Promise<void> {
  const w = h.world;
  const liveBefore = liveAt(w, meta.boardId, meta.nonce);
  const began = w.now;
  const flow = w.flow();
  if (flow !== undefined) flow.requestDay = utcDay(w.now);
  const answer = await answerOf(await guarded("handleRelay", () => handleRelay(appRequest("/api/relay", body), w.relayContext(ip))));
  const liveAtNonce = liveBefore || liveAt(w, meta.boardId, meta.nonce);
  h.relays.push({ seq: w.seq, boardId: meta.boardId, nonce: meta.nonce, liveAtNonce, concurrent: w.scheduler !== undefined, logEnd: w.store.log.length, flow: flow?.id, tookMs: w.now - began, status: answer.status, error: answer.error });
  h.answers.push(`relay ${meta.boardId}@${meta.nonce} salt ${meta.salt} from ${ip}: ${answer.status} ${answer.error ?? ""}`);
}

const ipOf = (i: number): string => CLIENT_IPS[i % CLIENT_IPS.length] as string;
const relaysIn = (h: Harness): Extract<Sent, { kind: "relay" }>[] => h.history.filter((s): s is Extract<Sent, { kind: "relay" }> => s.kind === "relay");
/** One of the last four relays: a copy or a re-signing matters most while the action it repeats may still be in flight. */
const recent = <T>(items: readonly T[], pick: number): T | undefined => items[items.length - 1 - (pick % Math.max(1, Math.min(4, items.length)))];

function publicRelay(board: number, ip: number, chaos: Chaos): Step {
  const name = named("relay", [`board=${PUBLIC_BOARDS[board]}`, `ip=${ip}`, chaosText(chaos)]);
  return command(name, (h) =>
    step(h, "relay", name, chaos, async () => {
      const boardId = PUBLIC_BOARDS[board] as bigint;
      const nonce = h.world.board(boardId).nonce;
      const salt = h.nextSalt++;
      const body = rotateBody(h.world, boardId, nonce, salt);
      h.history.push({ kind: "relay", body, ip: ipOf(ip), boardId, nonce, salt });
      await relayPublic(h, body, ipOf(ip), { boardId, nonce, salt });
    }),
  );
}

function copyRelay(pick: number, ip: number, chaos: Chaos): Step {
  const name = named("copy", [`pick=${pick}`, `ip=${ip}`, chaosText(chaos)]);
  return command(name, (h) =>
    step(h, "copy", name, chaos, async () => {
      const relays = relaysIn(h);
      const earlier = recent(relays, pick);
      if (earlier === undefined) return;
      const from = ipOf(ip) === earlier.ip ? ipOf(ip + 1) : ipOf(ip);
      await relayPublic(h, earlier.body, from, earlier);
    }),
  );
}

function resignedRelay(pick: number, ip: number, chaos: Chaos): Step {
  const name = named("resign", [`pick=${pick}`, `ip=${ip}`, chaosText(chaos)]);
  return command(name, (h) =>
    step(h, "resign", name, chaos, async () => {
      const relays = relaysIn(h);
      const earlier = recent(relays, pick);
      if (earlier === undefined) return;
      const salt = h.nextSalt++;
      const body = rotateBody(h.world, earlier.boardId, earlier.nonce, salt);
      h.history.push({ kind: "relay", body, ip: ipOf(ip), boardId: earlier.boardId, nonce: earlier.nonce, salt });
      await relayPublic(h, body, ipOf(ip), { boardId: earlier.boardId, nonce: earlier.nonce, salt });
    }),
  );
}

type JunkKind = "schema" | "badSignature" | "staleNonce";

function junkRelay(variant: JunkKind, board: number, ip: number): Step {
  const name = named("junk", [variant, `board=${PUBLIC_BOARDS[board]}`, `ip=${ip}`]);
  return command(name, (h) =>
    step(h, "junk", name, {}, async () => {
      const boardId = PUBLIC_BOARDS[board] as bigint;
      const nonce = h.world.board(boardId).nonce;
      const salt = h.nextSalt++;
      const body =
        variant === "schema"
          ? { action: "rotate", boardId: boardId.toString(), params: { envelopeHash: "0x12" }, deadline: "1", signature: "0x00" }
          : rotateBody(h.world, boardId, variant === "staleNonce" ? nonce - 1n : nonce, salt, variant !== "badSignature");
      h.history.push({ kind: "junk", body, ip: ipOf(ip) });
      const answer = await answerOf(await guarded("handleRelay", () => handleRelay(appRequest("/api/relay", body), h.world.relayContext(ipOf(ip)))));
      h.answers.push(`junk ${variant}: ${answer.status} ${answer.error ?? ""}`);
    }),
  );
}

function clientRetry(pick: number, chaos: Chaos): Step {
  const name = named("retry", [`pick=${pick}`, chaosText(chaos)]);
  return command(name, (h) => {
    const earlier = h.history[pick % Math.max(1, h.history.length)];
    const guest = earlier !== undefined && "guest" in earlier ? String(earlier.guest) : undefined;
    const kind = earlier?.kind === "join" ? "join" : "retry";
    return step(h, kind, name, { ...chaos, guest }, async () => {
      if (earlier === undefined) return;
      const w = h.world;
      switch (earlier.kind) {
        case "relay":
          await relayPublic(h, earlier.body, earlier.ip, earlier);
          return;
        case "junk": {
          const answer = await answerOf(await guarded("handleRelay", () => handleRelay(appRequest("/api/relay", earlier.body), w.relayContext(earlier.ip))));
          h.answers.push(`retry junk: ${answer.status} ${answer.error ?? ""}`);
          return;
        }
        case "join":
          await sendJoin(h, earlier.body, earlier.ip, earlier.guest, "retried");
          return;
        case "challenge": {
          const answer = await answerOf(await guarded("handleDemoChallenge", () => handleDemoChallenge(appRequest("/api/demo/challenge", earlier.body), w.demoContext(earlier.ip))));
          h.answers.push(`retry challenge guest ${earlier.guest}: ${answer.status} ${answer.error ?? ""}`);
          return;
        }
        case "token":
        case "verify": {
          const handler = earlier.kind === "token" ? handleDocumentToken : handleDocumentVerify;
          const answer = await answerOf(await guarded(earlier.kind, () => handler(appRequest(`/api/document/${earlier.kind}`, earlier.body), w.documentContext(earlier.ip))));
          h.answers.push(`retry ${earlier.kind}: ${answer.status} ${answer.error ?? ""}`);
          return;
        }
      }
    });
  });
}

function demoChallenge(guest: number, ip: number): Step {
  const name = named("challenge", [`guest=${guest}`, `ip=${ip}`]);
  return command(name, (h) =>
    step(h, "challenge", name, { guest: String(guest) }, async () => {
      const who = h.world.cast.guests[guest % h.world.cast.guests.length];
      if (who === undefined) return;
      const body = { guest: who.qor1 };
      h.history.push({ kind: "challenge", body, ip: ipOf(ip), guest });
      const answer = await answerOf(await guarded("handleDemoChallenge", () => handleDemoChallenge(appRequest("/api/demo/challenge", body), h.world.demoContext(ipOf(ip)))));
      h.answers.push(`challenge guest ${guest}: ${answer.status} ${answer.error ?? ""}`);
    }),
  );
}

export type JoinKind = "valid" | "noKem" | "copied" | "unreadable";

/** A guest asks for a challenge, signs it and joins: what the app does for one judge. */
async function joinFlow(h: Harness, guest: number, kind: JoinKind, ip: number): Promise<void> {
  const w = h.world;
  const who = w.cast.guests[guest % w.cast.guests.length];
  if (who === undefined) return;
  if (kind === "valid") w.setKem(who.evm, { kind: "own" });
  if (kind === "noKem") w.setKem(who.evm, { kind: "none" });
  if (kind === "unreadable") w.setKem(who.evm, { kind: "unreadable" });
  if (kind === "copied") w.setKem(who.evm, { kind: "copy", from: w.cast.seeded[0].evm });
  const from = ipOf(ip);
  const asked = { guest: who.qor1 };
  h.history.push({ kind: "challenge", body: asked, ip: from, guest });
  const issued = await answerOf(await guarded("handleDemoChallenge", () => handleDemoChallenge(appRequest("/api/demo/challenge", asked), w.demoContext(from))));
  if (issued.status !== 200) {
    h.answers.push(`join guest ${guest}: challenge ${issued.status} ${issued.error ?? ""}`);
    return;
  }
  const botNonce = issued.body.botNonce as Hex;
  const expiry = String(issued.body.expiry);
  const message = challengeMessage({ registry: REGISTRY_ADDRESS, boardId: DEMO_BOARD, guest: toHex(who.account), botNonce, expiry: BigInt(expiry) });
  const body = { guest: who.evm, botNonce, expiry, signature: bytesToHex(signAction(who.mldsa.secretKey, message)) };
  h.history.push({ kind: "join", body, ip: from, guest });
  await sendJoin(h, body, from, guest, kind);
}

/** One join request, recorded with what invariants 3 and 9 need about the moment it arrived. */
async function sendJoin(h: Harness, body: unknown, from: string, guest: number, kind: string): Promise<void> {
  const w = h.world;
  const flow = w.flow()?.id;
  const fullAtArrival = w.board(DEMO_BOARD).members.length >= DEMO_GUEST_CAP;
  const logFrom = w.store.log.length;
  const answer = await answerOf(await guarded("handleDemoJoin", () => handleDemoJoin(appRequest("/api/demo/join", body), w.demoContext(from))));
  h.joins.push({ seq: w.seq, guest, status: answer.status, error: answer.error, flow, fullAtArrival, concurrent: w.scheduler !== undefined, logFrom });
  h.answers.push(`join guest ${guest} ${kind}: ${answer.status} ${answer.error ?? ""}`);
}

function demoJoin(guest: number, kind: JoinKind, ip: number, chaos: Chaos): Step {
  const name = named("join", [`guest=${guest}`, kind, `ip=${ip}`, chaosText(chaos)]);
  return command(name, (h) => step(h, "join", name, { ...chaos, guest: String(guest) }, () => joinFlow(h, guest, kind, ip)));
}

/** Members whose KEM lookup fails for one command, picked by position on the board as it stands. */
function unreadableOf(h: Harness, pick: number | null): Hex[] {
  if (pick === null) return [];
  const members = h.world.board(DEMO_BOARD).members;
  const member = members[pick % Math.max(1, members.length)];
  return member === undefined ? [] : [member];
}

const plain = (value: unknown): string => JSON.stringify(value, (_k, v: unknown) => (typeof v === "bigint" ? v.toString() : v));

/** The pass a join handed to the background runner, oldest first; while requests overlap with none waiting, the pass a sweep runs. */
async function pressureFlow(h: Harness): Promise<void> {
  const w = h.world;
  const work = w.background.shift() ?? (w.scheduler === undefined ? undefined : () => freeDemoSeats(w.sweepContext()));
  if (work === undefined) {
    h.answers.push("pressure: nothing scheduled");
    return;
  }
  const outcome = (await guarded("freeDemoSeats", work)) as PressureOutcome;
  h.answers.push(`pressure: removed ${outcome.removed.length}, stopped ${plain(outcome.stopped)}`);
}

function pressurePass(unreadable: number | null, chaos: Chaos): Step {
  const name = named("pressure", [unreadable === null ? "" : `unreadable=${unreadable}`, chaosText(chaos)]);
  return command(name, (h) => step(h, "pressure", name, { ...chaos, unreadable: unreadableOf(h, unreadable) }, () => pressureFlow(h)));
}

/** Refusals that stop the demo sweep before it settles the marks a join left: the lock, the board read, the chair check. */
const BEFORE_SETTLING = new Set(["busy", "chain_unreachable", "out_of_time", "not_chair", "sweep_failed"]);

/** What the scheduler runs: the demo sweep, the envelope sweep, then the document sweep. */
async function sweepFlow(h: Harness): Promise<void> {
  const w = h.world;
  const began = w.now;
  const demo = await guarded("sweepDemoGuests", () => sweepDemoGuests(w.sweepContext()));
  h.answers.push(`sweep demo: ${plain(demo)}`);
  // A sweep whose 120 s ran out under it (an overlap's clock can do that) could not ask the chain
  // about the marks it holds, so it owes them nothing; the next sweep does.
  const inTime = w.now - began < DEMO_DEADLINE_MS;
  h.sweeps.push({ seq: w.seq, settled: inTime && demo.done !== "not_ready" && !(demo.done === "refused" && BEFORE_SETTLING.has(demo.reason)) });
  // Every envelope a grant on chain names, present now, must still be there after the sweep.
  const granted = new Set(w.events.filter((e) => e.kind === "granted" && e.envelopeHash !== undefined).map((e) => `envelope/${(e.envelopeHash as Hex).slice(2).toLowerCase()}`));
  const referenced = [...w.blobs.blobs.keys()].filter((pathname) => granted.has(pathname));
  h.envelopesChecked += referenced.length;
  // The two blob sweeps throw by design on a store or log failure; that is their answer, not a crash.
  const envelopes = await sweepUnreferencedEnvelopes({ blobs: w.blobs, store: w.store, now: w.now, logs: w.logs, clock: w.clock }).catch((e: unknown) => String(e));
  h.answers.push(`sweep envelopes: ${plain(envelopes)}`);
  for (const pathname of referenced) {
    if (!w.blobs.blobs.has(pathname)) h.lostBlobs.push(`the envelope sweep at command #${w.seq} deleted ${pathname.slice(0, 21)}, which a grant on chain names`);
  }
  const at = w.now;
  const due = [...w.blobs.uploadedAt].filter(([pathname, uploaded]) => pathname.startsWith("document/") && uploaded + DOCUMENT_KEEP_MS < at).length;
  // Read before the sweep runs: an overlapping sweep may move the scan point on while this one works,
  // and this one decides by the point it read at its start, never a later one.
  const scanned = parsePostedScan(await w.store.inner.get(POSTED_SCAN_KEY));
  const documents = await sweepUnverified({ blobs: w.blobs, store: w.store, blobOrigin: ORIGIN, now: at, clock: w.clock }).catch((e: unknown) => String(e));
  h.answers.push(`sweep documents: ${plain(documents)}`);
  if (typeof documents !== "string" && documents.done === "swept") h.docSweeps.push({ at, scanTime: scanned?.time, due });
}

function scheduledSweep(unreadable: number | null, chaos: Chaos): Step {
  const name = named("sweep", [unreadable === null ? "" : `unreadable=${unreadable}`, chaosText(chaos)]);
  return command(name, (h) => step(h, "sweep", name, { ...chaos, unreadable: unreadableOf(h, unreadable) }, () => sweepFlow(h)));
}

export type DocLie = "none" | "bytes" | "size";
export type DocStop = "token" | "upload" | "verify" | "post";

/** The bytes of one test document: deterministic from its salt, so a run replays the same names. */
function documentBytes(salt: number, size: number): Uint8Array {
  const out = new Uint8Array(size);
  let block = sha256(new TextEncoder().encode(`document ${salt}`));
  for (let i = 0; i < size; i++) {
    if (i % 32 === 0 && i > 0) block = sha256(block);
    out[i] = block[i % 32] ?? 0;
  }
  return out;
}

function documentFlow(ip: number, size: number, declareCap: boolean, lie: DocLie, stopAfter: DocStop, direct: boolean, board: number, chaos: Chaos): Step {
  const name = named("document", [`ip=${ip}`, `size=${size}`, declareCap ? "declares 25 MiB" : "", `lie=${lie}`, `until=${stopAfter}`, direct ? "direct" : "", `board=${PUBLIC_BOARDS[board]}`, chaosText(chaos)]);
  return command(name, (h) =>
    step(h, "document", name, chaos, async () => {
      const w = h.world;
      const from = ipOf(ip);
      const salt = h.nextSalt++;
      const bytes = documentBytes(salt, size);
      const hex = Buffer.from(sha256(bytes)).toString("hex");
      const asked = { sha256: hex };
      const tokenBody = { sha256: hex, size: declareCap ? DOCUMENT_CAP : size };
      h.history.push({ kind: "token", body: tokenBody, ip: from });
      const token = await answerOf(await guarded("handleDocumentToken", () => handleDocumentToken(appRequest("/api/document/token", tokenBody), w.documentContext(from))));
      h.answers.push(`document token: ${token.status} ${token.error ?? ""}`);
      if (stopAfter === "token" || token.status !== 200) return;
      if (token.body.exists === false) {
        await w.blobs.put(`document/${hex}`, lie === "bytes" ? documentBytes(salt + 1_000_000, size) : bytes);
        w.docs.set(`document/${hex}`, { honest: lie !== "bytes", size, uploadedAt: w.now });
      }
      if (stopAfter === "upload") return;
      h.history.push({ kind: "verify", body: asked, ip: from });
      const verified = await answerOf(await guarded("handleDocumentVerify", () => handleDocumentVerify(appRequest("/api/document/verify", asked), w.documentContext(from))));
      h.answers.push(`document verify: ${verified.status} ${verified.error ?? ""}`);
      if (stopAfter === "verify") return;
      const boardId = PUBLIC_BOARDS[board] as bigint;
      const current = w.board(boardId);
      const cipherSize = BigInt(size + (lie === "size" ? 1 : 0));
      const body = postBody(w, boardId, current.nonce, salt, `0x${hex}`, cipherSize);
      if (direct) {
        const data = encodeFunctionData({
          abi: boardRegistryAbi,
          functionName: "postDocument",
          args: [boardId, body.params.docRef as Hex, `0x${hex}`, cipherSize, current.epoch, BigInt(body.deadline), fakeSignature(current.nonce, true, salt)],
        });
        h.answers.push(`document posted directly: ${w.direct(data)}`);
        return;
      }
      h.history.push({ kind: "relay", body, ip: from, boardId, nonce: current.nonce, salt });
      await relayPublic(h, body, from, { boardId, nonce: current.nonce, salt });
    }),
  );
}

/** Addresses enough to reach every document byte cap in one command: sixty IPv4 clients, and the /64s of one IPv6 /48. */
function floodIp(i: number): string {
  return i % 5 === 4 ? `2001:db8:48:${i.toString(16)}::1` : `198.18.${Math.floor(i / 200)}.${(i % 200) + 1}`;
}

/**
 * Many clients each ask for cap-size document tokens and upload nothing, so the per-client, the
 * /48 and the total daily byte caps are all reached in one command (threat model C28, C44).
 */
function tokenFlood(clients: number, perClient: number, chaos: Chaos): Step {
  const name = named("flood", [`clients=${clients}`, `tokens=${perClient}`, chaosText(chaos)]);
  return command(name, (h) =>
    step(h, "flood", name, chaos, async () => {
      const w = h.world;
      let issued = 0;
      let refused = 0;
      for (let i = 0; i < clients; i++) {
        const from = floodIp(i);
        for (let k = 0; k < perClient; k++) {
          const hex = Buffer.from(sha256(new TextEncoder().encode(`flood ${h.nextSalt++}`))).toString("hex");
          const body = { sha256: hex, size: DOCUMENT_CAP };
          h.history.push({ kind: "token", body, ip: from });
          const answer = await answerOf(await guarded("handleDocumentToken", () => handleDocumentToken(appRequest("/api/document/token", body), w.documentContext(from))));
          if (answer.status === 200) issued += 1;
          if (answer.error === "upload_bytes") refused += 1;
        }
      }
      h.answers.push(`flood: ${issued} tokens issued, ${refused} refused upload_bytes`);
    }),
  );
}

/** Whole days too, so what outlives a day or two (ledger keys, the unsettled list, marks) is reached past its end. */
export type ClockStep = { kind: "seconds"; seconds: number } | { kind: "days"; days: number } | { kind: "hour" | "day"; justBefore: boolean };

function clockJump(jump: ClockStep): Step {
  const name =
    jump.kind === "seconds" ? `clock(+${jump.seconds}s)` : jump.kind === "days" ? `clock(+${jump.days} days)` : `clock(next ${jump.kind}${jump.justBefore ? ", 2 s before" : ""})`;
  return command(name, (h) =>
    step(h, "clock", name, {}, async () => {
      const w = h.world;
      if (jump.kind === "seconds" || jump.kind === "days") {
        w.advance(jump.kind === "seconds" ? jump.seconds * 1000 : jump.days * DAY);
        return;
      }
      const unit = jump.kind === "hour" ? HOUR : DAY;
      const boundary = (Math.floor(w.now / unit) + 1) * unit;
      const target = jump.justBefore ? boundary - 2_000 : boundary + 1_000;
      w.advance(target > w.now ? target - w.now : unit);
    }),
  );
}

function chainSettles(how: "mine" | "lose" | "revert"): Step {
  const name = `chain(${how} oldest)`;
  return command(name, (h) => step(h, "chain", name, {}, async () => h.world.settleOldest(how)));
}

function foreignTx(throughWindow: boolean): Step {
  const name = `foreign(${throughWindow ? "through the window" : "native"})`;
  return command(name, (h) => step(h, "foreign", name, {}, async () => h.world.foreignTx(throughWindow)));
}

/**
 * One request inside an overlap. A relay is a new action at the board's nonce ("fresh"), a
 * byte-identical copy of a recent relay, or a re-signing at a recent relay's nonce. A clock part
 * waits some turns and then moves time on, which can run a lock out under its holder.
 */
export type Part =
  | { kind: "relay"; how: "fresh" | "copy" | "resign"; board: number; pick: number; ip: number }
  | { kind: "join"; guest: number; ip: number }
  | { kind: "pressure" }
  | { kind: "sweep" }
  | { kind: "clock"; seconds: number; after: number };

function partText(p: Part): string {
  switch (p.kind) {
    case "relay":
      return `relay ${p.how} ${p.how === "fresh" ? `board=${PUBLIC_BOARDS[p.board]}` : `pick=${p.pick}`} ip=${p.ip}`;
    case "join":
      return `join guest=${p.guest} ip=${p.ip}`;
    case "clock":
      return `clock +${p.seconds}s after ${p.after} turns`;
    default:
      return p.kind;
  }
}

/**
 * The work a part does, with every choice that reads the history made now, before any part runs, so
 * two parts that name one earlier relay both act on it, and two fresh ones share a nonce.
 */
function preparePart(h: Harness, p: Part): () => Promise<void> {
  const w = h.world;
  switch (p.kind) {
    case "relay": {
      const ip = ipOf(p.ip);
      if (p.how === "fresh") {
        const boardId = PUBLIC_BOARDS[p.board] as bigint;
        const nonce = w.board(boardId).nonce;
        return async () => {
          const salt = h.nextSalt++;
          const body = rotateBody(w, boardId, nonce, salt);
          h.history.push({ kind: "relay", body, ip, boardId, nonce, salt });
          await relayPublic(h, body, ip, { boardId, nonce, salt });
        };
      }
      const earlier = recent(relaysIn(h), p.pick);
      if (earlier === undefined) return async () => undefined;
      if (p.how === "copy") return () => relayPublic(h, earlier.body, ip === earlier.ip ? ipOf(p.ip + 1) : ip, earlier);
      return async () => {
        const salt = h.nextSalt++;
        const body = rotateBody(w, earlier.boardId, earlier.nonce, salt);
        h.history.push({ kind: "relay", body, ip, boardId: earlier.boardId, nonce: earlier.nonce, salt });
        await relayPublic(h, body, ip, { boardId: earlier.boardId, nonce: earlier.nonce, salt });
      };
    }
    case "join":
      return () => joinFlow(h, p.guest, "valid", p.ip);
    case "pressure":
      return () => pressureFlow(h);
    case "sweep":
      return () => sweepFlow(h);
    case "clock":
      return async () => {
        for (let i = 0; i < p.after; i++) await w.turn("clock");
        w.advance(p.seconds * 1000);
      };
  }
}

/** The order the scheduler ran the requests in, as runs of turns per request ("2x5" is five turns of request 2), for the failure report. */
function scheduleText(s: fc.Scheduler): string {
  const runs: string[] = [];
  let last: string | undefined;
  let count = 0;
  for (const item of s.report()) {
    const who = item.label.split(" ")[0] ?? "-";
    if (who === last) {
      count += 1;
      continue;
    }
    if (last !== undefined) runs.push(`${last}x${count}`);
    last = who;
    count = 1;
  }
  if (last !== undefined) runs.push(`${last}x${count}`);
  return runs.length > 40 ? `${runs.slice(0, 40).join(" ")} ... (${runs.length} runs)` : runs.join(" ");
}

/**
 * Two or three requests at once. The scheduler, drawn from `seed`, picks which waiting step goes
 * next at every store call, chain call and wait, so races the one-at-a-time commands never reach
 * are reached here: two joins of one guest, a join behind a pass that holds demo:join, two relays at
 * one nonce, a mark taken back while another relay claims it, a lock that runs out under its holder.
 */
function overlapRun(seed: number, parts: readonly Part[], chaos: Chaos): Step {
  const name = named("overlap", [`[${parts.map(partText).join(" | ")}]`, `seed=${seed}`, chaosText(chaos)]);
  return command(name, async (h) => {
    const w = h.world;
    w.begin("overlap", chaos);
    try {
      const works = parts.map((p) => ({ p, work: preparePart(h, p) }));
      const [s] = fc.sample(fc.scheduler(), { seed, numRuns: 1 });
      if (s === undefined) throw new Error("fast-check drew no scheduler.");
      w.scheduler = s;
      const flows = works.map(({ p, work }) => w.runFlow(p.kind, p.kind === "join" ? String(p.guest) : undefined, work));
      const results = await s.waitFor(Promise.allSettled(flows));
      h.lastSchedule = scheduleText(s);
      for (const result of results) {
        if (result.status === "fulfilled") continue;
        if (!(result.reason instanceof HandlerThrew) || h.strictThrows) throw result.reason;
        h.answers.push(result.reason.message);
      }
    } finally {
      w.end();
    }
    await h.after(name);
  });
}

const latencyArb = fc.oneof({ arbitrary: fc.constant(0), weight: 8 }, { arbitrary: fc.constantFrom(800, 2_500), weight: 1 });
const fateArb: fc.Arbitrary<TxFate> = fc.oneof(
  { arbitrary: fc.constant<TxFate>("land"), weight: 4 },
  { arbitrary: fc.constantFrom<TxFate>("slow", "pending", "revert", "refuse", "lostReply", "noReceipt", "lieReceipt"), weight: 3 },
);
const chaosArb: fc.Arbitrary<Chaos> = fc.record({
  latency: latencyArb,
  fates: fc.array(fateArb, { maxLength: 3 }),
  nativeFates: fc.array(fc.constantFrom<NativeFate>("commit", "refuse"), { maxLength: 2 }),
  // Dense on purpose: a lost reply on any one write is rare in production, but every write must survive one.
  lost: fc.oneof(
    { weight: 6, arbitrary: fc.constant<LostMode>({ kind: "none" }) },
    { weight: 2, arbitrary: fc.uniqueArray(fc.integer({ min: 1, max: 120 }), { minLength: 1, maxLength: 3 }).map((ordinals): LostMode => ({ kind: "at", ordinals })) },
    { weight: 1, arbitrary: fc.constant<LostMode>({ kind: "every" }) },
    { weight: 2, arbitrary: fc.integer({ min: 0, max: 0x7fff_ffff }).map((seed): LostMode => ({ kind: "chance", seed })) },
  ),
});
const ipArb = fc.integer({ min: 0, max: CLIENT_IPS.length - 1 });
const boardArb = fc.integer({ min: 0, max: PUBLIC_BOARDS.length - 1 });
const guestArb = fc.integer({ min: 0, max: 5 });
const unreadableArb = fc.oneof({ arbitrary: fc.constant(null), weight: 6 }, { arbitrary: fc.nat(40), weight: 1 });

const joinKindArb = fc.oneof({ arbitrary: fc.constant<JoinKind>("valid"), weight: 4 }, { arbitrary: fc.constantFrom<JoinKind>("noKem", "copied", "unreadable"), weight: 1 });
const documentArb = fc
  .tuple(
    ipArb,
    fc.integer({ min: 1, max: 3_000 }),
    fc.boolean(),
    fc.constantFrom<DocLie>("none", "none", "bytes", "size"),
    fc.constantFrom<DocStop>("post", "post", "token", "upload", "verify"),
    fc.boolean(),
    boardArb,
    chaosArb,
  )
  .map(([ip, size, cap, lie, stop, direct, b, c]) => documentFlow(ip, size, cap, lie, stop, direct, b, c));
const clockArb = fc
  .oneof(
    fc.constantFrom(1, 30, 300, 1_800, 7_300).map((seconds): ClockStep => ({ kind: "seconds", seconds })),
    fc.tuple(fc.constantFrom<"hour" | "day">("hour", "day"), fc.boolean()).map(([kind, justBefore]): ClockStep => ({ kind, justBefore })),
    fc.constantFrom(2, 3).map((days): ClockStep => ({ kind: "days", days })),
  )
  .map((j) => clockJump(j));

const relayHowArb = fc.constantFrom<"fresh" | "copy" | "resign">("fresh", "copy", "resign");
const relayPartArb: fc.Arbitrary<Part> = fc.record({ kind: fc.constant("relay" as const), how: relayHowArb, board: boardArb, pick: fc.nat(3), ip: ipArb });
const clockPartArb: fc.Arbitrary<Part> = fc.record({ kind: fc.constant("clock" as const), seconds: fc.constantFrom(160, 400), after: fc.integer({ min: 1, max: 40 }) });
const anyPartArb: fc.Arbitrary<Part> = fc.oneof(
  relayPartArb,
  fc.record({ kind: fc.constant("join" as const), guest: guestArb, ip: ipArb }),
  fc.constant<Part>({ kind: "pressure" }),
  fc.constant<Part>({ kind: "sweep" }),
  clockPartArb,
);
/** The races the order asks for by name, then any two or three requests at all. */
const partsArb: fc.Arbitrary<Part[]> = fc.oneof(
  fc.tuple(guestArb, ipArb, ipArb).map(([guest, a, b]): Part[] => [
    { kind: "join", guest, ip: a },
    { kind: "join", guest, ip: b },
  ]),
  // Two guests at once: on a board one seat short, both pass the early full-board check and the
  // second meets the board the first has just filled only once it holds the join lock.
  fc
    .tuple(guestArb, guestArb, ipArb, ipArb)
    .filter(([a, b]) => a !== b)
    .map(([a, b, ipA, ipB]): Part[] => [
      { kind: "join", guest: a, ip: ipA },
      { kind: "join", guest: b, ip: ipB },
    ]),
  fc
    .tuple(guestArb, ipArb, fc.constantFrom<"pressure" | "sweep">("pressure", "sweep"), fc.option(clockPartArb, { nil: undefined }))
    .map(([guest, ip, holder, clock]): Part[] => [{ kind: holder }, { kind: "join", guest, ip }, ...(clock === undefined ? [] : [clock])]),
  fc
    .tuple(boardArb, fc.nat(3), fc.array(fc.tuple(relayHowArb, ipArb), { minLength: 2, maxLength: 3 }))
    .map(([board, pick, hows]): Part[] => hows.map(([how, ip]) => ({ kind: "relay", how, board, pick, ip }))),
  fc.array(anyPartArb, { minLength: 2, maxLength: 3 }),
);

/**
 * Every command the model draws from, weighted toward the relay and the demo board, where the promises
 * live. A foreign transaction halts the relayer for the rest of a run, so it is drawn rarely.
 */
export const commandArbs: fc.Arbitrary<Step>[] = [
  fc.oneof(
    { weight: 18, arbitrary: fc.tuple(boardArb, ipArb, chaosArb).map(([b, ip, c]) => publicRelay(b, ip, c)) },
    { weight: 6, arbitrary: fc.tuple(fc.nat(), ipArb, chaosArb).map(([p, ip, c]) => copyRelay(p, ip, c)) },
    { weight: 6, arbitrary: fc.tuple(fc.nat(), ipArb, chaosArb).map(([p, ip, c]) => resignedRelay(p, ip, c)) },
    { weight: 3, arbitrary: fc.tuple(fc.constantFrom<JunkKind>("schema", "badSignature", "staleNonce"), boardArb, ipArb).map(([v, b, ip]) => junkRelay(v, b, ip)) },
    { weight: 6, arbitrary: fc.tuple(fc.nat(), chaosArb).map(([p, c]) => clientRetry(p, c)) },
    { weight: 3, arbitrary: fc.tuple(guestArb, ipArb).map(([g, ip]) => demoChallenge(g, ip)) },
    { weight: 15, arbitrary: fc.tuple(guestArb, joinKindArb, ipArb, chaosArb).map(([g, k, ip, c]) => demoJoin(g, k, ip, c)) },
    { weight: 6, arbitrary: fc.tuple(unreadableArb, chaosArb).map(([u, c]) => pressurePass(u, c)) },
    { weight: 6, arbitrary: fc.tuple(unreadableArb, chaosArb).map(([u, c]) => scheduledSweep(u, c)) },
    { weight: 9, arbitrary: documentArb },
    { weight: 6, arbitrary: clockArb },
    { weight: 9, arbitrary: fc.constantFrom<"mine" | "lose" | "revert">("mine", "mine", "lose", "revert").map((how) => chainSettles(how)) },
    { weight: 1, arbitrary: fc.boolean().map((through) => foreignTx(through)) },
    { weight: 1, arbitrary: fc.tuple(fc.integer({ min: 1, max: 70 }), fc.integer({ min: 1, max: 5 }), chaosArb).map(([n, k, c]) => tokenFlood(n, k, c)) },
    { weight: 10, arbitrary: fc.tuple(fc.integer({ min: 0, max: 0x7fff_ffff }), partsArb, chaosArb).map(([seed, parts, c]) => overlapRun(seed, parts, c)) },
  ),
];

/**
 * The starting state of one run. Half the runs start with the demo board a few seats from full,
 * where pressure passes and board_full live, and a third of all runs one seat short of the cap,
 * where a join can meet a board another join filled while it waited for the lock.
 */
export const worldInitArb: fc.Arbitrary<WorldInit> = fc.record({
  fillers: fc.oneof(fc.integer({ min: 0, max: 6 }), fc.integer({ min: 30, max: 36 }), fc.constant(DEMO_GUEST_CAP - 4)),
  fillerStepMinutes: fc.constantFrom(5, 20),
  tightLimits: fc.boolean(),
  demoRelaysPerHour: fc.oneof({ weight: 3, arbitrary: fc.constant(120) }, { weight: 1, arbitrary: fc.constant(3) }),
  preSpend: fc.constantFrom<WorldInit["preSpend"]>(0, 0.5, 0.97),
});
