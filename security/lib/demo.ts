import { accountBytes, challengeMessage, sameAccount, signAction, signChallenge } from "@ava/core";
import { bytesToHex, getAbiItem, hexToBytes, type Hex } from "viem";
import { DEMO_FREE_SEATS, DEMO_GUEST_CAP, REGISTRY_DEPLOY_BLOCK, SPONSOR_AMOUNT_UQOR } from "../../packages/server/src/config.ts";
import { balanceOf, sleep } from "./chain.ts";
import type { Ctx } from "./context.ts";
import { dev, notConfigured, said, type DevAnswer } from "./dev.ts";
import { REGISTRY } from "./guard.ts";
import { DEMO_POOL, FILL_PROFILE, FILL_RANGE, type Person, type Profile } from "./identities.ts";
import { standingOf } from "./people.ts";
import { abi, boardAt, type Board } from "./registry.ts";

const JSON_HEADERS = { "content-type": "application/json" };
const LOG_PAGE_BLOCKS = 10_000n;
/** A join holds the bot's lock for up to 120 s and may wait 20 s for it. */
const JOIN_TIMEOUT_MS = 150_000;

/** The most members the demo board holds once a background pressure pass is done (C41). */
export const SEATS_AFTER_PASS = DEMO_GUEST_CAP - DEMO_FREE_SEATS;
/** How long the dev server's own background pass may take to free its seats, six removals at most. */
export const PASS_WITHIN_MS = 180_000;
const PASS_POLL_MS = 5_000;

/** The 20 bytes as lowercase hex: one key per account whatever form named it. */
export const key = (address: string): string => bytesToHex(accountBytes(address));

export interface Challenge {
  boardId: bigint;
  botNonce: Hex;
  expiry: bigint;
  message: Hex;
}

/**
 * Asks the bot for a guest challenge. The challenge counts only if the bytes it says to sign are
 * exactly the ones @ava/core builds from its fields, so the guest never signs bytes it did not check.
 */
export async function askChallenge(guest: Person, from: string): Promise<{ answer: DevAnswer; challenge?: Challenge }> {
  const answer = await dev({ method: "POST", path: "/api/demo/challenge", from, headers: JSON_HEADERS, body: JSON.stringify({ guest: guest.evm }) });
  const j = answer.json as { registry?: unknown; boardId?: unknown; botNonce?: unknown; expiry?: unknown; message?: unknown } | undefined;
  if (answer.status !== 200 || typeof j?.boardId !== "string" || typeof j.botNonce !== "string" || typeof j.expiry !== "string" || typeof j.message !== "string" || typeof j.registry !== "string") return { answer };
  if (!/^[1-9][0-9]{0,77}$/.test(j.boardId) || !/^0x[0-9a-fA-F]{64}$/.test(j.botNonce) || !/^[1-9][0-9]{0,19}$/.test(j.expiry)) return { answer };
  const challenge = { boardId: BigInt(j.boardId), botNonce: j.botNonce as Hex, expiry: BigInt(j.expiry), message: j.message as Hex };
  const rebuilt = bytesToHex(challengeMessage({ registry: REGISTRY, boardId: challenge.boardId, guest: guest.evm, botNonce: challenge.botNonce, expiry: challenge.expiry }));
  if (key(j.registry) !== key(REGISTRY) || rebuilt.toLowerCase() !== challenge.message.toLowerCase()) return { answer };
  return { answer, challenge };
}

export function joinBody(guest: Person, c: Challenge, signature: Hex): string {
  return JSON.stringify({ guest: guest.evm, botNonce: c.botNonce, expiry: c.expiry.toString(), signature });
}

/** The guest's own pure ML-DSA-87 signature over `bytes`, which @ava/core signs only in the challenge form. */
export const signBytes = (guest: Person, bytes: Hex): Hex => bytesToHex(signAction(guest.pqc.secretKey, hexToBytes(bytes)));

/**
 * The join body the app sends: the signature comes from signChallenge, built from the challenge's
 * fields and the latest block's timestamp, never from bytes the bot sent (the C33 mirror).
 */
export async function typedJoinBody(ctx: Ctx, guest: Person, c: Challenge): Promise<string> {
  const block = await ctx.client.getBlock({ blockTag: "latest" });
  const { signature } = signChallenge(guest.pqc.secretKey, { registry: REGISTRY, boardId: c.boardId, guest: guest.evm, botNonce: c.botNonce, expiry: c.expiry, latestBlockTimestamp: block.timestamp });
  return joinBody(guest, c, bytesToHex(signature));
}

const SPONSOR_TRIES = 3;
const SPONSOR_FUNDS_WITHIN_MS = 60_000;

/**
 * A fresh identity from `range` that our own sponsor has just funded: the first with no balance and
 * no key, skipping any the sponsor says it funded before. Its standing is read from the chain.
 *
 * @returns The person and a line of evidence, or the reason there is none.
 */
export async function sponsoredGuest(ctx: Ctx, range: { from: number; to: number }, role: string): Promise<{ person: Person; line: string } | { why: string }> {
  for (let index = range.from, tries = 0; index <= range.to && tries < SPONSOR_TRIES; index++) {
    const person = await ctx.people.derive(index, role);
    const before = await standingOf(person);
    if (before.balance !== 0n || before.pqc.registered) continue;
    tries++;
    const a = await dev({ method: "POST", path: "/api/sponsor", from: ctx.ips.fresh(), headers: JSON_HEADERS, body: JSON.stringify({ address: person.qor1 }), timeoutMs: 90_000 });
    if (notConfigured(a)) return { why: `the sponsor answers ${said(a)}` };
    // An earlier run whose send failed leaves the once-only mark behind: take the next fresh identity.
    if (a.status === 409 && a.error === "already_sponsored") continue;
    if (a.status !== 202) return { why: `the sponsor answered ${said(a)} for the fresh identity ${person.qor1}` };
    let balance = await balanceOf(person.qor1);
    for (const started = Date.now(); balance < SPONSOR_AMOUNT_UQOR && Date.now() - started < SPONSOR_FUNDS_WITHIN_MS; ) {
      await sleep(3_000);
      balance = await balanceOf(person.qor1);
    }
    if (balance < SPONSOR_AMOUNT_UQOR) return { why: `the sponsor answered 202 for ${person.qor1}, which holds ${balance} uqor a minute later` };
    const hash = (a.json as { txHash?: unknown } | undefined)?.txHash;
    return { person, line: `${person.qor1} (index ${index}) sponsored in ${String(hash)}, holding ${balance} uqor` };
  }
  return { why: `no fresh identity was left to sponsor in indices ${range.from} to ${range.to}` };
}

export const join = (body: string, from: string): Promise<DevAnswer> => dev({ method: "POST", path: "/api/demo/join", from, headers: JSON_HEADERS, body, timeoutMs: JOIN_TIMEOUT_MS });

/** A join's transaction hash, when it answered 202 with one. */
export function txHashOf(a: DevAnswer): Hex | undefined {
  const h = (a.json as { txHash?: unknown } | undefined)?.txHash;
  return a.status === 202 && typeof h === "string" && /^0x[0-9a-f]{64}$/.test(h) ? (h as Hex) : undefined;
}

/** What a background pressure pass did, as the registry shows it: polled read-only, never asked for. */
export interface PassSeen {
  /** True once the board held SEATS_AFTER_PASS members or fewer within PASS_WITHIN_MS. */
  reached: boolean;
  ms: number;
  /** The members the pass started from. */
  from: readonly Hex[];
  /** The board at the last read. */
  to: Board;
  /** Who in `from` is no longer a member. */
  removed: Hex[];
}

/**
 * Reads the registry, and never the server, until the demo board holds SEATS_AFTER_PASS members or
 * fewer or PASS_WITHIN_MS has passed. The dev server's own background runner does the removing.
 */
export async function awaitPass(ctx: Ctx, boardId: bigint, from: readonly Hex[]): Promise<PassSeen> {
  const started = Date.now();
  let board = await boardAt(ctx.client, boardId);
  while (board.members.length > SEATS_AFTER_PASS && Date.now() - started < PASS_WITHIN_MS) {
    await sleep(PASS_POLL_MS);
    board = await boardAt(ctx.client, boardId);
  }
  const to = board;
  const removed = from.filter((m) => !to.members.some((n) => sameAccount(n, m)));
  return { reached: to.members.length <= SEATS_AFTER_PASS, ms: Date.now() - started, from, to, removed };
}

/** A pass the way evidence lines quote it. */
export const passLine = (p: PassSeen): string =>
  `${p.reached ? "brought the board" : "DID NOT BRING THE BOARD"} to ${SEATS_AFTER_PASS} or fewer in ${Math.round(p.ms / 1000)} s (${p.from.length} members to ${p.to.members.length}), removing ${p.removed.join(", ") || "nobody"}`;

export interface Admission {
  steps: string;
  /** The last join's answer. */
  answer?: DevAnswer;
  /** The join body that was answered 202, for a replay. */
  body?: string;
  txHash?: Hex;
  landed: boolean;
  /**
   * The first join met a full board: the board just before it and just after its 503, the
   * retry-after it gave, the background pass that then freed seats, and whether the join after
   * that pass went on the first challenge (false when the server said it was gone, so a fresh one
   * was asked for, and when the pass never freed seats, so no join followed).
   */
  full?: { before: Board; after: Board; retryAfter: string | undefined; pass: PassSeen; sameChallenge: boolean };
  /** The background pass the admission started by leaving the board above SEATS_AFTER_PASS. */
  pass?: PassSeen;
}

const admittedThisRun = new WeakMap<Ctx, Person[]>();

/** Every guest admit() seated this run, in the order they were admitted. */
export const ourGuests = (ctx: Ctx): readonly Person[] => admittedThisRun.get(ctx) ?? [];

/** A join body over a fresh challenge, or the failed challenge's answer. */
async function freshBody(guest: Person, ctx: Ctx): Promise<{ body: string } | { answer: DevAnswer; line: string }> {
  const asked = await askChallenge(guest, ctx.ips.fresh());
  if (asked.challenge === undefined) return { answer: asked.answer, line: `challenge -> ${said(asked.answer)}` };
  return { body: joinBody(guest, asked.challenge, signBytes(guest, asked.challenge.message)) };
}

const membersKey = (b: Board): string => b.members.map(key).sort().join(",");

/** The server's answers that a join's challenge can no longer be used: none is stored, or its expiry has passed. */
const challengeGone = (a: DevAnswer): boolean => (a.status === 409 && a.error === "no_challenge") || (a.status === 403 && a.error === "challenge_expired");

/**
 * The guest flow a judge follows, each step from its own address: challenge, sign, join, then the
 * receipt (C41). A join that answers 503 board_full is never a removal: the board is read right
 * after it, the dev server's own background pass is waited for until the board holds
 * SEATS_AFTER_PASS members or fewer, and the guest then sends the same join again, because the bot
 * answers board_full before it reads the challenge or counts anything. Only when that answer says
 * the challenge is gone does the guest ask for a fresh one and join once more. An admission that
 * leaves the board above SEATS_AFTER_PASS starts a pass too, and that pass is waited for as well,
 * so the next attack finds the board still.
 *
 * @param firstBody The first join's body, when the caller signed its own challenge; otherwise a
 *   fresh challenge is asked for.
 * @throws When DEMO_BOARD_ID is not set; callers report "not run" before that.
 */
export async function admit(ctx: Ctx, guest: Person, firstBody?: string): Promise<Admission> {
  const boardId = ctx.env.demoBoardId;
  if (boardId === undefined) throw new Error("DEMO_BOARD_ID is not set in security/.env.");
  const steps: string[] = [];
  let before = await boardAt(ctx.client, boardId);
  let made = firstBody === undefined ? await freshBody(guest, ctx) : { body: firstBody };
  if (!("body" in made)) return { steps: made.line, answer: made.answer, landed: false };
  let body = made.body;
  let answer = await join(body, ctx.ips.fresh());
  let full: Admission["full"];
  if (answer.status === 503 && answer.error === "board_full") {
    const after = await boardAt(ctx.client, boardId);
    const retryAfter = answer.headers["retry-after"];
    const still = after.nonce === before.nonce && membersKey(after) === membersKey(before);
    steps.push(
      `join -> 503 board_full, retry-after ${retryAfter ?? "none"}; the board read just after: ${after.members.length} members, nonce ${after.nonce}, ${still ? "as just before" : `CHANGED from ${before.members.length} members, nonce ${before.nonce}`}`,
    );
    const pass = await awaitPass(ctx, boardId, before.members);
    steps.push(`with no request from us, the background pass ${passLine(pass)}`);
    if (!pass.reached) return { steps: steps.join("; "), answer, full: { before, after, retryAfter, pass, sameChallenge: false }, landed: false };
    answer = await join(body, ctx.ips.fresh());
    const sameChallenge = !challengeGone(answer);
    full = { before, after, retryAfter, pass, sameChallenge };
    before = pass.to;
    if (sameChallenge) {
      steps.push("the same join again, on the challenge board_full left in place");
    } else {
      steps.push(`the same join again -> ${said(answer)}, so a fresh challenge, signed`);
      made = await freshBody(guest, ctx);
      if (!("body" in made)) return { steps: [...steps, `fresh ${made.line}`].join("; "), answer: made.answer, full, landed: false };
      body = made.body;
      answer = await join(body, ctx.ips.fresh());
    }
  }
  const txHash = txHashOf(answer);
  if (txHash === undefined) return { steps: [...steps, `join -> ${said(answer)}`].join("; "), answer, ...(full === undefined ? {} : { full }), landed: false };
  const receipt = await ctx.client.waitForTransactionReceipt({ hash: txHash, timeout: 120_000, pollingInterval: 2_000 });
  history(ctx)?.admitted.add(key(guest.evm));
  steps.push(`join -> 202 ${txHash}, ${receipt.status}`);
  const landed = receipt.status === "success";
  if (landed) admittedThisRun.set(ctx, [...ourGuests(ctx), guest]);
  let pass: PassSeen | undefined;
  // The bot starts a pass after any admission that leaves more than SEATS_AFTER_PASS members
  // (packages/server/src/demo.ts admit), so the guest's own seat counts in the members it starts from.
  if (landed && before.members.length + 1 > SEATS_AFTER_PASS) {
    pass = await awaitPass(ctx, boardId, [...before.members, guest.evm]);
    steps.push(`the background pass this admission started ${passLine(pass)}`);
  }
  return { steps: steps.join("; "), answer, body, txHash, landed, ...(full === undefined ? {} : { full }), ...(pass === undefined ? {} : { pass }) };
}

/** Who the demo board has ever admitted, and when each current member was added (block number), from the registry's own events. */
export interface DemoHistory {
  admitted: Set<string>;
  addedAt: Map<string, bigint>;
  /** The transaction of the board's latest membership change: an action the demo chair's ML-DSA key signed. */
  lastTx?: Hex;
}

const state = new WeakMap<Ctx, { history: DemoHistory; next: number }>();
const history = (ctx: Ctx): DemoHistory | undefined => state.get(ctx)?.history;

const MEMBER_ADDED = getAbiItem({ abi, name: "MemberAdded" });
const MEMBER_REMOVED = getAbiItem({ abi, name: "MemberRemoved" });

/** Reads every MemberAdded and MemberRemoved of the demo board since the registry's deploy block, in pages, once a run. */
export async function demoHistory(ctx: Ctx, boardId: bigint, fresh = false): Promise<DemoHistory> {
  const known = state.get(ctx);
  if (known !== undefined && !fresh) return known.history;
  const latest = await ctx.client.getBlockNumber();
  const events: { block: bigint; index: number; added: boolean; member: string; tx: Hex }[] = [];
  for (let from = REGISTRY_DEPLOY_BLOCK; from <= latest; from += LOG_PAGE_BLOCKS) {
    const to = from + LOG_PAGE_BLOCKS - 1n < latest ? from + LOG_PAGE_BLOCKS - 1n : latest;
    const logs = await ctx.client.getLogs({ address: REGISTRY, events: [MEMBER_ADDED, MEMBER_REMOVED], fromBlock: from, toBlock: to, strict: true });
    for (const log of logs) {
      if (log.removed || log.args.boardId !== boardId || log.blockNumber === null || log.logIndex === null || log.transactionHash === null) continue;
      events.push({ block: log.blockNumber, index: log.logIndex, added: log.eventName === "MemberAdded", member: key(log.args.member), tx: log.transactionHash });
    }
  }
  events.sort((a, b) => (a.block === b.block ? a.index - b.index : a.block < b.block ? -1 : 1));
  const admitted = new Set<string>();
  const addedAt = new Map<string, bigint>();
  for (const e of events) {
    if (e.added) {
      admitted.add(e.member);
      addedAt.set(e.member, e.block);
    } else {
      addedAt.delete(e.member);
    }
  }
  const lastTx = events.at(-1)?.tx;
  const h: DemoHistory = { admitted, addedAt, ...(lastTx === undefined ? {} : { lastTx }) };
  state.set(ctx, { history: h, next: known?.next ?? DEMO_POOL.from });
  return h;
}

/** The next pool identity the demo board has never admitted, set up for `profile`. */
export async function freshGuest(ctx: Ctx, boardId: bigint, role: string, profile: Profile = FILL_PROFILE): Promise<Person> {
  const h = await demoHistory(ctx, boardId);
  const s = state.get(ctx)!;
  for (; s.next <= DEMO_POOL.to; s.next++) {
    const person = await ctx.people.derive(s.next, role);
    if (h.admitted.has(key(person.evm))) continue;
    s.next++;
    await ctx.people.ensureAll([{ person, profile }]);
    return person;
  }
  throw new Error("Every identity in the demo pool has been admitted once already.");
}

/**
 * Guests to fill the demo board: first the C7 fill identities the board has never admitted (they
 * are registered already when C7 ran), then fresh pool identities.
 */
export async function fillGuests(ctx: Ctx, boardId: bigint, count: number): Promise<Person[]> {
  const h = await demoHistory(ctx, boardId);
  const out: Person[] = [];
  for (const person of await ctx.people.fill(FILL_RANGE.count)) {
    if (out.length >= count) break;
    if (!h.admitted.has(key(person.evm))) out.push(person);
  }
  await ctx.people.ensureAll(out.map((person) => ({ person, profile: FILL_PROFILE })));
  while (out.length < count) out.push(await freshGuest(ctx, boardId, `guest${out.length + 1}`));
  return out;
}

