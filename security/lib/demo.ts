import { accountBytes, challengeMessage, signAction } from "@ava/core";
import { bytesToHex, getAbiItem, hexToBytes, type Hex } from "viem";
import { REGISTRY_DEPLOY_BLOCK } from "../../packages/server/src/config.ts";
import type { Ctx } from "./context.ts";
import { dev, type DevAnswer } from "./dev.ts";
import { REGISTRY } from "./guard.ts";
import { DEMO_POOL, FILL_PROFILE, FILL_RANGE, type Person, type Profile } from "./identities.ts";
import { abi } from "./registry.ts";

const JSON_HEADERS = { "content-type": "application/json" };
const LOG_PAGE_BLOCKS = 10_000n;
/** A join holds the bot's lock for up to 120 s and may wait 20 s for it. */
const JOIN_TIMEOUT_MS = 150_000;

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

export const join = (body: string, from: string): Promise<DevAnswer> => dev({ method: "POST", path: "/api/demo/join", from, headers: JSON_HEADERS, body, timeoutMs: JOIN_TIMEOUT_MS });

/** A join's transaction hash, when it answered 202 with one. */
export function txHashOf(a: DevAnswer): Hex | undefined {
  const h = (a.json as { txHash?: unknown } | undefined)?.txHash;
  return a.status === 202 && typeof h === "string" && /^0x[0-9a-f]{64}$/.test(h) ? (h as Hex) : undefined;
}

/** The whole guest flow, each step from its own address: challenge, sign, join, then the receipt. */
export async function admit(ctx: Ctx, guest: Person): Promise<{ steps: string; answer?: DevAnswer; txHash?: Hex; landed: boolean }> {
  const asked = await askChallenge(guest, ctx.ips.fresh());
  if (asked.challenge === undefined) return { steps: `challenge -> ${asked.answer.status} ${asked.answer.error ?? ""}`.trim(), answer: asked.answer, landed: false };
  const body = joinBody(guest, asked.challenge, signBytes(guest, asked.challenge.message));
  const answer = await join(body, ctx.ips.fresh());
  const txHash = txHashOf(answer);
  if (txHash === undefined) return { steps: `join -> ${answer.status} ${answer.error ?? ""}`.trim(), answer, landed: false };
  const receipt = await ctx.client.waitForTransactionReceipt({ hash: txHash, timeout: 120_000, pollingInterval: 2_000 });
  history(ctx)?.admitted.add(key(guest.evm));
  return { steps: `join -> 202 ${txHash}, ${receipt.status}`, answer, txHash, landed: receipt.status === "success" };
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

