import { evmWindowCost } from "@qorechain/evm";
import { accountBytes, toHex } from "@ava/core";
import { bytesToHex, decodeErrorResult, decodeFunctionResult, encodeFunctionData, type Hex } from "viem";
import { z } from "zod";
import { boardRegistryAbi } from "./abi/boardRegistry.ts";
import type { RelayerAddress } from "./chain/account.ts";
import { OutOfTime, elapsedMs, startDeadline, within, type Deadline } from "./chain/deadline.ts";
import type { CallOutcome, FeeQuote, RelayChain } from "./chain/types.ts";
import {
  GAS_CEILING,
  LOCK_TTL_SECONDS,
  MAX_FEE_PER_GAS,
  REGISTRY_ADDRESS,
  RELAY_BODY_CAP,
  RELAY_DEADLINE_MS,
  RELAY_LIMITS,
  SEND_CUTOFF_MS,
  SEND_LOCK_WAIT_MS,
  type RelayAction,
} from "./config.ts";
import { declaredLength, json, readCapped, refuse, TooLarge, type HandlerContext } from "./http.ts";
import { logEvent } from "./log.ts";
import { clientKey } from "./ratelimit.ts";
import { accountBytesStrict } from "./requestAddress.ts";
import { LockBusy } from "./store.ts";
import { DailyCeilingReached, RelayerHalted, ensureWindow, isHalted, recordWindowSend, reserveSpend, type WindowState } from "./window.ts";

export interface RelayLimits {
  perIp: number;
  perChair: number;
  perBoard: number;
  /** Actions whose pre-flight passed, across every chair and board. */
  total: number;
  /** Requests whose pre-flight failed, across every IP. */
  rejected: number;
  windowSeconds: number;
}

export type RelayContext = HandlerContext & {
  /** The relayer's public addresses. Its keys live only inside `chain`. */
  relayer: RelayerAddress;
  chain: RelayChain;
  /** Overrides RELAY_LIMITS. */
  limits?: RelayLimits;
  /** The pause after a window opens. Tests pass one that moves their clock instead of waiting. */
  sleep?: (ms: number) => Promise<void>;
  /** A monotonic clock in milliseconds for the time budget; the process's own by default. */
  clock?: () => number;
};

export const SEND_LOCK = "relayer:send";
const REJECTED_KEY = "rate:relay:rejected";
const VALID_KEY = "rate:relay:valid";

const DECIMAL = /^(0|[1-9][0-9]{0,77})$/;
const MAX_UINT = { 8: 0xffn, 32: 0xffff_ffffn, 64: 0xffff_ffff_ffff_ffffn, 256: (1n << 256n) - 1n } as const;
const SIGNATURE_HEX = /^0x[0-9a-fA-F]{9254}$/;

/** An unsigned integer as a canonical decimal string (no sign, no leading zeros), within its Solidity type. */
const uint = (bits: keyof typeof MAX_UINT, min = 0n) =>
  z
    .string()
    .regex(DECIMAL)
    .transform((s) => BigInt(s))
    .refine((n) => n >= min && n <= MAX_UINT[bits]);

const bytes32 = z
  .string()
  .regex(/^0x[0-9a-fA-F]{64}$/)
  .transform((s) => s.toLowerCase() as Hex);

/** A 0x address in exact EIP-55 form, decoded to its 20 bytes by the strict shared codec (threat model C16). */
const address = z
  .string()
  .max(42)
  .transform((s, ctx) => {
    if (s.startsWith("0x")) {
      try {
        return toHex(accountBytesStrict(s));
      } catch {
        // Falls through to the issue below.
      }
    }
    ctx.addIssue({ code: "custom", message: "not a 0x address" });
    return z.NEVER;
  });

/** Exactly 4,627 bytes: one ML-DSA-87 signature. */
const signature = z
  .string()
  .regex(SIGNATURE_HEX)
  .transform((s) => s.toLowerCase() as Hex);

const common = { deadline: uint(64), signature };
const boardId = uint(256, 1n);

/**
 * The relay body. Unknown top-level fields, such as a target, a gas limit or a value, are dropped
 * and never read: the relayer builds the whole transaction itself. Inside `params` only the fields
 * of that action (docs/spec/actions.md) are accepted.
 */
const relayBody = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("create"),
    boardId: z.never().optional(),
    params: z.strictObject({ chair: address, boardRef: bytes32, envelopeHash: bytes32, envelopeSize: uint(32) }),
    ...common,
  }),
  z.object({
    action: z.literal("add"),
    boardId,
    params: z.strictObject({ member: address, mode: uint(8), envelopeHash: bytes32, envelopeSize: uint(32), epochAfter: uint(64) }),
    ...common,
  }),
  z.object({
    action: z.literal("remove"),
    boardId,
    params: z.strictObject({ member: address, envelopeHash: bytes32, envelopeSize: uint(32), epochAfter: uint(64) }),
    ...common,
  }),
  z.object({
    action: z.literal("rotate"),
    boardId,
    params: z.strictObject({ envelopeHash: bytes32, envelopeSize: uint(32), epochAfter: uint(64) }),
    ...common,
  }),
  z.object({
    action: z.literal("post"),
    boardId,
    params: z.strictObject({ docRef: bytes32, cipherHash: bytes32, cipherSize: uint(64), epoch: uint(64) }),
    ...common,
  }),
  z.object({
    action: z.literal("transfer"),
    boardId,
    params: z.strictObject({ newChair: address }),
    ...common,
  }),
]);

type RelayBody = z.infer<typeof relayBody>;

interface Built {
  action: RelayAction;
  data: Hex;
  /** Set for every action but create. */
  boardId?: bigint;
  /** Set for create only: the chair named in the signed parameters. */
  chair?: Hex;
}

/** The calldata, built by the server from the typed fields and the generated ABI (threat model C24). */
export function buildCalldata(b: RelayBody): Built {
  const abi = boardRegistryAbi;
  switch (b.action) {
    case "create": {
      const p = b.params;
      const data = encodeFunctionData({ abi, functionName: "createBoard", args: [p.chair, p.boardRef, p.envelopeHash, Number(p.envelopeSize), b.deadline, b.signature] });
      return { action: "create", data, chair: p.chair };
    }
    case "add": {
      const p = b.params;
      const args = [b.boardId, p.member, Number(p.mode), p.envelopeHash, Number(p.envelopeSize), p.epochAfter, b.deadline, b.signature] as const;
      return { action: "add", data: encodeFunctionData({ abi, functionName: "addMember", args }), boardId: b.boardId };
    }
    case "remove": {
      const p = b.params;
      const args = [b.boardId, p.member, p.envelopeHash, Number(p.envelopeSize), p.epochAfter, b.deadline, b.signature] as const;
      return { action: "remove", data: encodeFunctionData({ abi, functionName: "removeMember", args }), boardId: b.boardId };
    }
    case "rotate": {
      const p = b.params;
      const args = [b.boardId, p.envelopeHash, Number(p.envelopeSize), p.epochAfter, b.deadline, b.signature] as const;
      return { action: "rotate", data: encodeFunctionData({ abi, functionName: "rotateEpoch", args }), boardId: b.boardId };
    }
    case "post": {
      const p = b.params;
      const args = [b.boardId, p.docRef, p.cipherHash, p.cipherSize, p.epoch, b.deadline, b.signature] as const;
      return { action: "post", data: encodeFunctionData({ abi, functionName: "postDocument", args }), boardId: b.boardId };
    }
    case "transfer": {
      const args = [b.boardId, b.params.newChair, b.deadline, b.signature] as const;
      return { action: "transfer", data: encodeFunctionData({ abi, functionName: "transferChair", args }), boardId: b.boardId };
    }
  }
}

const REGISTRY_ERRORS: ReadonlySet<string> = new Set(boardRegistryAbi.flatMap((entry) => (entry.type === "error" ? [entry.name] : [])));

/**
 * The registry's custom error name for a revert, or "reverted". Only names the registry's own ABI
 * declares can come out, so nothing the chain or a caller wrote is ever echoed.
 */
export function revertName(data: Hex | undefined): string {
  if (data === undefined || data === "0x") return "reverted";
  try {
    const { errorName } = decodeErrorResult({ abi: boardRegistryAbi, data });
    return REGISTRY_ERRORS.has(errorName) ? errorName : "reverted";
  } catch {
    return "reverted";
  }
}

/**
 * EIP-1559 fees for one send: a fee cap of twice the base fee plus the tip, held at MAX_FEE_PER_GAS,
 * or undefined when even the base fee plus the tip would not fit under that ceiling.
 */
export function feeCaps(quote: FeeQuote): { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint } | undefined {
  const { baseFeePerGas, maxPriorityFeePerGas } = quote;
  if (baseFeePerGas <= 0n || maxPriorityFeePerGas < 0n) return undefined;
  const wanted = baseFeePerGas * 2n + maxPriorityFeePerGas;
  const maxFeePerGas = wanted < MAX_FEE_PER_GAS ? wanted : MAX_FEE_PER_GAS;
  if (baseFeePerGas + maxPriorityFeePerGas > maxFeePerGas) return undefined;
  return { maxFeePerGas, maxPriorityFeePerGas };
}

type Fields = Record<string, string | number | boolean>;

function refusal(status: number, reason: string, fields: Fields = {}, headers: Record<string, string> = {}): Response {
  logEvent("relay_refused", { reason, status, ...fields });
  return refuse(status, reason, headers);
}

/** Counts one request under `key` in shared state. Fails closed: a store error counts as over. */
async function under(ctx: RelayContext, key: string, max: number, windowSeconds: number): Promise<boolean> {
  try {
    return (await ctx.store.incrWindow(key, windowSeconds)) <= max;
  } catch {
    return false;
  }
}

/** The 20 bytes as lowercase hex, so one account always counts under one key whatever form named it. */
const accountKey = (account: string): string => bytesToHex(accountBytes(account));

async function readBody(request: Request): Promise<{ body: RelayBody } | { response: Response }> {
  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") return { response: refusal(415, "json_only") };
  const stated = declaredLength(request);
  if (stated !== undefined && stated > RELAY_BODY_CAP) return { response: refusal(413, "body_too_large") };
  if (request.body === null) return { response: refusal(400, "bad_body") };
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await readCapped(request.body, RELAY_BODY_CAP)));
  } catch (error) {
    return { response: error instanceof TooLarge ? refusal(413, "body_too_large") : refusal(400, "bad_body") };
  }
  const checked = relayBody.safeParse(parsed);
  if (!checked.success) {
    // Paths name our own schema's fields, never a value or a key the caller chose.
    const field = (checked.error.issues[0]?.path ?? []).map(String).join(".").slice(0, 64);
    return { response: refusal(400, "bad_body", { field }) };
  }
  return { body: checked.data };
}

/** The board's current chair, read with getBoard at the latest block, or the registry's refusal. */
async function chairOf(ctx: RelayContext, boardId: bigint, deadline: Deadline): Promise<{ chair: Hex } | { refused: string } | undefined> {
  const data = encodeFunctionData({ abi: boardRegistryAbi, functionName: "getBoard", args: [boardId] });
  try {
    const outcome = await within(deadline, ctx.chain.call({ from: ctx.relayer.evm, to: REGISTRY_ADDRESS, data }), "reading the board");
    if (!outcome.ok) return { refused: revertName(outcome.revertData) };
    return { chair: decodeFunctionResult({ abi: boardRegistryAbi, functionName: "getBoard", data: outcome.data }).chair };
  } catch {
    return undefined;
  }
}

const lateRefusal = (fields: Fields): Response => refusal(503, "out_of_time", fields, { "retry-after": "30" });

/**
 * The exact transaction's eth_call, run before anything but the IP is counted (threat model C40).
 * The registry checks the chair's signature, so only an action that passes here may count against
 * a chair, a board or the total. A revert counts against the rejected total alone and answers 422
 * with the registry's error name, or 429 once that total is spent.
 *
 * @returns undefined when the call passed, otherwise the refusal to send.
 */
async function preflight(ctx: RelayContext, built: Built, limits: RelayLimits, fields: Fields, deadline: Deadline): Promise<Response | undefined> {
  let outcome: CallOutcome;
  try {
    outcome = await within(deadline, ctx.chain.call({ from: ctx.relayer.evm, to: REGISTRY_ADDRESS, data: built.data }), "the pre-flight call");
  } catch (error) {
    return error instanceof OutOfTime ? lateRefusal(fields) : refusal(502, "chain_unreachable", fields);
  }
  if (outcome.ok) return undefined;
  if (!(await under(ctx, REJECTED_KEY, limits.rejected, limits.windowSeconds))) {
    return refusal(429, "rate_limited", { ...fields, limit: "rejected" }, { "retry-after": String(limits.windowSeconds) });
  }
  return refusal(422, revertName(outcome.revertData), fields);
}

/** Everything after admission, while holding the send lock: one transaction at a time, so nonces never collide. */
async function relayOnce(ctx: RelayContext, built: Built, fields: Fields, deadline: Deadline): Promise<Response> {
  if (elapsedMs(deadline) > SEND_CUTOFF_MS) return lateRefusal(fields);
  try {
    if (await isHalted(ctx.store, ctx.now)) return refusal(503, "halted", fields);
  } catch {
    return refusal(503, "ledger_unavailable", fields);
  }
  let state: WindowState;
  try {
    state = await ensureWindow({ store: ctx.store, now: ctx.now, relayer: ctx.relayer, chain: ctx.chain, sleep: ctx.sleep, deadline });
  } catch (error) {
    if (error instanceof RelayerHalted) return refusal(503, "halted", fields);
    if (error instanceof DailyCeilingReached) return refusal(503, "daily_ceiling", fields);
    if (error instanceof OutOfTime) return lateRefusal(fields);
    if (error instanceof LockBusy) return refusal(503, "busy", fields, { "retry-after": "30" });
    return refusal(503, "window_unavailable", fields);
  }

  // The contract is the check: the exact transaction must pass eth_call before anything is spent.
  const tx = { from: ctx.relayer.evm, to: REGISTRY_ADDRESS, data: built.data };
  let gas: bigint;
  let quote: FeeQuote;
  try {
    const outcome = await within(deadline, ctx.chain.call(tx), "the pre-flight call");
    if (!outcome.ok) return refusal(422, revertName(outcome.revertData), fields);
    gas = await within(deadline, ctx.chain.estimateGas(tx), "the gas estimate");
    quote = await within(deadline, ctx.chain.feeQuote(), "the fee quote");
  } catch (error) {
    return error instanceof OutOfTime ? lateRefusal(fields) : refusal(502, "chain_unreachable", fields);
  }
  const ceiling = GAS_CEILING[built.action];
  if (gas > ceiling) return refusal(422, "gas_above_ceiling", { ...fields, gas: gas.toString() });
  const fee = feeCaps(quote);
  if (fee === undefined) return refusal(503, "fee_above_ceiling", fields);

  // The worst case, gas limit times fee cap, is what the window charges and what the ledger records.
  const worst = evmWindowCost({ gas: ceiling, maxFeePerGas: fee.maxFeePerGas });
  if (elapsedMs(deadline) > SEND_CUTOFF_MS) return lateRefusal(fields);
  try {
    await reserveSpend(ctx.store, ctx.now, worst, built.action);
  } catch (error) {
    return refusal(503, error instanceof DailyCeilingReached ? "daily_ceiling" : "ledger_unavailable", fields);
  }
  // A send started after the cutoff could outlive the function and the lock.
  if (elapsedMs(deadline) > SEND_CUTOFF_MS) return lateRefusal(fields);
  // The window's own record of our sends, so a later read can tell our spending from anyone else's.
  try {
    await recordWindowSend(ctx.store, state.window.openedHeight, worst);
  } catch {
    return refusal(503, "ledger_unavailable", fields);
  }

  let hash: Hex;
  try {
    hash = await ctx.chain.send({ to: REGISTRY_ADDRESS, data: built.data, gas: ceiling, ...fee }, deadline);
  } catch {
    return refusal(502, "broadcast_failed", fields);
  }
  if (!/^0x[0-9a-f]{64}$/.test(hash)) return refusal(502, "broadcast_failed", fields);
  logEvent("relay_sent", { ...fields, txHash: hash, gas: ceiling.toString(), maxFeePerGas: fee.maxFeePerGas.toString(), worstUqor: worst.toString() });
  return json(202, { txHash: hash });
}

/**
 * Relays one chair-signed board action to the registry from the relayer's own account (threat model
 * C23 to C26, C31, C32, C36, C40).
 *
 * Admission, in order: POST only (405); the per-IP limit, which every request counts against (429);
 * `application/json` (415); at most RELAY_BODY_CAP bytes, refused while reading (413); the body
 * schema, so a malformed address (anything but exact EIP-55), hash, integer or a signature of any
 * other length is refused (400) before any chain call; the eth_call of the exact transaction from
 * the relayer, so the registry checks the signature before any other counter moves (422 with the
 * registry's error name, counted against the rejected total only, 429 once that is spent); then,
 * for an action that passed, the per-board limit, the chair (the create parameter, or getBoard at
 * the latest block, whose revert answers 422 with the registry's error name), the per-chair limit
 * and the valid-action total (429).
 *
 * Then, under the shared lock "relayer:send" (waiting up to 20 s, else 503): the day's halt flag
 * (503 halted after a suspected key leak, until the next UTC day); ensureWindow (503 at the
 * daily ceiling or without a usable window); eth_call of the exact transaction again, because
 * another action may have moved the board's nonce while this one waited (422 on a revert, and
 * nothing is sent); estimateGas (422 above the action's gas ceiling); the fee cap (503 above
 * MAX_FEE_PER_GAS); the worst case recorded against the daily ceiling (503 when it would pass); the
 * same worst case recorded against the window it goes through; one broadcast with the action's
 * ceiling as gas limit.
 *
 * The whole path runs on one clock started when the request arrives: no send starts after
 * SEND_CUTOFF_MS (45 s), no window opens after OPEN_CUTOFF_MS (20 s), and every read ends by
 * RELAY_DEADLINE_MS (55 s), each answered 503 out_of_time, so the path ends inside the function's
 * and the 60 s lock's lifetime.
 *
 * @returns 202 with `{ txHash }` only. A hash is a claim that the transaction was handed to the
 *   node, never that it succeeded: the caller confirms the receipt and the registry event (C26).
 */
export async function handleRelay(request: Request, ctx: RelayContext): Promise<Response> {
  const deadline = startDeadline(RELAY_DEADLINE_MS, ctx.clock);
  if (request.method !== "POST") return refusal(405, "method_not_allowed", {}, { allow: "POST" });
  const limits = ctx.limits ?? RELAY_LIMITS;
  const retry = { "retry-after": String(limits.windowSeconds) };
  const ip = clientKey(ctx.clientIp);
  if (ip === undefined) return refusal(429, "rate_limited", { limit: "bad_client_ip" }, retry);
  if (!(await under(ctx, `rate:relay:ip:${ip}`, limits.perIp, limits.windowSeconds))) return refusal(429, "rate_limited", { ip, limit: "per_ip" }, retry);

  const read = await readBody(request);
  if ("response" in read) return read.response;
  const built = buildCalldata(read.body);
  const fields: Fields = built.boardId === undefined ? { action: built.action } : { action: built.action, boardId: built.boardId.toString() };

  const refused = await preflight(ctx, built, limits, fields, deadline);
  if (refused !== undefined) return refused;

  if (built.boardId !== undefined && !(await under(ctx, `rate:relay:board:${built.boardId}`, limits.perBoard, limits.windowSeconds))) {
    return refusal(429, "rate_limited", { ...fields, limit: "per_board" }, retry);
  }
  let chair = built.chair;
  if (chair === undefined) {
    const found = await chairOf(ctx, built.boardId ?? 0n, deadline);
    if (found === undefined) return refusal(502, "chain_unreachable", fields);
    if ("refused" in found) return refusal(422, found.refused, fields);
    chair = found.chair;
  }
  if (!(await under(ctx, `rate:relay:chair:${accountKey(chair)}`, limits.perChair, limits.windowSeconds))) {
    return refusal(429, "rate_limited", { ...fields, limit: "per_chair" }, retry);
  }
  if (!(await under(ctx, VALID_KEY, limits.total, limits.windowSeconds))) return refusal(429, "rate_limited", { ...fields, limit: "total" }, retry);

  const waitMs = Math.floor(Math.max(0, Math.min(SEND_LOCK_WAIT_MS, SEND_CUTOFF_MS - elapsedMs(deadline))));
  try {
    return await ctx.store.withLock(SEND_LOCK, LOCK_TTL_SECONDS, () => relayOnce(ctx, built, fields, deadline), { waitMs });
  } catch (error) {
    if (error instanceof LockBusy) return refusal(503, "busy", fields, { "retry-after": "30" });
    return refusal(503, "store_unavailable", fields);
  }
}
