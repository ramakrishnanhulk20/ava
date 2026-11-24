import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getJson } from "@qorechain/sdk";
import { deriveDrillAccount, type DrillAccount } from "./account.js";
import { assertTestnet } from "./chain.js";
import { DENOM, HTTP, REST, UQOR_PER_QOR, requireMnemonic } from "./env.js";

export interface DrillStatus {
  chainId: string;
  balanceUqor: bigint;
  /** `matchesOurKey` is undefined when the chain's answer carries no readable key. */
  pq: { found: boolean; possessionProven?: boolean; matchesOurKey?: boolean };
  kem: { found: boolean; matchesOurKey?: boolean };
  window: {
    found: boolean;
    live: boolean;
    remainingBlocks: bigint;
    remainingTxs: bigint;
    remainingValue: bigint;
    nativeOnly: boolean;
    allowedTargets: string[];
  };
}

type Json = Record<string, unknown>;

function asObject(value: unknown, where: string): Json {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Unexpected answer from ${where}: not a JSON object.`);
  }
  return value as Json;
}

/** An answer without a boolean `found` is unknown, never "not found". */
function requireFound(body: Json, where: string): boolean {
  if (typeof body.found !== "boolean") {
    throw new Error(`Unexpected answer from ${where}: no boolean "found" field. Treating the state as unknown.`);
  }
  return body.found;
}

function uint(value: unknown, where: string): bigint {
  const text = typeof value === "number" ? String(value) : value;
  if (typeof text !== "string" || !/^\d{1,40}$/.test(text)) {
    throw new Error(`Unexpected number from ${where}.`);
  }
  return BigInt(text);
}

function sameKey(base64: unknown, ours: Uint8Array): boolean | undefined {
  if (typeof base64 !== "string" || base64.length === 0) return undefined;
  return Buffer.from(base64, "base64").equals(Buffer.from(ours));
}

export function formatQor(uqor: bigint): string {
  const whole = uqor / UQOR_PER_QOR;
  const fraction = (uqor % UQOR_PER_QOR).toString().padStart(6, "0").replace(/0+$/, "");
  return fraction === "" ? whole.toString() : `${whole}.${fraction}`;
}

/**
 * Reads the drill account's balance, ML-DSA-87 key, KEM key and EVM window
 * from the testnet REST API. Fails closed: any answer it cannot parse throws
 * instead of being read as "absent".
 */
export async function readStatus(account: DrillAccount): Promise<DrillStatus> {
  const chainId = await assertTestnet();
  const address = encodeURIComponent(account.qor1);

  const balanceRoute = `/cosmos/bank/v1beta1/balances/${address}`;
  const pqRoute = `/qorechain/pqc/v1/account/${address}`;
  const kemRoute = `/qorechain/pqc/v1/kem/${address}`;
  const windowRoute = `/qorechain/pqc/v1/evm_window/${address}`;

  const [balanceBody, pqBody, kemBody, windowBody] = await Promise.all(
    [balanceRoute, pqRoute, kemRoute, windowRoute].map(async (route) => asObject(await getJson<unknown>(`${REST}${route}`, HTTP), route)),
  );

  const balances = balanceBody!.balances;
  if (!Array.isArray(balances)) throw new Error(`Unexpected answer from ${balanceRoute}: no balances list.`);
  const coin = balances.map((c) => asObject(c, balanceRoute)).find((c) => c.denom === DENOM);
  const balanceUqor = coin === undefined ? 0n : uint(coin.amount, balanceRoute);

  const pqFound = requireFound(pqBody!, pqRoute);
  const pqAccount = pqFound ? asObject(pqBody!.account, pqRoute) : undefined;
  const pq: DrillStatus["pq"] = { found: pqFound };
  if (pqAccount !== undefined) {
    if (typeof pqAccount.possession_proven === "boolean") pq.possessionProven = pqAccount.possession_proven;
    const match = sameKey(pqAccount.public_key, account.pqc.publicKey);
    if (match !== undefined) pq.matchesOurKey = match;
  }

  const kemFound = requireFound(kemBody!, kemRoute);
  const kem: DrillStatus["kem"] = { found: kemFound };
  if (kemFound) {
    const match = sameKey(asObject(kemBody!.key, kemRoute).public_key, account.seal.mlkemPublicKey);
    if (match !== undefined) kem.matchesOurKey = match;
  }

  const windowFound = requireFound(windowBody!, windowRoute);
  const targets = windowBody!.allowed_targets;
  const window: DrillStatus["window"] = {
    found: windowFound,
    live: windowFound && windowBody!.live === true,
    remainingBlocks: windowFound ? uint(windowBody!.remaining_blocks ?? "0", windowRoute) : 0n,
    remainingTxs: windowFound ? uint(windowBody!.remaining_txs ?? "0", windowRoute) : 0n,
    remainingValue: windowFound ? uint(windowBody!.remaining_value ?? "0", windowRoute) : 0n,
    nativeOnly: windowFound && windowBody!.native_only === true,
    allowedTargets: Array.isArray(targets) ? targets.filter((t): t is string => typeof t === "string" && /^0x[0-9a-fA-F]{40}$/.test(t)) : [],
  };

  return { chainId, balanceUqor, pq, kem, window };
}

function yesNo(value: boolean | undefined): string {
  return value === undefined ? "not readable" : value ? "yes" : "NO";
}

export function printStatus(account: DrillAccount, s: DrillStatus): void {
  console.log(`chain id:    ${s.chainId} confirmed`);
  console.log(`qor1:        ${account.qor1}`);
  console.log(`0x:          ${account.evm}`);
  console.log(`balance:     ${s.balanceUqor} uqor (${formatQor(s.balanceUqor)} QOR)`);
  console.log(
    s.pq.found
      ? `PQ key:      found:true possession_proven:${s.pq.possessionProven ?? "not readable"} this account's ML-DSA-87 key:${yesNo(s.pq.matchesOurKey)}`
      : "PQ key:      found:false",
  );
  console.log(s.kem.found ? `KEM key:     found:true this account's QoreSeal key:${yesNo(s.kem.matchesOurKey)}` : "KEM key:     found:false");
  if (!s.window.found) {
    console.log("EVM window:  none");
  } else {
    const scope = s.window.nativeOnly ? "native_only" : s.window.allowedTargets.length > 0 ? `targets ${s.window.allowedTargets.join(",")}` : "unscoped";
    console.log(
      `EVM window:  ${s.window.live ? "live" : "not usable"}; ${s.window.remainingBlocks} blocks, ${s.window.remainingTxs} txs, ${s.window.remainingValue} uqor left; ${scope}`,
    );
  }
}

async function main(): Promise<void> {
  const account = await deriveDrillAccount(requireMnemonic());
  printStatus(account, await readStatus(account));
}

const entry = process.argv[1];
if (entry !== undefined && resolve(entry).toLowerCase() === resolve(fileURLToPath(import.meta.url)).toLowerCase()) {
  main().catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}
