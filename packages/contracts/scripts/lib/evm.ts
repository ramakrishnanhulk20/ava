import { evmWindowCost, weiToUqorCeil } from "@qorechain/evm";
import { fetchEvmWindow, getJson, openEvmWindowMsg, withRetry } from "@qorechain/sdk";
import { sameAccount } from "@ava/core";
import { BaseError, ExecutionRevertedError, keccak256, type Hex, type PublicClient, type TransactionReceipt } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { Deployer } from "../account.js";
import { DENOM, EVM_CHAIN_ID, HTTP, REST, UQOR_PER_QOR } from "../env.js";
import { MAX_FEE_UQOR, sendTx } from "../tx.js";

// Each window admits exactly the one EVM transaction it was opened for, for about five minutes
// at 1.4 s blocks, and no more value than that transaction can spend.
const WINDOW_BLOCKS = 200;
const WINDOW_TXS = 1;
// Opening a window moves the account nonce; the EVM side needs a moment to see the new one.
const WAIT_AFTER_WINDOW_MS = 10_000;
const GAS_HEADROOM_PERCENT = 125n;
// The testnet base fee is 100 gwei. A fee cap above this means something is wrong, so stop.
const MAX_FEE_PER_GAS_CEILING = 500_000_000_000n;

/** The deployer never goes below this, counting the worst case of the next spend. */
export const DEPLOYER_FLOOR_UQOR = 500_000n;

export interface EvmFees {
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

export interface OpenedWindow {
  hash: string;
  feeUqor: bigint;
  maxValue: bigint;
}

/** A spend that could leave the deployer under the floor. The message says what this one spend needs. */
export class BudgetError extends Error {
  constructor(
    message: string,
    readonly balanceUqor: bigint,
    readonly maxSpendUqor: bigint,
  ) {
    super(message);
    this.name = "BudgetError";
  }
}

export type CallOutcome = { ok: true; data: Hex } | { ok: false; revertData: Hex | undefined; message: string };

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export function formatQor(uqor: bigint): string {
  const sign = uqor < 0n ? "-" : "";
  const abs = uqor < 0n ? -uqor : uqor;
  const fraction = (abs % UQOR_PER_QOR).toString().padStart(6, "0").replace(/0+$/, "");
  return `${sign}${abs / UQOR_PER_QOR}${fraction === "" ? "" : `.${fraction}`}`;
}

/** The account's uqor balance from the bank module, 0 for an account the chain has never seen. */
export async function balanceOf(address: string): Promise<bigint> {
  const body = await getJson<{ balances?: unknown }>(`${REST}/cosmos/bank/v1beta1/balances/${encodeURIComponent(address)}`, HTTP);
  if (!Array.isArray(body.balances)) throw new Error("Unexpected balance answer: no balances list.");
  const coin = body.balances.find((c: { denom?: unknown }) => c?.denom === DENOM) as { amount?: unknown } | undefined;
  if (coin === undefined) return 0n;
  if (typeof coin.amount !== "string" || !/^\d{1,40}$/.test(coin.amount)) throw new Error("Unexpected balance amount.");
  return BigInt(coin.amount);
}

/** EIP-1559 fees fixed once per transaction, so its window is sized for exactly what it may spend. */
export async function fees(client: PublicClient): Promise<EvmFees> {
  const [block, maxPriorityFeePerGas] = await Promise.all([client.getBlock({ blockTag: "latest" }), client.estimateMaxPriorityFeePerGas()]);
  if (block.baseFeePerGas === null) throw new Error("The latest block carries no base fee.");
  const maxFeePerGas = block.baseFeePerGas * 2n + maxPriorityFeePerGas;
  if (maxFeePerGas > MAX_FEE_PER_GAS_CEILING) throw new Error(`Fee cap ${maxFeePerGas} wei per gas is above the ${MAX_FEE_PER_GAS_CEILING} ceiling. Stopping.`);
  return { maxFeePerGas, maxPriorityFeePerGas };
}

export function withHeadroom(gas: bigint): bigint {
  return (gas * GAS_HEADROOM_PERCENT + 99n) / 100n;
}

/** The window's max_value for one transaction: its gas limit times its fee cap, from evmWindowCost. */
export function windowValueFor(gas: bigint, fee: EvmFees): bigint {
  return evmWindowCost({ gas, maxFeePerGas: fee.maxFeePerGas });
}

/** The most one window plus the transaction it admits can take: the window's own fee cap plus its max_value. */
export function windowSpendCap(maxValue: bigint): bigint {
  return MAX_FEE_UQOR + maxValue;
}

/**
 * Stops before a spend when its worst case could leave the deployer under DEPLOYER_FLOOR_UQOR.
 *
 * @returns The balance read, in uqor.
 * @throws BudgetError naming the amount to send to the deployer.
 */
export async function assertBudget(deployer: Deployer, maxSpendUqor: bigint, what: string): Promise<bigint> {
  const balance = await balanceOf(deployer.qor1);
  const after = balance - maxSpendUqor;
  if (after < DEPLOYER_FLOOR_UQOR) {
    throw new BudgetError(
      `Stopping before ${what}: the deployer holds ${formatQor(balance)} QOR and this may spend up to ${formatQor(maxSpendUqor)} QOR, ` +
        `which could leave it under ${formatQor(DEPLOYER_FLOOR_UQOR)} QOR. This one transaction needs at least ${formatQor(DEPLOYER_FLOOR_UQOR - after)} QOR more at ${deployer.qor1}.`,
      balance,
      maxSpendUqor,
    );
  }
  return balance;
}

/**
 * Opens an EVM window for exactly one transaction, checks the chain stored exactly that scope,
 * then waits before the EVM transaction is signed. An empty target list is an unscoped window,
 * which only a contract creation needs.
 */
export async function openWindow(deployer: Deployer, maxValue: bigint, allowedTargets: Hex[]): Promise<OpenedWindow> {
  const message = openEvmWindowMsg({ sender: deployer.qor1, blocks: WINDOW_BLOCKS, maxTxs: WINDOW_TXS, maxValue, allowedTargets });
  const tx = await sendTx(deployer, "hybrid", [message], "");
  const window = await withRetry(() => fetchEvmWindow({ rest: REST, address: deployer.qor1 }), { retries: 4, backoff: 2_000 });
  const scopeMatches =
    window.allowedTargets.length === allowedTargets.length && window.allowedTargets.every((t, i) => sameAccount(t, allowedTargets[i]!));
  if (!window.found || !window.live || window.nativeOnly || window.remainingTxs !== BigInt(WINDOW_TXS) || window.remainingValue !== maxValue || !scopeMatches) {
    throw new Error(`The window opened in ${tx.hash} is not the one asked for. Stopping before any EVM transaction.`);
  }
  await sleep(WAIT_AFTER_WINDOW_MS);
  return { hash: tx.hash, feeUqor: BigInt(tx.fee.amount[0]!.amount), maxValue };
}

export function describeWindow(w: OpenedWindow, scope: string): string {
  return `${scope}, ${WINDOW_TXS} tx, ${WINDOW_BLOCKS} blocks, max_value ${w.maxValue} uqor from evmWindowCost; opened in ${w.hash} (fee ${formatQor(w.feeUqor)} QOR)`;
}

/**
 * Signs one EVM transaction locally and broadcasts it once. The hash is known before sending, so
 * a dropped connection is answered by looking the hash up, never by sending again.
 */
export async function sendEvm(
  client: PublicClient,
  account: Deployer,
  tx: { to?: Hex; data: Hex; gas: bigint } & EvmFees,
): Promise<{ hash: Hex; receipt: TransactionReceipt }> {
  const signer = privateKeyToAccount(account.privateKey);
  if (!sameAccount(signer.address, account.qor1)) throw new Error("The EVM signing key is not this account's key.");
  const nonce = await client.getTransactionCount({ address: account.evm, blockTag: "pending" });
  const serialized = await signer.signTransaction({ type: "eip1559", chainId: EVM_CHAIN_ID, nonce, value: 0n, ...tx });
  const hash = keccak256(serialized);
  try {
    await client.sendRawTransaction({ serializedTransaction: serialized });
  } catch (err) {
    const reason = err instanceof Error ? err.message.split("\n")[0]!.slice(0, 200) : "unknown error";
    console.log(`  broadcast of ${hash} did not confirm (${reason}); looking it up on chain.`);
    // A refusal means the node never took it; a lost answer means it may still be pending.
    const seen = await withRetry(() => client.getTransaction({ hash }), { retries: 5, backoff: 2_000 }).catch(() => undefined);
    if (seen === undefined) throw new Error(`EVM transaction ${hash} was refused and is not on chain: ${reason}`);
  }
  const receipt = await client.waitForTransactionReceipt({ hash, timeout: 90_000, pollingInterval: 2_000 });
  return { hash, receipt };
}

/** What the chain kept for an EVM transaction: gas used times the price it paid, in uqor rounded up. */
export function evmFeeUqor(receipt: TransactionReceipt): bigint {
  return weiToUqorCeil(receipt.gasUsed * receipt.effectiveGasPrice);
}

/**
 * eth_call of one exact transaction. A revert comes back as an outcome with its raw revert data;
 * anything else (a network failure, a node error) is thrown, so a refusal is never inferred from
 * a call that did not run.
 */
export async function ethCall(client: PublicClient, req: { from: Hex; to: Hex; data?: Hex; value?: bigint }): Promise<CallOutcome> {
  try {
    const { data } = await client.call({ account: req.from, to: req.to, data: req.data, value: req.value });
    return { ok: true, data: data ?? "0x" };
  } catch (err) {
    if (!(err instanceof BaseError)) throw err;
    const reverted = err.walk((e) => e instanceof ExecutionRevertedError);
    if (reverted === null) throw err;
    // The same place viem itself reads revert data from: the innermost error, as a string or under .data.
    const inner = err.walk() as { data?: unknown } | null;
    const raw = typeof inner?.data === "object" && inner.data !== null ? (inner.data as { data?: unknown }).data : inner?.data;
    const revertData = typeof raw === "string" && /^0x([0-9a-fA-F]{2})*$/.test(raw) ? (raw as Hex) : undefined;
    return { ok: false, revertData, message: (reverted as BaseError).shortMessage };
  }
}
