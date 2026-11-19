import { evmWindowCost, weiToUqorCeil, type EvmWindow } from "@qorechain/evm";
import { EthNativeSigner, clearPqcStatusCache, fetchPqcStatus, type PqcStatus } from "@qorechain/sdk";
import {
  BaseError,
  ExecutionRevertedError,
  createPublicClient,
  decodeAbiParameters,
  decodeErrorResult,
  defineChain,
  encodeFunctionData,
  hexToBytes,
  http,
  keccak256,
  parseEventLogs,
  type Hex,
  type PublicClient,
  type TransactionReceipt,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { boardRegistryAbi } from "../../packages/server/src/abi/boardRegistry.ts";
import { startDeadline } from "../../packages/server/src/chain/deadline.ts";
import { accountSequence, balanceOf, closeWindowTx, openWindowTx, readEvmWindow, sendNative, type CommittedTx, type Fee, type Messages } from "../../packages/server/src/chain/native.ts";
import {
  DENOM,
  MAX_FEE_PER_GAS,
  MAX_GAS_CEILING,
  MAX_NATIVE_FEE_UQOR,
  MIN_GAS_PRICE_MILLI_UQOR,
  WAIT_AFTER_WINDOW_MS,
  WINDOW_CLOSE_FEE,
  WINDOW_OPEN_FEE,
} from "../../packages/server/src/config.ts";
import { isRegistryOnly } from "../../packages/server/src/window.ts";
import { COSMOS_CHAIN_ID, EVM_CHAIN_ID, EVM_RPC, REGISTRY, REST, assertContract } from "./guard.ts";
import type { Person } from "./identities.ts";

export { accountSequence, balanceOf, readEvmWindow, type CommittedTx, type EvmWindow, type Fee, type Messages };

const NATIVE_BUDGET_MS = 120_000;
const GAS_ADJUSTMENT_PERCENT = 130n;
// The SDK's own client prices at 0.15 uqor per gas, above the chain's 0.1 floor.
const GAS_PRICE_MILLI_UQOR = 150n;
const GAS_HEADROOM_PERCENT = 125n;
const PQC_STATUS = "0x0000000000000000000000000000000000000a02";
/** The precompile's answer is at least four words; an inactive one answers success with nothing. */
const MIN_STATUS_BYTES = 160;

export const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const ceilDiv = (a: bigint, b: bigint): bigint => (a + b - 1n) / b;

export const qoreTestnet = defineChain({
  id: EVM_CHAIN_ID,
  name: "QoreChain testnet",
  nativeCurrency: { name: "QOR", symbol: "QOR", decimals: 18 },
  rpcUrls: { default: { http: [EVM_RPC] } },
});

export function evmClient(): PublicClient {
  return createPublicClient({ chain: qoreTestnet, transport: http(EVM_RPC, { retryCount: 3, retryDelay: 1_500, timeout: 20_000 }) });
}

export const formatQor = (uqor: bigint): string => {
  const sign = uqor < 0n ? "-" : "";
  const abs = uqor < 0n ? -uqor : uqor;
  const fraction = (abs % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  return `${sign}${abs / 1_000_000n}${fraction === "" ? "" : `.${fraction}`}`;
};

/**
 * Prices a native transaction the way packages/contracts/scripts/tx.ts does: simulated gas times
 * 1.3, at 0.15 uqor per gas, refused under the chain's floor or above the server's native fee cap.
 */
export async function simulatedFee(person: Person, mode: "classical" | "hybrid", messages: Messages): Promise<Fee> {
  const auth = await accountSequence(person.qor1);
  if (auth === undefined) throw new Error(`${person.role} (${person.qor1}) does not exist on chain yet: fund it first.`);
  const signer = new EthNativeSigner(person.unified, { signMode: mode, rest: REST });
  const signBytesVersion = mode === "hybrid" ? await signer.resolveSignBytesVersion(COSMOS_CHAIN_ID) : undefined;
  const { txRawBytes } = signer.sign({ chainId: COSMOS_CHAIN_ID, accountNumber: auth.accountNumber, sequence: auth.sequence, messages, memo: "", fee: { amount: [], gas: "0" }, signBytesVersion });
  const response = await globalThis.fetch(`${REST}/cosmos/tx/v1beta1/simulate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tx_bytes: Buffer.from(txRawBytes).toString("base64") }),
    signal: AbortSignal.timeout(20_000),
  });
  const body = (await response.json().catch(() => ({}))) as { gas_info?: { gas_used?: unknown } };
  const used = body.gas_info?.gas_used;
  if (!response.ok || typeof used !== "string" || !/^\d{1,12}$/.test(used)) throw new Error(`Simulation of ${person.role}'s transaction failed (HTTP ${response.status}). Nothing was sent.`);
  const gas = ceilDiv(BigInt(used) * GAS_ADJUSTMENT_PERCENT, 100n);
  const amount = ceilDiv(gas * GAS_PRICE_MILLI_UQOR, 1000n);
  if (amount < ceilDiv(gas * MIN_GAS_PRICE_MILLI_UQOR, 1000n) || amount > MAX_NATIVE_FEE_UQOR) throw new Error(`A simulated fee of ${amount} uqor is outside the bounds. Nothing was sent.`);
  return { amount: [{ denom: DENOM, amount: amount.toString() }], gas: gas.toString() };
}

/**
 * Sends one native transaction signed by a person this suite controls, through the server's own
 * sendNative (one broadcast, looked up by hash, never resent). The fee is simulated unless given.
 */
export async function nativeTx(person: Person, mode: "classical" | "hybrid", messages: Messages, fee?: Fee): Promise<CommittedTx> {
  const finalFee = fee ?? (await simulatedFee(person, mode, messages));
  return sendNative(person, mode, messages, finalFee, startDeadline(NATIVE_BUDGET_MS));
}

export const feeOf = (tx: CommittedTx): bigint => BigInt(tx.fee.amount[0]?.amount ?? "0");

/** The REST view of the account's post-quantum key, never cached. */
export async function pqcStatus(qor1: string): Promise<PqcStatus> {
  clearPqcStatusCache();
  return fetchPqcStatus({ rest: REST, address: qor1 });
}

export interface KeyStatus {
  registered: boolean;
  algorithmId: number;
  pubkey: Uint8Array;
  possessionProven: boolean;
}

const STATUS_ABI = [
  {
    type: "function",
    name: "pqcKeyStatus",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [
      { name: "registered", type: "bool" },
      { name: "algorithmId", type: "uint8" },
      { name: "pubkey", type: "bytes" },
      { name: "possessionProven", type: "bool" },
    ],
  },
] as const;

/** What the registry itself reads: the pqcKeyStatus precompile with all four values. Throws on empty or short data. */
export async function readKeyStatus(client: PublicClient, account: Hex): Promise<KeyStatus> {
  const { data } = await client.call({ to: PQC_STATUS, data: encodeFunctionData({ abi: STATUS_ABI, functionName: "pqcKeyStatus", args: [account] }) });
  if (data === undefined || (data.length - 2) / 2 < MIN_STATUS_BYTES) throw new Error("pqcKeyStatus answered with empty or short data.");
  const [registered, algorithmId, pubkey, possessionProven] = decodeAbiParameters(STATUS_ABI[0].outputs, data);
  return { registered, algorithmId, pubkey: hexToBytes(pubkey), possessionProven };
}

export type CallOutcome = { ok: true; data: Hex } | { ok: false; revertData: Hex | undefined; message: string };

/**
 * eth_call of one exact transaction at the latest block, to one of our two contracts only. A revert
 * comes back as an outcome with its raw revert data; anything else is thrown, so a refusal is never
 * inferred from a call that did not run.
 */
export async function ethCall(client: PublicClient, req: { from: Hex; to: Hex; data: Hex; value?: bigint }): Promise<CallOutcome> {
  assertContract(req.to);
  try {
    const { data } = await client.call({ account: req.from, to: req.to, data: req.data, value: req.value ?? 0n, blockTag: "latest" });
    return { ok: true, data: data ?? "0x" };
  } catch (err) {
    if (!(err instanceof BaseError)) throw err;
    const reverted = err.walk((e) => e instanceof ExecutionRevertedError);
    if (reverted === null) throw err;
    const inner = err.walk() as { data?: unknown } | null;
    const raw = typeof inner?.data === "object" && inner.data !== null ? (inner.data as { data?: unknown }).data : inner?.data;
    const revertData = typeof raw === "string" && /^0x([0-9a-fA-F]{2})*$/.test(raw) ? (raw as Hex) : undefined;
    return { ok: false, revertData, message: (reverted as BaseError).shortMessage };
  }
}

/** A refusal in readable form: the registry's error name with its arguments, or "" for a revert carrying no data. */
export function refusalOf(outcome: CallOutcome): { name: string; text: string } {
  if (outcome.ok) return { name: "PASSED", text: "the call passed" };
  if (outcome.revertData === undefined || outcome.revertData === "0x") return { name: "", text: "reverted with no error data" };
  try {
    const { errorName, args } = decodeErrorResult({ abi: boardRegistryAbi, data: outcome.revertData });
    return { name: errorName, text: `${errorName}(${(args ?? []).map(String).join(", ")})` };
  } catch {
    return { name: "", text: `reverted with data ${outcome.revertData.slice(0, 74)} that is none of the registry's errors` };
  }
}

/** The registry's events in a receipt, emitted by the registry itself. */
export function registryEvents(receipt: TransactionReceipt): { eventName: string; args: Record<string, unknown> }[] {
  return parseEventLogs({ abi: boardRegistryAbi, logs: receipt.logs })
    .filter((l) => l.address.toLowerCase() === REGISTRY.toLowerCase())
    .map((l) => ({ eventName: String(l.eventName), args: (l.args ?? {}) as Record<string, unknown> }));
}

/** What the chain kept for an EVM transaction, in uqor rounded up. */
export const evmFeeUqor = (receipt: TransactionReceipt): bigint => weiToUqorCeil(receipt.gasUsed * receipt.effectiveGasPrice);

/** EIP-1559 fees for one send: twice the base fee plus the tip, held at the server's own fee ceiling. */
export async function feeCaps(client: PublicClient): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }> {
  const [block, maxPriorityFeePerGas] = await Promise.all([client.getBlock({ blockTag: "latest" }), client.estimateMaxPriorityFeePerGas()]);
  if (block.baseFeePerGas === null) throw new Error("The latest block carries no base fee.");
  const wanted = block.baseFeePerGas * 2n + maxPriorityFeePerGas;
  const maxFeePerGas = wanted < MAX_FEE_PER_GAS ? wanted : MAX_FEE_PER_GAS;
  if (block.baseFeePerGas + maxPriorityFeePerGas > maxFeePerGas) throw new Error("The base fee is above the fee ceiling. Stopping.");
  return { maxFeePerGas, maxPriorityFeePerGas };
}

/** The most one wallet transaction can take from its window: the largest gas ceiling at the highest fee cap. */
export const WORST_TX_UQOR = evmWindowCost({ gas: MAX_GAS_CEILING, maxFeePerGas: MAX_FEE_PER_GAS });
const WINDOW_BLOCKS = 3_000;
const WINDOW_MAX_TXS = 40;

export interface Sent {
  hash: Hex;
  receipt: TransactionReceipt;
  feeUqor: bigint;
}

/**
 * The security wallet's own EVM lane: board actions it sends itself, as any account may, through a
 * window it opens scoped to the registry alone. Only the wallet signs here. Opens and closes are
 * counted so the run can report what they cost.
 */
export class WalletLane {
  readonly opened: { hash: string; feeUqor: bigint }[] = [];
  readonly closed: { hash: string; feeUqor: bigint }[] = [];
  readonly client: PublicClient;
  readonly wallet: Person;
  readonly log: (line: string) => void;

  constructor(client: PublicClient, wallet: Person, log: (line: string) => void) {
    this.client = client;
    this.wallet = wallet;
    this.log = log;
  }

  /**
   * Makes sure a live window scoped to the registry alone admits at least `txs` more worst-case
   * transactions. A window of any other scope is closed first. The read-back must be exactly what
   * was asked for, or the window is closed and this throws.
   */
  async ensureWindow(txs: number): Promise<void> {
    const current = await readEvmWindow(this.wallet.qor1);
    const fits = current.found && current.live && isRegistryOnly(current) && current.remainingTxs >= BigInt(txs) && current.remainingValue >= BigInt(txs) * WORST_TX_UQOR && current.remainingBlocks > 300n;
    if (fits) return;
    if (current.found && current.live && !isRegistryOnly(current)) await this.close();
    const maxTxs = Math.min(WINDOW_MAX_TXS, Math.max(txs, 12));
    const request = { blocks: WINDOW_BLOCKS, maxTxs, maxValue: BigInt(maxTxs) * WORST_TX_UQOR, allowedTargets: [REGISTRY] as const };
    const tx = await openWindowTx(this.wallet, { ...request, allowedTargets: [...request.allowedTargets] }, WINDOW_OPEN_FEE, startDeadline(NATIVE_BUDGET_MS));
    this.opened.push({ hash: tx.hash, feeUqor: feeOf(tx) });
    const back = await readEvmWindow(this.wallet.qor1);
    if (!back.found || !back.live || !isRegistryOnly(back) || back.maxTxs !== BigInt(maxTxs) || back.maxValue !== request.maxValue) {
      await this.close();
      throw new Error(`The window opened in ${tx.hash} is not the one asked for. Closed it; nothing was sent through it.`);
    }
    this.log(`  window:   the wallet's own, allowed_targets [${REGISTRY}], ${maxTxs} txs, ${WINDOW_BLOCKS} blocks, opened in ${tx.hash}`);
    await sleep(WAIT_AFTER_WINDOW_MS);
  }

  /** Closes the wallet's window when one is live. Returns the close's hash, or undefined when there was none. */
  async close(): Promise<string | undefined> {
    const current = await readEvmWindow(this.wallet.qor1);
    if (!current.found || !current.live) return undefined;
    const tx = await closeWindowTx(this.wallet, WINDOW_CLOSE_FEE, startDeadline(NATIVE_BUDGET_MS));
    this.closed.push({ hash: tx.hash, feeUqor: feeOf(tx) });
    return tx.hash;
  }

  /** Signs one transaction to one of our two contracts with the wallet's key and broadcasts it once. The hash is known before sending. */
  async broadcast(to: Hex, data: Hex, gas: bigint, nonce: number, fee: { maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }): Promise<Hex> {
    assertContract(to);
    const signer = privateKeyToAccount(this.wallet.privateKey);
    const serialized = await signer.signTransaction({ type: "eip1559", chainId: EVM_CHAIN_ID, nonce, to, data, gas, value: 0n, ...fee });
    const hash = keccak256(serialized);
    try {
      await this.client.sendRawTransaction({ serializedTransaction: serialized });
    } catch {
      // A refusal means the node never took it; a lost answer means it may still be pending.
      const seen = await this.client.getTransaction({ hash }).catch(() => undefined);
      if (seen === undefined) throw new Error(`EVM transaction ${hash} was refused and is not on chain.`);
    }
    return hash;
  }

  async receipt(hash: Hex): Promise<Sent> {
    const receipt = await this.client.waitForTransactionReceipt({ hash, timeout: 120_000, pollingInterval: 2_000 });
    return { hash, receipt, feeUqor: evmFeeUqor(receipt) };
  }

  /**
   * One registry write from the wallet. The exact transaction must pass eth_call first; a refusal
   * there is thrown, because a write is only sent when its effect is the point. Gas is estimated
   * with 25 percent headroom and capped at the server's largest ceiling.
   */
  async write(data: Hex): Promise<Sent> {
    const pre = await ethCall(this.client, { from: this.wallet.evm, to: REGISTRY, data });
    if (!pre.ok) throw new Error(`The wallet's write was refused at pre-flight: ${refusalOf(pre).text}. Nothing was sent.`);
    const estimated = await this.client.estimateGas({ account: this.wallet.evm, to: REGISTRY, data });
    const gas = ceilDiv(estimated * GAS_HEADROOM_PERCENT, 100n);
    if (gas > MAX_GAS_CEILING) throw new Error(`The write needs ${gas} gas, above the ${MAX_GAS_CEILING} ceiling. Nothing was sent.`);
    await this.ensureWindow(1);
    const fee = await feeCaps(this.client);
    const nonce = await this.client.getTransactionCount({ address: this.wallet.evm, blockTag: "pending" });
    const sent = await this.receipt(await this.broadcast(REGISTRY, data, gas, nonce, fee));
    if (sent.receipt.status !== "success") throw new Error(`The wallet's write ${sent.hash} reverted on chain.`);
    return sent;
  }

  /**
   * Two writes signed from the same view of the board and broadcast back to back, with consecutive
   * nonces and a fixed gas limit, so neither is estimated against the other's result (C17).
   */
  async writePair(first: Hex, second: Hex, gas: bigint): Promise<[Sent, Sent]> {
    await this.ensureWindow(2);
    const fee = await feeCaps(this.client);
    const nonce = await this.client.getTransactionCount({ address: this.wallet.evm, blockTag: "pending" });
    const a = await this.broadcast(REGISTRY, first, gas, nonce, fee);
    const b = await this.broadcast(REGISTRY, second, gas, nonce + 1, fee);
    return [await this.receipt(a), await this.receipt(b)];
  }
}

export { isRegistryOnly };
