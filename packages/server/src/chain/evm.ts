import { sameAccount } from "@ava/core";
import {
  BaseError,
  ExecutionRevertedError,
  TransactionNotFoundError,
  TransactionReceiptNotFoundError,
  createPublicClient,
  defineChain,
  http,
  keccak256,
  type Hex,
  type PublicClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { EVM_CHAIN_ID, EVM_RPC, HTTP } from "../config.ts";
import { logEvent } from "../log.ts";
import type { RelayerAccount } from "./account.ts";
import { leftMs, pause, within, type Deadline } from "./deadline.ts";

export const qoreTestnet = defineChain({
  id: EVM_CHAIN_ID,
  name: "QoreChain testnet",
  nativeCurrency: { name: "QOR", symbol: "QOR", decimals: 18 },
  rpcUrls: { default: { http: [EVM_RPC] } },
});

/**
 * The public EVM JSON-RPC with a 4 s timeout on every call. Reads retry once after a pause; the
 * send client passes `retries: 0`, so a send step is one 4 s nonce read and one 4 s broadcast.
 */
export function evmClient(options: { retries?: number } = {}): PublicClient {
  return createPublicClient({
    chain: qoreTestnet,
    transport: http(EVM_RPC, { retryCount: options.retries ?? HTTP.retries, retryDelay: HTTP.retryDelayMs, timeout: HTTP.timeoutMs }),
  });
}

/** An eth_call that ran: it returned, or it reverted with this raw revert data (if any). */
export type CallOutcome = { ok: true; data: Hex } | { ok: false; revertData: Hex | undefined };

export interface TxRequest {
  from: Hex;
  to: Hex;
  data: Hex;
}

export interface FeeQuote {
  baseFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

export interface EvmSend {
  to: Hex;
  data: Hex;
  gas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}

/** What a receipt says one transaction cost: the gas it used and the price per gas it paid, in wei. */
export interface ReceiptFee {
  gasUsed: bigint;
  effectiveGasPrice: bigint;
}

/** Blocks are about 1.4 s, so a receipt is looked for about once a block. */
const RECEIPT_POLL_MS = 1_000;

/**
 * eth_call of one exact transaction at the latest block. A revert comes back as an outcome with its
 * raw revert data; anything else (a network failure, a node error) is thrown, so a refusal is never
 * inferred from a call that did not run.
 */
export async function ethCall(client: PublicClient, req: TxRequest): Promise<CallOutcome> {
  try {
    const { data } = await client.call({ account: req.from, to: req.to, data: req.data, value: 0n, blockTag: "latest" });
    return { ok: true, data: data ?? "0x" };
  } catch (err) {
    if (!(err instanceof BaseError)) throw err;
    if (err.walk((e) => e instanceof ExecutionRevertedError) === null) throw err;
    // The same place viem itself reads revert data from: the innermost error, as a string or under .data.
    const inner = err.walk() as { data?: unknown } | null;
    const raw = typeof inner?.data === "object" && inner.data !== null ? (inner.data as { data?: unknown }).data : inner?.data;
    return { ok: false, revertData: typeof raw === "string" && /^0x([0-9a-fA-F]{2})*$/.test(raw) ? (raw as Hex) : undefined };
  }
}

export async function estimateGas(client: PublicClient, req: TxRequest): Promise<bigint> {
  return client.estimateGas({ account: req.from, to: req.to, data: req.data, value: 0n });
}

/** The latest block's base fee and the node's suggested tip. The caller decides the fee cap. */
export async function feeQuote(client: PublicClient): Promise<FeeQuote> {
  const [block, maxPriorityFeePerGas] = await Promise.all([client.getBlock({ blockTag: "latest" }), client.estimateMaxPriorityFeePerGas()]);
  if (block.baseFeePerGas === null) throw new Error("The latest block carries no base fee.");
  return { baseFeePerGas: block.baseFeePerGas, maxPriorityFeePerGas };
}

/** The account's next EVM nonce, counting what is already waiting in the mempool. */
export async function pendingNonce(client: PublicClient, address: Hex): Promise<number> {
  return client.getTransactionCount({ address, blockTag: "pending" });
}

/** A send that stopped before anything was handed to the node: no transaction exists and no nonce was used. */
export class NotBroadcast extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotBroadcast";
  }
}

/**
 * One transaction the relayer signed, as known from its signed bytes before any broadcast: its lane,
 * the account nonce (EVM) or sequence (native) it carries, and its hash. EVM hashes are 0x and
 * lowercase; native hashes are 64 uppercase hex digits, as the chain's REST names them.
 */
export interface SignedTx {
  kind: "evm" | "native";
  nonce: bigint;
  hash: string;
}

/**
 * Runs after signing and before the broadcast. When it throws, the transaction is never handed to
 * the node and the send throws NotBroadcast.
 */
export type BeforeBroadcast = (signed: SignedTx) => Promise<void>;

/**
 * Where one of the relayer's own transactions stands: in a block ("landed", or "reverted" when its
 * receipt says it reverted), waiting in a node's pool, or unknown to the chain. Both "landed" and
 * "reverted" used the account's nonce; only "landed" can have changed the registry. "landed" also
 * covers a transaction in a block whose receipt was not there to read, so it is never a guess at
 * success. Native transactions answer "landed" whatever their result code.
 */
export type TxStatus = "landed" | "reverted" | "pending" | "unknown";

/**
 * Signs one EIP-1559 transaction locally with the relayer's secp256k1 key (value 0, chain id 9800,
 * the pending nonce) and broadcasts it once. The hash is known before sending, so a lost answer is
 * met by looking the hash up until the deadline, never by sending again. Does not wait for the receipt.
 *
 * @param beforeBroadcast Given the nonce and hash once signed, before the broadcast (threat model
 *   C24). If it throws, nothing is sent.
 * @returns The transaction hash, once the node has taken it.
 * @throws NotBroadcast when the key is not the relayer's, the nonce read or the signing failed, or
 *   beforeBroadcast threw, so nothing was sent. An Error when the node refused the transaction and
 *   it is not seen before the deadline: it was handed over, so it may still land.
 */
export async function sendEvm(client: PublicClient, account: RelayerAccount, tx: EvmSend, deadline: Deadline, beforeBroadcast?: BeforeBroadcast): Promise<Hex> {
  const signer = privateKeyToAccount(account.privateKey);
  if (!sameAccount(signer.address, account.evm)) throw new NotBroadcast("The EVM signing key is not the relayer's key.");
  let serialized: Hex;
  let nonce: number;
  try {
    nonce = await pendingNonce(client, account.evm);
    serialized = await signer.signTransaction({ type: "eip1559", chainId: EVM_CHAIN_ID, nonce, value: 0n, ...tx });
  } catch {
    throw new NotBroadcast("The EVM transaction could not be prepared: nothing was sent.");
  }
  const hash = keccak256(serialized);
  try {
    await beforeBroadcast?.({ kind: "evm", nonce: BigInt(nonce), hash });
  } catch {
    throw new NotBroadcast("The EVM transaction could not be recorded before its broadcast: nothing was sent.");
  }
  try {
    await client.sendRawTransaction({ serializedTransaction: serialized });
  } catch {
    // A refusal means the node never took it; a lost answer means it may still be pending.
    logEvent("evm_broadcast_unconfirmed", { hash });
    if (!(await seenBefore(client, hash, deadline))) throw new Error(`EVM transaction ${hash} was refused and is not on chain.`);
  }
  return hash;
}

async function seenBefore(client: PublicClient, hash: Hex, deadline: Deadline): Promise<boolean> {
  while (leftMs(deadline) > 0) {
    const seen = await within(deadline, client.getTransaction({ hash }), "the transaction lookup").catch(() => undefined);
    if (seen !== undefined) return true;
    await pause(Math.min(1_000, leftMs(deadline)));
  }
  return false;
}

/**
 * The receipt of `hash`, looked up until it is found or the deadline passes. A receipt that names
 * another transaction is treated as none.
 *
 * @returns The gas used and effective gas price, or undefined when no receipt was seen in time.
 */
export async function receiptFee(client: PublicClient, hash: Hex, deadline: Deadline): Promise<ReceiptFee | undefined> {
  while (leftMs(deadline) > 0) {
    const receipt = await within(deadline, client.getTransactionReceipt({ hash }), "the receipt lookup").catch(() => undefined);
    if (receipt !== undefined) {
      if (receipt.transactionHash.toLowerCase() !== hash.toLowerCase()) return undefined;
      return { gasUsed: receipt.gasUsed, effectiveGasPrice: receipt.effectiveGasPrice };
    }
    await pause(Math.min(RECEIPT_POLL_MS, leftMs(deadline)));
  }
  return undefined;
}

/**
 * Where the relayer's EVM transaction `hash` stands on the node: "reverted" when its receipt's
 * status (as viem reads it) says it reverted, "landed" for any other receipt or a block number
 * with no receipt yet, "pending" while the node holds it unmined, "unknown" when the node knows
 * neither. An answer that names another transaction is thrown, like any failed lookup, so a caller
 * never reads "unknown" or "reverted" from a lookup that did not run.
 */
export async function evmTxStatus(client: PublicClient, hash: string): Promise<TxStatus> {
  if (!/^0x[0-9a-f]{64}$/.test(hash)) throw new Error("An EVM transaction hash is 0x and 64 lowercase hex digits.");
  const wanted = hash as Hex;
  try {
    const receipt = await client.getTransactionReceipt({ hash: wanted });
    if (receipt.transactionHash.toLowerCase() !== wanted) throw new Error("The receipt names another transaction.");
    return receipt.status === "reverted" ? "reverted" : "landed";
  } catch (error) {
    if (!(error instanceof TransactionReceiptNotFoundError)) throw error;
  }
  try {
    const found = await client.getTransaction({ hash: wanted });
    if (found.hash.toLowerCase() !== wanted) throw new Error("The node answered with another transaction.");
    return found.blockNumber === null ? "pending" : "landed";
  } catch (error) {
    if (error instanceof TransactionNotFoundError) return "unknown";
    throw error;
  }
}

/** keccak256 of the code at `address`, or undefined when there is none. */
export async function codeKeccak(client: PublicClient, address: Hex): Promise<Hex | undefined> {
  const code = await client.getCode({ address });
  return code === undefined || code === "0x" ? undefined : keccak256(code);
}
