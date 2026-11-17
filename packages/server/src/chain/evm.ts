import { sameAccount } from "@ava/core";
import {
  BaseError,
  ExecutionRevertedError,
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

/**
 * Signs one EIP-1559 transaction locally with the relayer's secp256k1 key (value 0, chain id 9800,
 * the pending nonce) and broadcasts it once. The hash is known before sending, so a lost answer is
 * met by looking the hash up until the deadline, never by sending again. Does not wait for the receipt.
 *
 * @returns The transaction hash, once the node has taken it.
 * @throws When the key is not the relayer's, or the node refused the transaction and it is not
 *   seen before the deadline.
 */
export async function sendEvm(client: PublicClient, account: RelayerAccount, tx: EvmSend, deadline: Deadline): Promise<Hex> {
  const signer = privateKeyToAccount(account.privateKey);
  if (!sameAccount(signer.address, account.evm)) throw new Error("The EVM signing key is not the relayer's key.");
  const nonce = await pendingNonce(client, account.evm);
  const serialized = await signer.signTransaction({ type: "eip1559", chainId: EVM_CHAIN_ID, nonce, value: 0n, ...tx });
  const hash = keccak256(serialized);
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

/** keccak256 of the code at `address`, or undefined when there is none. */
export async function codeKeccak(client: PublicClient, address: Hex): Promise<Hex | undefined> {
  const code = await client.getCode({ address });
  return code === undefined || code === "0x" ? undefined : keccak256(code);
}
