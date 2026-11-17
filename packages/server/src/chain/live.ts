import { getJson, postJsonRpc } from "@qorechain/sdk";
import type { PublicClient } from "viem";
import { CHAIN_ID, EVM_CHAIN_ID, EVM_RPC, HTTP, RPC, WINDOW_CLOSE_FEE, WINDOW_OPEN_FEE } from "../config.ts";
import { publicAddress, relayerFromMnemonic, type RelayerAccount, type RelayerAddress } from "./account.ts";
import { OutOfTime, leftMs, pause, within, type Deadline } from "./deadline.ts";
import { estimateGas, ethCall, evmClient, feeQuote, pendingNonce, sendEvm } from "./evm.ts";
import { accountSequence, closeWindowTx, openWindowTx, readEvmWindow } from "./native.ts";
import type { RelayChain } from "./types.ts";

const SEQUENCE_PAUSE_MS = 1_500;

/**
 * Opening or closing a window is a native transaction signed with the committed sequence, which is
 * also the EVM nonce. An EVM transaction still in the mempool holds that number, so the native one
 * would be refused; wait for the mempool to clear first, and give up at the deadline rather than
 * race it.
 */
async function waitForQuietNonce(client: PublicClient, account: RelayerAccount, deadline: Deadline): Promise<void> {
  for (;;) {
    const [auth, pending] = await within(deadline, Promise.all([accountSequence(account.qor1), pendingNonce(client, account.evm)]), "reading the nonce");
    if (auth === undefined) throw new Error(`${account.qor1} does not exist on chain yet: fund it first.`);
    if (BigInt(pending) <= auth.sequence) return;
    if (leftMs(deadline) <= SEQUENCE_PAUSE_MS) throw new OutOfTime("the relayer's pending EVM transactions cleared");
    await pause(SEQUENCE_PAUSE_MS);
  }
}

/**
 * The relayer's chain access on the live testnet. The account, with its keys, stays inside this
 * closure: the object returned carries no key, so a handler holding it cannot leak one. Reads use
 * one paused retry; the send uses a client with none, so it fits its 10 s.
 */
export function liveChain(account: RelayerAccount, reads: PublicClient = evmClient(), sends: PublicClient = evmClient({ retries: 0 })): RelayChain {
  return {
    readWindow: () => readEvmWindow(account.qor1),
    openWindow: async (request, deadline) => {
      await waitForQuietNonce(reads, account, deadline);
      return { hash: (await openWindowTx(account, request, WINDOW_OPEN_FEE, deadline)).hash };
    },
    closeWindow: async (deadline) => {
      await waitForQuietNonce(reads, account, deadline);
      return { hash: (await closeWindowTx(account, WINDOW_CLOSE_FEE, deadline)).hash };
    },
    call: (req) => ethCall(reads, req),
    estimateGas: (req) => estimateGas(reads, req),
    feeQuote: () => feeQuote(reads),
    send: (tx, deadline) => sendEvm(sends, account, tx, deadline),
  };
}

/** The relayer's public address and its live chain access, from its phrase: what handleRelay's context needs. */
export async function liveRelayer(mnemonic: string): Promise<{ relayer: RelayerAddress; chain: RelayChain }> {
  const account = await relayerFromMnemonic(mnemonic);
  return { relayer: publicAddress(account), chain: liveChain(account) };
}

/**
 * Asks the consensus RPC and the EVM JSON-RPC which chain they serve, and throws unless both are
 * the testnet, so a wrong endpoint never receives anything the relayer signed.
 */
export async function assertTestnet(): Promise<string> {
  const status = await getJson<{ result?: { node_info?: { network?: unknown } } }>(`${RPC}/status`, HTTP);
  const network = status.result?.node_info?.network;
  if (network !== CHAIN_ID) throw new Error(`RPC ${RPC} does not report chain ${CHAIN_ID}. Refusing to continue.`);
  const body = await postJsonRpc<{ result?: unknown }>(EVM_RPC, { jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }, HTTP);
  const expected = `0x${EVM_CHAIN_ID.toString(16)}`;
  if (typeof body.result !== "string" || body.result.toLowerCase() !== expected) {
    throw new Error(`EVM RPC ${EVM_RPC} does not report chain id ${expected}. Refusing to continue.`);
  }
  return network;
}
