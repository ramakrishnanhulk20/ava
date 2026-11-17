import { getJson, postJsonRpc } from "@qorechain/sdk";
import { createPublicClient, defineChain, http, type PublicClient } from "viem";
import { CHAIN_ID, EVM_CHAIN_ID, EVM_RPC, HTTP, RPC } from "./env.js";

interface RpcStatus {
  result?: { node_info?: { network?: unknown } };
}

export const qoreTestnet = defineChain({
  id: EVM_CHAIN_ID,
  name: "QoreChain testnet",
  nativeCurrency: { name: "QOR", symbol: "QOR", decimals: 18 },
  rpcUrls: { default: { http: [EVM_RPC] } },
});

/** Reads go to the public EVM JSON-RPC with retries and a timeout on every call. */
export function evmClient(): PublicClient {
  return createPublicClient({
    chain: qoreTestnet,
    transport: http(EVM_RPC, { retryCount: HTTP.retries, retryDelay: HTTP.retryDelayMs, timeout: HTTP.timeoutMs }),
  });
}

/**
 * Asks both the consensus RPC and the EVM JSON-RPC which chain they serve and
 * throws unless both are the testnet. Every script calls this before reading
 * or signing anything, so a wrong or hijacked endpoint can never receive a
 * signature from the deployer.
 *
 * @returns The confirmed native chain id.
 * @throws When either endpoint cannot be read, or reports any other chain.
 */
export async function assertTestnet(): Promise<string> {
  const status = await getJson<RpcStatus>(`${RPC}/status`, HTTP);
  const network = status.result?.node_info?.network;
  if (network !== CHAIN_ID) {
    const shown = (JSON.stringify(network) ?? "nothing").slice(0, 80);
    throw new Error(`RPC ${RPC} reports chain ${shown}, expected ${CHAIN_ID}. Refusing to continue.`);
  }

  const body = await postJsonRpc<{ result?: unknown }>(EVM_RPC, { jsonrpc: "2.0", id: 1, method: "eth_chainId", params: [] }, HTTP);
  const expected = `0x${EVM_CHAIN_ID.toString(16)}`;
  if (typeof body.result !== "string" || body.result.toLowerCase() !== expected) {
    const shown = (JSON.stringify(body.result) ?? "nothing").slice(0, 80);
    throw new Error(`EVM RPC ${EVM_RPC} reports chain id ${shown}, expected ${expected}. Refusing to continue.`);
  }
  return network;
}
