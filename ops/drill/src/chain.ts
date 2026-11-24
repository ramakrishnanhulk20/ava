import { getJson } from "@qorechain/sdk";
import { CHAIN_ID, HTTP, RPC } from "./env.js";

interface RpcStatus {
  result?: { node_info?: { network?: unknown } };
}

/**
 * Asks the consensus RPC which chain it serves and throws unless it is the
 * testnet. Every script calls this before reading or signing anything, so a
 * wrong or hijacked endpoint can never receive a signature from this account.
 *
 * @returns The confirmed chain id.
 * @throws When the RPC cannot be read, or reports any other chain.
 */
export async function assertTestnet(): Promise<string> {
  const status = await getJson<RpcStatus>(`${RPC}/status`, HTTP);
  const network = status.result?.node_info?.network;
  if (network !== CHAIN_ID) {
    const shown = (JSON.stringify(network) ?? "nothing").slice(0, 80);
    throw new Error(`RPC ${RPC} reports chain ${shown}, expected ${CHAIN_ID}. Refusing to continue.`);
  }
  return network;
}
