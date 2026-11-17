import type { EvmWindow } from "@qorechain/evm";
import type { Deadline } from "./deadline.ts";
import type { CallOutcome, EvmSend, FeeQuote, TxRequest } from "./evm.ts";
import type { WindowRequest } from "./native.ts";

export type { CallOutcome, Deadline, EvmSend, EvmWindow, FeeQuote, TxRequest, WindowRequest };

/**
 * What the window keeper needs from the chain, for the relayer's own account. The implementation
 * holds the relayer's keys; nothing that calls it ever does.
 */
export interface WindowChain {
  /** The relayer's window as the chain's REST reports it now. */
  readWindow(): Promise<EvmWindow>;
  /** Opens (and so replaces) the relayer's window with exactly these bounds; resolves once committed, all by `deadline`. */
  openWindow(request: WindowRequest, deadline: Deadline): Promise<{ hash: string }>;
  /** Closes the relayer's window at once; resolves once committed, all by `deadline`. */
  closeWindow(deadline: Deadline): Promise<{ hash: string }>;
}

/** What the relay handler needs from the chain on top of the window. */
export interface RelayChain extends WindowChain {
  /** eth_call of the exact transaction at the latest block. */
  call(req: TxRequest): Promise<CallOutcome>;
  estimateGas(req: TxRequest): Promise<bigint>;
  feeQuote(): Promise<FeeQuote>;
  /**
   * Signs with the relayer's secp256k1 key and broadcasts once; resolves with the hash, never the
   * outcome. Takes at most about 10 s: the caller starts it only while that much is left.
   */
  send(tx: EvmSend, deadline: Deadline): Promise<`0x${string}`>;
}
