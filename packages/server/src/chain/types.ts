import type { EvmWindow } from "@qorechain/evm";
import type { Deadline } from "./deadline.ts";
import type { BeforeBroadcast, CallOutcome, EvmSend, FeeQuote, ReceiptFee, SignedTx, TxRequest, TxStatus } from "./evm.ts";
import type { WindowRequest } from "./native.ts";

export type { BeforeBroadcast, CallOutcome, Deadline, EvmSend, EvmWindow, FeeQuote, ReceiptFee, SignedTx, TxRequest, TxStatus, WindowRequest };

/**
 * What the window keeper needs from the chain, for the relayer's own account. The implementation
 * holds the relayer's keys; nothing that calls it ever does.
 */
export interface WindowChain {
  /** The relayer's window as the chain's REST reports it now. */
  readWindow(): Promise<EvmWindow>;
  /**
   * Opens (and so replaces) the relayer's window with exactly these bounds; resolves once committed,
   * all by `deadline`. `beforeBroadcast` runs once signed and before the broadcast; if it throws,
   * nothing is sent.
   */
  openWindow(request: WindowRequest, deadline: Deadline, beforeBroadcast?: BeforeBroadcast): Promise<{ hash: string }>;
  /** Closes the relayer's window at once; resolves once committed, all by `deadline`. `beforeBroadcast` as for openWindow. */
  closeWindow(deadline: Deadline, beforeBroadcast?: BeforeBroadcast): Promise<{ hash: string }>;
  /**
   * The relayer account's next nonce as the chain reports it, mempool included. The EVM nonce and
   * the native sequence are one counter, so every send, open and close moves it. Optional only so
   * older callers still type-check: without it the relayer refuses every open and send.
   */
  nonce?(): Promise<bigint>;
  /**
   * Where one of the relayer's own signed transactions stands (threat model C24, C40): what lets the
   * stored nonce move past it ("landed" or "reverted", both in a block), and what lets a mark naming
   * it give way ("unknown" or "reverted", neither of which changed the registry). Throws when the
   * lookup itself fails. Optional only so older callers still type-check: without it the relayer
   * refuses every open and send.
   */
  txStatus?(kind: SignedTx["kind"], hash: string): Promise<TxStatus>;
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
   * `beforeBroadcast` runs once signed and before the broadcast; if it throws, nothing is sent and
   * the send throws NotBroadcast.
   */
  send(tx: EvmSend, deadline: Deadline, beforeBroadcast?: BeforeBroadcast): Promise<`0x${string}`>;
  /**
   * The receipt of one of our own sends, looked for until `deadline`: what it really cost, or
   * undefined when none was seen. Without this method every send keeps its worst case booked.
   */
  receipt?(hash: `0x${string}`, deadline: Deadline): Promise<ReceiptFee | undefined>;
  /**
   * keccak256 of the code at REGISTRY_ADDRESS at the latest block, or undefined when there is none.
   * Optional only so older callers still type-check: without it the relay refuses every request.
   */
  registryCodeHash?(): Promise<`0x${string}` | undefined>;
}
