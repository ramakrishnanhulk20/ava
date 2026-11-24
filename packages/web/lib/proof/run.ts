import { assertHash, sameAccount, sha256, verifyAction } from "@ava/core";
import { BaseError, ExecutionRevertedError, bytesToHex, decodeEventLog, hexToBytes, pad, parseAbi, toEventSelector, toHex, type Hex } from "viem";
import { REGISTRY, client } from "../chain";
import { blobUrl, readBlob, readBoard, type BoardSnapshot } from "../guest/board";
import { throwIfStopped } from "../guest/time";
import { decodeWrite, refusalName, trials, unsignedRotate, type TrialKind, type Write } from "./specimen";

const PQC_VERIFY = "0x0000000000000000000000000000000000000a01";
const PQC_STATUS = "0x0000000000000000000000000000000000000a02";
const precompiles = parseAbi([
  "function pqcVerify(bytes pubkey, bytes signature, bytes message) view returns (bool valid)",
  "function pqcKeyStatus(address account) view returns (bool registered, uint8 algorithmId, bytes pubkey, bool possessionProven)",
]);
const withNonce = parseAbi([
  "event MemberAdded(uint256 indexed boardId, address indexed member, uint64 epoch, uint8 mode, uint64 nonce)",
  "event MemberRemoved(uint256 indexed boardId, address indexed member, uint64 newEpoch, uint64 nonce)",
  "event EpochRotated(uint256 indexed boardId, uint64 indexed newEpoch, uint64 nonce)",
  "event DocumentPosted(uint256 indexed boardId, uint256 indexed docId, bytes32 docRef, uint64 epoch, bytes32 cipherHash, uint64 cipherSize, uint64 nonce)",
]);
const NONCE_EVENTS = withNonce.map((item) => toEventSelector(item));
const PAGE_BLOCKS = 10_000n;
const PAGES_BACK = 40;
/** A made-up sender with no key and no seat anywhere, for the "sent by a stranger" try. */
const STRANGER: Hex = "0x00000000000000000000000000000000000b0b00";
const SHOWN_BYTES = 9 * 17;

/** What the registry said to one simulated call. */
export type Outcome = { refused: true; name: string | undefined } | { refused: false };

/** One landed change to the board, found in the registry's own events and read back from its transaction. */
export interface Specimen {
  txHash: Hex;
  block: bigint;
  nonce: bigint;
  write: Write;
  calldata: Hex;
}

export interface ProofRun {
  board: BoardSnapshot;
  unsigned?: { asChair: Outcome; asStranger: Outcome };
  specimen?: Specimen;
  replay?: Outcome;
  /** For each try of the signature table: what the chain's own check said and what this browser's said. */
  signatures?: { what: TrialKind; chain: boolean; here: boolean }[];
  /** The newest pack as the blob store holds it, hashed here and laid against the registry's record. */
  pack?: { docId: bigint; size: bigint; recorded: Hex; computed: Hex; same: boolean; firstBytes: Uint8Array };
}

/** Asks the public RPC what the registry would do with this call, sent by `from`. Nothing is broadcast. */
async function simulate(data: Hex, from: Hex): Promise<Outcome> {
  try {
    await client.call({ account: from, to: REGISTRY, data, blockTag: "latest" });
    return { refused: false };
  } catch (error) {
    if (!(error instanceof BaseError) || error.walk((e) => e instanceof ExecutionRevertedError) === null) throw error;
    const inner = error.walk() as { data?: unknown } | null;
    const raw = typeof inner?.data === "object" && inner.data !== null ? (inner.data as { data?: unknown }).data : inner?.data;
    return { refused: true, name: refusalName(typeof raw === "string" && /^0x([0-9a-fA-F]{2})*$/.test(raw) ? (raw as Hex) : undefined) };
  }
}

/** The newest change to the board that carries a board nonce, looked for backwards from the latest block. */
async function newestWrite(boardId: bigint, latest: bigint, signal: AbortSignal): Promise<Specimen | undefined> {
  for (let page = 0n; page < BigInt(PAGES_BACK); page++) {
    throwIfStopped(signal);
    const to = latest - page * PAGE_BLOCKS;
    if (to < 0n) return undefined;
    const from = to - PAGE_BLOCKS + 1n > 0n ? to - PAGE_BLOCKS + 1n : 0n;
    const logs = await client.request({ method: "eth_getLogs", params: [{ address: REGISTRY, fromBlock: toHex(from), toBlock: toHex(to), topics: [NONCE_EVENTS, pad(toHex(boardId), { size: 32 })] }] });
    const placed = logs
      .filter((l) => sameAccount(l.address, REGISTRY) && l.transactionHash !== null && l.blockNumber !== null && l.logIndex !== null)
      .map((l) => ({ log: l, block: BigInt(l.blockNumber as Hex), index: Number(BigInt(l.logIndex as Hex)) }))
      .sort((x, y) => (x.block === y.block ? y.index - x.index : x.block < y.block ? 1 : -1));
    for (const { log, block } of placed) {
      let nonce: bigint;
      try {
        nonce = decodeEventLog({ abi: withNonce, data: log.data, topics: log.topics as [Hex, ...Hex[]] }).args.nonce;
      } catch {
        continue;
      }
      const txHash = log.transactionHash as Hex;
      const tx = await client.getTransaction({ hash: txHash });
      if (tx.to === null || !sameAccount(tx.to, REGISTRY)) continue;
      const write = decodeWrite(tx.input);
      if (write === undefined || write.boardId !== boardId) continue;
      return { txHash, block, nonce, write, calldata: tx.input };
    }
  }
  return undefined;
}

/**
 * Runs the proof page's checks against the public EVM RPC and the blob store, from this browser,
 * and reports each as it finishes. All of it is reads and simulated calls: nothing is signed,
 * nothing is sent, and none of it passes through our server.
 *
 * 1. A rotation of the board, right in every field, sent as the chair's own address and as a
 *    stranger with a signature of zeros.
 * 2. The newest landed change to the board, its exact bytes sent again.
 * 3. That change's real signature, checked by the chain's ML-DSA-87 precompile and by this browser
 *    over the message it was made for and over four changed ones.
 * 4. The newest pack's stored bytes, hashed here and compared with the registry's record.
 *
 * @param onChange Called with what is known so far after every step.
 * @throws Error when a read fails; what was found before it stays shown.
 */
export async function runProof(boardId: bigint, signal: AbortSignal, onChange: (run: ProofRun) => void): Promise<void> {
  const board = await readBoard(boardId);
  let run: ProofRun = { board };
  const tell = (patch: Partial<ProofRun>): void => {
    run = { ...run, ...patch };
    if (!signal.aborted) onChange(run);
  };
  tell({});

  const zeros = unsignedRotate({ boardId, epoch: board.epoch, latestBlockTimestamp: board.blockTimestamp });
  const [asChair, asStranger] = await Promise.all([simulate(zeros, board.chair), simulate(zeros, STRANGER)]);
  tell({ unsigned: { asChair, asStranger } });

  throwIfStopped(signal);
  const specimen = await newestWrite(boardId, board.blockNumber, signal);
  if (specimen !== undefined) {
    tell({ specimen });
    tell({ replay: await simulate(specimen.calldata, STRANGER) });

    throwIfStopped(signal);
    const status = await client.readContract({ address: PQC_STATUS, abi: precompiles, functionName: "pqcKeyStatus", args: [board.chair] });
    const publicKey = hexToBytes(status[2]);
    const signatures: NonNullable<ProofRun["signatures"]> = [];
    for (const trial of trials(specimen.write, { registry: REGISTRY, nonce: specimen.nonce })) {
      throwIfStopped(signal);
      const chain = await client.readContract({ address: PQC_VERIFY, abi: precompiles, functionName: "pqcVerify", args: [status[2], bytesToHex(trial.signature), bytesToHex(trial.message)] });
      signatures.push({ what: trial.what, chain, here: verifyAction(publicKey, trial.message, trial.signature) });
      tell({ signatures: [...signatures] });
    }
  }

  throwIfStopped(signal);
  const doc = board.latest;
  if (doc !== undefined) {
    const stored = await readBlob(blobUrl("document", doc.cipherHash), Number(doc.cipherSize), signal);
    let same = BigInt(stored.length) === doc.cipherSize;
    let computed: Hex = "0x";
    try {
      computed = bytesToHex(sha256(stored));
      assertHash(stored, doc.cipherHash);
    } catch {
      same = false;
    }
    tell({ pack: { docId: doc.docId, size: doc.cipherSize, recorded: doc.cipherHash, computed, same, firstBytes: stored.slice(0, SHOWN_BYTES) } });
  }
}
