import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { toChecksumAddress } from "@qorechain/sdk";
import { sameAccount } from "@ava/core";
import { decodeErrorResult, encodeFunctionData, parseEventLogs, type Abi, type Hex, type PublicClient, type TransactionReceipt } from "viem";
import type { Deployer } from "../account.js";
import { CHAIN_ID, DEPLOYMENTS_PATH, EVM_CHAIN_ID } from "../env.js";
import {
  assertBudget,
  describeWindow,
  ethCall,
  evmFeeUqor,
  fees,
  formatQor,
  openWindow,
  sendEvm,
  windowSpendCap,
  windowValueFor,
  withHeadroom,
  type CallOutcome,
  type OpenedWindow,
} from "./evm.js";

export const PACKAGE_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const ARTIFACT_PATH = fileURLToPath(new URL("../../out/BoardRegistry.sol/BoardRegistry.json", import.meta.url));

export interface RegistryArtifact {
  abi: Abi;
  bytecode: Hex;
  deployedBytecode: Hex;
  /** The exact solc build, e.g. `0.8.38+commit.1835d247`. */
  compilerVersion: string;
  /** The solc metadata of this build: settings and the keccak256 of every source it compiled. */
  metadata: { language: string; settings: Record<string, unknown>; sources: Record<string, { keccak256: Hex }> };
}

export interface RegistryRecord {
  address: Hex;
  deployTx: Hex;
  blockNumber: string;
  deployer: Hex;
  runtimeCodeHash: Hex;
  solcVersion: string;
}

export interface BoardState {
  blockNumber: bigint;
  timestamp: bigint;
  chair: Hex;
  boardRef: Hex;
  epoch: bigint;
  nonce: bigint;
  memberCount: number;
  documentCount: number;
  members: Hex[];
}

export interface Registry {
  client: PublicClient;
  deployer: Deployer;
  address: Hex;
  abi: Abi;
}

export interface WriteResult {
  hash: Hex;
  data: Hex;
  receipt: TransactionReceipt;
  evmFeeUqor: bigint;
  window: OpenedWindow;
  events: { eventName: string; args: Record<string, unknown> }[];
}

// The EVM JSON-RPC reports contract and log addresses in lowercase, which carries no checksum.
// They come from the chain, not from a person, so they are put in EIP-55 form for display.
export const fromRpc = (address: string): Hex => toChecksumAddress(address) as Hex;

const HEX = (v: unknown, what: string): Hex => {
  if (typeof v !== "string" || !/^0x[0-9a-fA-F]{2,}$/.test(v)) throw new Error(`The build output has no ${what}.`);
  return v as Hex;
};

export function loadRegistryArtifact(): RegistryArtifact {
  if (!existsSync(ARTIFACT_PATH)) throw new Error(`No build output at ${ARTIFACT_PATH}. Run: forge build`);
  const json = JSON.parse(readFileSync(ARTIFACT_PATH, "utf8")) as {
    abi?: unknown;
    bytecode?: { object?: unknown };
    deployedBytecode?: { object?: unknown };
    metadata?: { language?: unknown; compiler?: { version?: unknown }; settings?: unknown; sources?: unknown };
  };
  if (!Array.isArray(json.abi)) throw new Error("The build output has no ABI.");
  const meta = json.metadata;
  const version = meta?.compiler?.version;
  if (typeof version !== "string" || !/^\d+\.\d+\.\d+\+commit\.[0-9a-f]{8}$/.test(version)) throw new Error("The build output names no exact solc version.");
  if (typeof meta?.language !== "string" || typeof meta.settings !== "object" || meta.settings === null || typeof meta.sources !== "object" || meta.sources === null) {
    throw new Error("The build output carries no solc metadata.");
  }
  return {
    abi: json.abi as Abi,
    bytecode: HEX(json.bytecode?.object, "bytecode"),
    deployedBytecode: HEX(json.deployedBytecode?.object, "deployed bytecode"),
    compilerVersion: version,
    metadata: meta as RegistryArtifact["metadata"],
  };
}

function readDeployments(): Record<string, unknown> {
  if (!existsSync(DEPLOYMENTS_PATH)) return { network: CHAIN_ID, evmChainId: EVM_CHAIN_ID };
  const d = JSON.parse(readFileSync(DEPLOYMENTS_PATH, "utf8")) as Record<string, unknown>;
  if (d.network !== CHAIN_ID || d.evmChainId !== EVM_CHAIN_ID) throw new Error(`${DEPLOYMENTS_PATH} is not a ${CHAIN_ID} record. Refusing to guess.`);
  return d;
}

/** The BoardRegistry entry in deployments/testnet.json, or undefined when there is none. */
export function recordedRegistry(): RegistryRecord | undefined {
  const entry = readDeployments().BoardRegistry as Partial<RegistryRecord> | undefined;
  if (entry === undefined) return undefined;
  const ok =
    /^0x[0-9a-fA-F]{40}$/.test(entry.address ?? "") &&
    /^0x[0-9a-f]{64}$/.test(entry.deployTx ?? "") &&
    /^\d+$/.test(entry.blockNumber ?? "") &&
    /^0x[0-9a-fA-F]{40}$/.test(entry.deployer ?? "") &&
    /^0x[0-9a-f]{64}$/.test(entry.runtimeCodeHash ?? "") &&
    typeof entry.solcVersion === "string";
  if (!ok) throw new Error(`The BoardRegistry entry in ${DEPLOYMENTS_PATH} is malformed. Refusing to guess.`);
  return entry as RegistryRecord;
}

/** Writes the BoardRegistry entry and keeps every other entry as it was. */
export function saveRegistry(record: RegistryRecord): void {
  const d = readDeployments();
  d.BoardRegistry = record;
  writeFileSync(DEPLOYMENTS_PATH, `${JSON.stringify(d, null, 2)}\n`, "utf8");
}

/**
 * Reads a board and its member set at one block, the latest, so the nonce, the epoch and the
 * members a signature is built from all describe the same moment (threat model C17).
 */
export async function boardAt(r: Registry, boardId: bigint): Promise<BoardState> {
  const block = await r.client.getBlock({ blockTag: "latest" });
  const at = { address: r.address, abi: r.abi, blockNumber: block.number } as const;
  const [board, members] = await Promise.all([
    r.client.readContract({ ...at, functionName: "getBoard", args: [boardId] }) as Promise<Record<string, unknown>>,
    r.client.readContract({ ...at, functionName: "getMembers", args: [boardId] }) as Promise<unknown>,
  ]);
  if (
    typeof board.chair !== "string" ||
    typeof board.boardRef !== "string" ||
    typeof board.epoch !== "bigint" ||
    typeof board.nonce !== "bigint" ||
    typeof board.memberCount !== "number" ||
    typeof board.documentCount !== "number" ||
    !Array.isArray(members) ||
    members.some((m) => typeof m !== "string")
  ) {
    throw new Error(`getBoard or getMembers for board ${boardId} did not decode as the ABI says.`);
  }
  return {
    blockNumber: block.number,
    timestamp: block.timestamp,
    chair: board.chair as Hex,
    boardRef: board.boardRef as Hex,
    epoch: board.epoch,
    nonce: board.nonce,
    memberCount: board.memberCount,
    documentCount: board.documentCount,
    members: members as Hex[],
  };
}

/** createNonces[chair] and the block it was read at. */
export async function createNonceAt(r: Registry, chair: Hex): Promise<{ blockNumber: bigint; timestamp: bigint; nonce: bigint }> {
  const block = await r.client.getBlock({ blockTag: "latest" });
  const nonce = await r.client.readContract({ address: r.address, abi: r.abi, functionName: "createNonces", args: [chair], blockNumber: block.number });
  if (typeof nonce !== "bigint") throw new Error("createNonces did not decode as a uint64.");
  return { blockNumber: block.number, timestamp: block.timestamp, nonce };
}

export interface Grant {
  envelopeHash: Hex;
  envelopeSize: number;
  mode: number;
  member: Hex;
}

export interface DocumentRecord {
  docRef: Hex;
  cipherHash: Hex;
  cipherSize: bigint;
  epoch: bigint;
  postedAt: bigint;
}

/** Every envelope granted for one epoch, in the order they landed. */
export async function grantsOf(r: Registry, boardId: bigint, epoch: bigint): Promise<Grant[]> {
  const list = await r.client.readContract({ address: r.address, abi: r.abi, functionName: "getGrants", args: [boardId, epoch] });
  if (!Array.isArray(list)) throw new Error("getGrants did not decode as a list.");
  return list.map((g: Record<string, unknown>) => {
    if (typeof g.envelopeHash !== "string" || typeof g.envelopeSize !== "number" || typeof g.mode !== "number" || typeof g.member !== "string") {
      throw new Error("A grant did not decode as the ABI says.");
    }
    return { envelopeHash: g.envelopeHash as Hex, envelopeSize: g.envelopeSize, mode: g.mode, member: g.member as Hex };
  });
}

export async function documentOf(r: Registry, boardId: bigint, docId: bigint): Promise<DocumentRecord> {
  const d = (await r.client.readContract({ address: r.address, abi: r.abi, functionName: "getDocument", args: [boardId, docId] })) as Record<string, unknown>;
  if (typeof d.docRef !== "string" || typeof d.cipherHash !== "string" || typeof d.cipherSize !== "bigint" || typeof d.epoch !== "bigint" || typeof d.postedAt !== "bigint") {
    throw new Error("getDocument did not decode as the ABI says.");
  }
  return { docRef: d.docRef as Hex, cipherHash: d.cipherHash as Hex, cipherSize: d.cipherSize, epoch: d.epoch, postedAt: d.postedAt };
}

/** True when `members` and `expected` hold the same accounts, compared as 20 bytes. */
export function sameMembers(members: readonly string[], expected: readonly string[]): boolean {
  return members.length === expected.length && expected.every((e) => members.some((m) => sameAccount(m, e)));
}

/** A refused call in readable form: the decoded custom error with its arguments, or the node's words. */
export function describeRefusal(abi: Abi, outcome: Extract<CallOutcome, { ok: false }>): { name: string; text: string } {
  if (outcome.revertData === undefined || outcome.revertData === "0x") return { name: "", text: `reverted with no error data (${outcome.message})` };
  try {
    const { errorName, args } = decodeErrorResult({ abi, data: outcome.revertData });
    const shown = (args ?? []).map((a) => (typeof a === "string" && /^0x[0-9a-fA-F]{40}$/.test(a) ? fromRpc(a) : String(a)));
    return { name: errorName, text: `${errorName}(${shown.join(", ")})` };
  } catch {
    return { name: "", text: `reverted with data ${outcome.revertData.slice(0, 74)} that is not one of the registry's errors` };
  }
}

/** eth_call of the exact calldata from the deployer, never broadcast. */
export async function callFromDeployer(r: Registry, data: Hex, value?: bigint): Promise<CallOutcome> {
  return ethCall(r.client, { from: r.deployer.evm, to: r.address, data, value });
}

/**
 * Relays one registry write from the deployer, which grants nothing (anyone may relay).
 *
 * Order: eth_call of the exact transaction must pass; gas is estimated with 25 percent headroom;
 * a window scoped to the registry alone is sized with evmWindowCost for this one transaction; the
 * budget guard runs; the window opens; the transaction is sent once and must succeed.
 *
 * @throws When the pre-flight is refused (nothing is sent), the budget guard stops, the window is
 *   not the one asked for, or the transaction reverts.
 */
export async function relayWrite(r: Registry, functionName: string, args: readonly unknown[], log: (line: string) => void): Promise<WriteResult> {
  const data = encodeFunctionData({ abi: r.abi, functionName, args });
  const pre = await callFromDeployer(r, data);
  if (!pre.ok) throw new Error(`Pre-flight eth_call of ${functionName} was refused: ${describeRefusal(r.abi, pre).text}. Nothing was sent.`);
  log(`  pre-flight: eth_call of the exact ${functionName} from the deployer passes`);
  const gas = withHeadroom(await r.client.estimateGas({ account: r.deployer.evm, to: r.address, data }));
  const fee = await fees(r.client);
  const maxValue = windowValueFor(gas, fee);
  await assertBudget(r.deployer, windowSpendCap(maxValue), functionName);
  const window = await openWindow(r.deployer, maxValue, [r.address]);
  log(`  window:   allowed_targets [${r.address}], ${describeWindow(window, "scoped")}`);

  const { hash, receipt } = await sendEvm(r.client, r.deployer, { to: r.address, data, gas, ...fee });
  if (receipt.status !== "success") throw new Error(`${functionName} ${hash} reverted on chain (the fee was charged).`);
  const events = parseEventLogs({ abi: r.abi, logs: receipt.logs })
    .filter((l) => sameAccount(l.address, r.address))
    .map((l) => ({ eventName: String(l.eventName), args: (l.args ?? {}) as Record<string, unknown> }));
  const result = { hash, data, receipt, evmFeeUqor: evmFeeUqor(receipt), window, events };
  log(`  tx:       ${hash}, block ${receipt.blockNumber}, gas used ${receipt.gasUsed}, fee ${formatQor(result.evmFeeUqor)} QOR`);
  log(`  events:   ${events.map((e) => e.eventName).join(", ")}`);
  return result;
}
