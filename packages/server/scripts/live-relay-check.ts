import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import {
  Action,
  KemKeyUnavailable,
  canonicalPhrase,
  deadlineFrom,
  fetchKemKey,
  identityFromMnemonic,
  newEpochKey,
  sameAccount,
  sealEpochKey,
  sha256,
  signBoardAction,
  type Identity,
  type KemRecipient,
} from "@ava/core";
import type { EvmWindow } from "@qorechain/evm";
import { clearPqcStatusCache, fetchPqcStatus, isRegisteredPqcKey, withRetry } from "@qorechain/sdk";
import { bytesToHex, type Hex, type PublicClient } from "viem";
import { boardRegistryAbi } from "../src/abi/boardRegistry.ts";
import { isRelayerMnemonic, publicAddress, relayerFromMnemonic, type RelayerAccount } from "../src/chain/account.ts";
import { codeKeccak, evmClient } from "../src/chain/evm.ts";
import { assertTestnet, liveChain } from "../src/chain/live.ts";
import { balanceOf, readEvmWindow } from "../src/chain/native.ts";
import { REGISTRY_ADDRESS, REGISTRY_CODE_KECCAK, REST, UQOR_PER_QOR } from "../src/config.ts";
import { loadEnv, requireRelayerMnemonic, type ServerEnv } from "../src/env.ts";
import { handleRelay } from "../src/relay.ts";
import { UpstashStore } from "../src/store.ts";

const SERVER_ENV = fileURLToPath(new URL("../.env", import.meta.url));
const CONTRACTS_ENV = fileURLToPath(new URL("../../contracts/.env", import.meta.url));
const DEPLOYMENTS = fileURLToPath(new URL("../../contracts/deployments/testnet.json", import.meta.url));
const MIN_BALANCE_UQOR = 1_000_000n;
const DEADLINE_SECONDS = 600;
/** Boards searched, newest first, for one the proof's chair created. */
const BOARD_SEARCH = 64n;

function formatQor(uqor: bigint): string {
  const fraction = (uqor % UQOR_PER_QOR).toString().padStart(6, "0").replace(/0+$/, "");
  return `${uqor / UQOR_PER_QOR}${fraction === "" ? "" : `.${fraction}`}`;
}

function describeWindow(w: EvmWindow): string {
  if (!w.found) return "none stored";
  return `live ${w.live}, allowed_targets [${w.allowedTargets.join(", ")}], native_only ${w.nativeOnly}, ${w.remainingTxs} of ${w.maxTxs} txs, ${w.remainingBlocks} blocks, ${w.remainingValue} of ${w.maxValue} uqor left`;
}

async function provenKey(account: RelayerAccount): Promise<boolean> {
  clearPqcStatusCache();
  const status = await fetchPqcStatus({ rest: REST, address: account.qor1 });
  return status.registered && isRegisteredPqcKey(status, account.pqc.publicKey) === true && status.possessionProven === true;
}

/** Only a dropped connection or a timeout is retried; every other KEM refusal stops at once (threat model C15). */
async function kemKeyOf(address: string): Promise<KemRecipient> {
  return withRetry(() => fetchKemKey(address), {
    retries: 4,
    backoff: 2_000,
    maxBackoff: 6_000,
    shouldRetry: (err) => err instanceof KemKeyUnavailable && (err.reason === "NETWORK" || err.reason === "TIMEOUT"),
  });
}

/** The newest board the proof's chair created, or undefined when the last BOARD_SEARCH boards hold none. */
async function proofBoard(client: PublicClient, chair: Hex): Promise<bigint | undefined> {
  const count = await client.readContract({ address: REGISTRY_ADDRESS, abi: boardRegistryAbi, functionName: "boardCount" });
  for (let id = count; id >= 1n && id > count - BOARD_SEARCH; id--) {
    const board = await client.readContract({ address: REGISTRY_ADDRESS, abi: boardRegistryAbi, functionName: "getBoard", args: [id] });
    if (sameAccount(board.chair, chair)) return id;
  }
  return undefined;
}

async function boardAt(client: PublicClient, id: bigint) {
  const block = await client.getBlock({ blockTag: "latest" });
  const at = { address: REGISTRY_ADDRESS, abi: boardRegistryAbi, blockNumber: block.number } as const;
  const [board, members] = await Promise.all([
    client.readContract({ ...at, functionName: "getBoard", args: [id] }),
    client.readContract({ ...at, functionName: "getMembers", args: [id] }),
  ]);
  return { block, board, members };
}

/** Signs and relays one rotateEpoch on the proof chair's newest board, then follows it to its receipt. */
async function relayOneRotation(env: ServerEnv, relayer: RelayerAccount, chair: Identity, client: PublicClient): Promise<boolean> {
  const id = await proofBoard(client, chair.evm);
  if (id === undefined) {
    console.log(`board:     none of the last ${BOARD_SEARCH} boards has the proof's chair ${chair.evm}. Run the registry proof first.`);
    return false;
  }
  const { block, board, members } = await boardAt(client, id);
  const epochAfter = board.epoch + 1n;
  console.log(`board:     ${id}, chair ${board.chair}, epoch ${board.epoch}, nonce ${board.nonce}, ${members.length} members, read at block ${block.number}`);

  const recipients: KemRecipient[] = [];
  for (const address of members) recipients.push(await kemKeyOf(address));
  const envelope = sealEpochKey({ registry: REGISTRY_ADDRESS, boardRef: board.boardRef, epoch: epochAfter, epochKey: newEpochKey(), recipients });
  const envelopeHash = bytesToHex(sha256(envelope));
  const deadline = deadlineFrom(block.timestamp, DEADLINE_SECONDS);
  const signed = signBoardAction(chair.mldsa.secretKey, {
    action: Action.ROTATE,
    envelopeHash,
    envelopeSize: envelope.length,
    epochAfter,
    registry: REGISTRY_ADDRESS,
    boardId: id,
    nonce: board.nonce,
    deadline,
    latestBlockTimestamp: block.timestamp,
  });
  const signature = bytesToHex(signed.signature);
  console.log(`signed:    ROTATE to epoch ${epochAfter} by the chair's ML-DSA-87 key over board nonce ${board.nonce}; envelope ${envelope.length} bytes, sha256 ${envelopeHash}`);
  console.log("           The envelope is not uploaded anywhere, so this test board's members cannot open the new epoch. Only the proof's test boards are used.");

  const body = {
    action: "rotate",
    boardId: id.toString(),
    params: { envelopeHash, envelopeSize: String(envelope.length), epochAfter: epochAfter.toString() },
    deadline: deadline.toString(),
    signature,
  };
  const request = new Request("http://localhost/api/relay", { method: "POST", headers: { "content-type": "application/json", "x-ava": "1" }, body: JSON.stringify(body) });
  const store = UpstashStore.connect({ url: env.UPSTASH_REDIS_REST_URL, token: env.UPSTASH_REDIS_REST_TOKEN });
  const response = await handleRelay(request, { clientIp: "127.0.0.1", now: Date.now(), store, relayer: publicAddress(relayer), chain: liveChain(relayer, client) });
  const answer = (await response.json()) as { txHash?: unknown; error?: unknown };
  console.log(`relay:     HTTP ${response.status} ${JSON.stringify(answer)}`);
  if (response.status !== 202 || typeof answer.txHash !== "string") return false;

  const hash = answer.txHash as Hex;
  const receipt = await client.waitForTransactionReceipt({ hash, timeout: 90_000, pollingInterval: 2_000 });
  const feeUqor = (receipt.gasUsed * receipt.effectiveGasPrice + 10n ** 12n - 1n) / 10n ** 12n;
  console.log(`tx:        ${hash}`);
  console.log(`receipt:   status ${receipt.status}, block ${receipt.blockNumber}, gas used ${receipt.gasUsed}, fee ${formatQor(feeUqor)} QOR`);
  const after = await boardAt(client, id);
  const moved = after.board.epoch === epochAfter && after.board.nonce === board.nonce + 1n;
  console.log(`board:     ${id} now at epoch ${after.board.epoch}, nonce ${after.board.nonce}: ${moved ? "moved by exactly one, as signed" : "NOT what was signed"}`);
  return receipt.status === "success" && moved;
}

async function main(): Promise<void> {
  if (existsSync(SERVER_ENV)) process.loadEnvFile(SERVER_ENV);
  const missing: string[] = [];

  const chainId = await assertTestnet();
  console.log(`chain id:  ${chainId} confirmed`);
  const client = evmClient();
  const code = await codeKeccak(client, REGISTRY_ADDRESS);
  if (code !== REGISTRY_CODE_KECCAK) throw new Error(`The code at ${REGISTRY_ADDRESS} hashes to ${code ?? "nothing"}, not ${REGISTRY_CODE_KECCAK}. Stopping.`);
  console.log(`registry:  ${REGISTRY_ADDRESS}, runtime code keccak ${code}, as recorded at deploy`);

  let env: ServerEnv | undefined;
  try {
    env = loadEnv();
    requireRelayerMnemonic(env);
  } catch (err) {
    missing.push(err instanceof Error ? err.message : "server settings could not be read");
  }

  const phrase = process.env.RELAYER_MNEMONIC;
  let relayer: RelayerAccount | undefined;
  if (phrase !== undefined && isRelayerMnemonic(phrase)) {
    relayer = await relayerFromMnemonic(phrase);
    const [balance, keyed, window] = await Promise.all([balanceOf(relayer.qor1), provenKey(relayer), readEvmWindow(relayer.qor1)]);
    console.log(`relayer:   ${relayer.qor1} / ${relayer.evm}`);
    console.log(`balance:   ${formatQor(balance)} QOR`);
    console.log(`ML-DSA-87: ${keyed ? "registered, this phrase's key, possession proven" : "not registered"}`);
    console.log(`window:    before: ${describeWindow(window)}`);
    if (balance < MIN_BALANCE_UQOR) missing.push(`funds: the relayer holds ${formatQor(balance)} QOR; send at least ${formatQor(MIN_BALANCE_UQOR - balance)} QOR more to ${relayer.qor1}`);
    if (!keyed) missing.push(`key: the relayer's ML-DSA-87 key is not registered with possession proven at ${relayer.qor1}`);
  } else {
    missing.push(`RELAYER_MNEMONIC is not set to 24 valid words in ${SERVER_ENV}. Run: npx tsx scripts/new-relayer.ts`);
  }

  const chairPhrase = existsSync(CONTRACTS_ENV) ? parseEnv(readFileSync(CONTRACTS_ENV, "utf8")).PROVE_CHAIR_MNEMONIC : undefined;
  let chair: Identity | undefined;
  if (chairPhrase === undefined || chairPhrase.trim() === "") {
    missing.push(`PROVE_CHAIR_MNEMONIC is not in ${CONTRACTS_ENV}. Run the registry proof first.`);
  } else {
    chair = await identityFromMnemonic(canonicalPhrase(chairPhrase));
    console.log(`chair:     ${chair.evm} (the registry proof's chair, read from packages/contracts/.env)`);
  }

  if (relayer !== undefined && chair !== undefined) {
    const deployer = (JSON.parse(readFileSync(DEPLOYMENTS, "utf8")) as { BoardRegistry: { deployer: string } }).BoardRegistry.deployer;
    const own = !sameAccount(relayer.qor1, chair.qor1) && !sameAccount(relayer.qor1, deployer);
    console.log(`accounts:  the relayer is ${own ? "its own account, not the chair and not the deployer" : "NOT its own account"}`);
    if (!own) throw new Error("The relayer shares an account with the chair or the deployer. Stopping.");
  }

  if (missing.length > 0 || env === undefined || relayer === undefined || chair === undefined) {
    console.log("missing:");
    for (const line of missing) console.log(`  - ${line}`);
    console.log("Nothing was sent.");
    return;
  }

  const ok = await relayOneRotation(env, relayer, chair, client);
  console.log(`window:    after: ${describeWindow(await readEvmWindow(relayer.qor1))}`);
  console.log(`result:    ${ok ? "one rotateEpoch relayed from the relayer's own account and confirmed on chain" : "FAILED"}`);
  if (!ok) process.exitCode = 1;
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
