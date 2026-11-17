import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { clearPqcStatusCache, fetchEvmWindow, fetchPqcStatus, isRegisteredPqcKey, openEvmWindowMsg, postJsonRpc, toChecksumAddress, withRetry } from "@qorechain/sdk";
import { evmWindowCost } from "@qorechain/evm";
import { mldsa } from "@qorechain/pqc";
import { generateSealKeys, isQoreSealError, open, seal, validateMlkemPublicKey } from "@qorechain/qoreseal";
import {
  BaseError,
  ContractFunctionRevertedError,
  bytesToHex,
  decodeAbiParameters,
  encodeAbiParameters,
  encodeFunctionData,
  hexToBytes,
  keccak256,
  parseEventLogs,
  toBytes,
  type Abi,
  type Hex,
  type PublicClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { deriveDeployer, sameAccount, type Deployer } from "./account.js";
import { assertTestnet, evmClient } from "./chain.js";
import { CHAIN_ID, DEPLOYMENTS_PATH, EVM_CHAIN_ID, EVM_RPC, EXPLORER, HTTP, PROBE_ARTIFACT_PATH, REST, requireMnemonic } from "./env.js";
import { sendTx } from "./tx.js";

const PQC_STATUS = "0x0000000000000000000000000000000000000a02";
const PURPOSE = "ava.m1.probe";
const DOMAIN_TAG = "ava.probe.v1";
const ML_DSA_87_SIGNATURE_LENGTH = 4627;
const ML_KEM_1024_PUBLIC_KEY_LENGTH = 1568;

// Each window admits exactly the one EVM transaction it was opened for, for
// about five minutes at 1.4 s blocks, and no more value than that transaction can spend.
const WINDOW_BLOCKS = 200;
const WINDOW_TXS = 1;
const WAIT_AFTER_WINDOW_MS = 10_000;
const GAS_HEADROOM_PERCENT = 125n;
// The testnet base fee is 100 gwei. A fee cap above this means something is wrong, so stop.
const MAX_FEE_PER_GAS_CEILING = 500_000_000_000n;

interface Artifact {
  abi: Abi;
  bytecode: Hex;
  deployedBytecode: Hex;
}

interface Deployment {
  network: string;
  evmChainId: number;
  PqcProbe: { address: Hex; deployTx: Hex; blockNumber: string; deployer: Hex };
}

type CallOutcome = { passes: true } | { passes: false; error: string };

// The EVM JSON-RPC reports contract and log addresses in lowercase, which carries no checksum.
// They come from the chain, not from a person, so they are put in EIP-55 form before the shared codec sees them.
const fromRpc = (address: string): Hex => toChecksumAddress(address) as Hex;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function sha256(bytes: Uint8Array): Hex {
  return `0x${createHash("sha256").update(bytes).digest("hex")}`;
}

function loadArtifact(): Artifact {
  if (!existsSync(PROBE_ARTIFACT_PATH)) throw new Error(`No build output at ${PROBE_ARTIFACT_PATH}. Run: forge build`);
  const json = JSON.parse(readFileSync(PROBE_ARTIFACT_PATH, "utf8")) as { abi?: unknown; bytecode?: { object?: unknown }; deployedBytecode?: { object?: unknown } };
  const hex = (v: unknown, what: string): Hex => {
    if (typeof v !== "string" || !/^0x[0-9a-f]{2,}$/i.test(v)) throw new Error(`The build output has no ${what}.`);
    return v as Hex;
  };
  if (!Array.isArray(json.abi)) throw new Error("The build output has no ABI.");
  return { abi: json.abi as Abi, bytecode: hex(json.bytecode?.object, "bytecode"), deployedBytecode: hex(json.deployedBytecode?.object, "deployed bytecode") };
}

function loadDeployment(): Deployment | undefined {
  if (!existsSync(DEPLOYMENTS_PATH)) return undefined;
  const d = JSON.parse(readFileSync(DEPLOYMENTS_PATH, "utf8")) as Deployment;
  if (d.network !== CHAIN_ID || d.evmChainId !== EVM_CHAIN_ID || !/^0x[0-9a-fA-F]{40}$/.test(d.PqcProbe?.address ?? "") || !/^0x[0-9a-f]{64}$/.test(d.PqcProbe?.deployTx ?? "")) {
    throw new Error(`${DEPLOYMENTS_PATH} is not a testnet PqcProbe record. Refusing to guess.`);
  }
  return d;
}

/** EIP-1559 fees fixed once per transaction, so the window is sized for exactly what the transaction may spend. */
async function fees(client: PublicClient): Promise<{ maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }> {
  const [block, maxPriorityFeePerGas] = await Promise.all([client.getBlock({ blockTag: "latest" }), client.estimateMaxPriorityFeePerGas()]);
  if (block.baseFeePerGas === null) throw new Error("The latest block carries no base fee.");
  const maxFeePerGas = block.baseFeePerGas * 2n + maxPriorityFeePerGas;
  if (maxFeePerGas > MAX_FEE_PER_GAS_CEILING) throw new Error(`Fee cap ${maxFeePerGas} wei per gas is above the ${MAX_FEE_PER_GAS_CEILING} ceiling. Stopping.`);
  return { maxFeePerGas, maxPriorityFeePerGas };
}

/**
 * Opens an EVM window for one transaction, checks the chain stored exactly
 * that scope, then waits before the EVM transaction is signed (opening the
 * window moves the account nonce).
 */
async function openWindow(deployer: Deployer, maxValue: bigint, allowedTargets: Hex[]): Promise<string> {
  const message = openEvmWindowMsg({ sender: deployer.qor1, blocks: WINDOW_BLOCKS, maxTxs: WINDOW_TXS, maxValue, allowedTargets });
  const tx = await sendTx(deployer, "hybrid", [message], "");
  const window = await fetchEvmWindow({ rest: REST, address: deployer.qor1 });
  const scopeMatches =
    window.allowedTargets.length === allowedTargets.length && window.allowedTargets.every((t, i) => Buffer.from(hexToBytes(t as Hex)).equals(Buffer.from(hexToBytes(allowedTargets[i]!))));
  if (!window.found || !window.live || window.nativeOnly || window.remainingTxs !== BigInt(WINDOW_TXS) || window.remainingValue !== maxValue || !scopeMatches) {
    throw new Error(`The window opened in ${tx.hash} is not the one asked for. Stopping before any EVM transaction.`);
  }
  await sleep(WAIT_AFTER_WINDOW_MS);
  return tx.hash;
}

/**
 * Signs one EVM transaction locally and broadcasts it once. The hash is known
 * before sending, so a dropped connection is answered by looking the hash up,
 * never by sending again.
 */
async function sendEvm(client: PublicClient, deployer: Deployer, tx: { to?: Hex; data: Hex; gas: bigint; maxFeePerGas: bigint; maxPriorityFeePerGas: bigint }) {
  const signer = privateKeyToAccount(deployer.privateKey);
  const nonce = await client.getTransactionCount({ address: deployer.evm, blockTag: "pending" });
  const serialized = await signer.signTransaction({ type: "eip1559", chainId: EVM_CHAIN_ID, nonce, value: 0n, ...tx });
  const hash = keccak256(serialized);
  try {
    await client.sendRawTransaction({ serializedTransaction: serialized });
  } catch (err) {
    const reason = err instanceof Error ? err.message.split("\n")[0]!.slice(0, 200) : "unknown error";
    console.log(`  broadcast of ${hash} did not confirm (${reason}); looking it up on chain.`);
    // A refusal means the node never took it; a lost answer means it may still be pending.
    const seen = await withRetry(() => client.getTransaction({ hash }), { retries: 5, backoff: 2_000 }).catch(() => undefined);
    if (seen === undefined) throw new Error(`EVM transaction ${hash} was refused and is not on chain: ${reason}`);
  }
  const receipt = await client.waitForTransactionReceipt({ hash, timeout: 90_000, pollingInterval: 2_000 });
  return { hash, receipt };
}

async function recordCall(client: PublicClient, probe: Hex, abi: Abi, from: Hex, args: readonly [Hex, Hex, Hex]): Promise<CallOutcome> {
  try {
    await client.simulateContract({ address: probe, abi, functionName: "record", args, account: from });
    return { passes: true };
  } catch (err) {
    const reverted = err instanceof BaseError ? err.walk((e) => e instanceof ContractFunctionRevertedError) : undefined;
    if (reverted instanceof ContractFunctionRevertedError && reverted.data?.errorName !== undefined) {
      return { passes: false, error: `${reverted.data.errorName}(${(reverted.data.args ?? []).map(String).join(", ")})` };
    }
    throw err;
  }
}

function flipOneByte(signature: Uint8Array, offset: number): Uint8Array {
  const copy = Uint8Array.from(signature);
  copy[offset] = copy[offset]! ^ 0x01;
  return copy;
}

/**
 * Reads the deployer's ML-KEM key from the public EVM JSON-RPC and returns it
 * only if it is the key for exactly this account (compared as 20 bytes),
 * algorithm 2, 1,568 bytes, and accepted by QoreSeal's own key check.
 */
async function readKemKey(deployer: Deployer): Promise<Uint8Array> {
  const body = await postJsonRpc<{ result?: Record<string, unknown>; error?: unknown }>(
    EVM_RPC,
    { jsonrpc: "2.0", id: 1, method: "qor_getKEMKey", params: [deployer.evm] },
    HTTP,
  );
  const r = body.result;
  if (body.error !== undefined || r === undefined || r === null || typeof r !== "object") throw new Error("qor_getKEMKey gave no result. Stopping the seal.");
  if (r.found !== true) throw new Error("qor_getKEMKey reports no KEM key for the deployer. Stopping the seal.");
  if (typeof r.address !== "string" || !sameAccount(r.address, deployer.evm)) throw new Error("qor_getKEMKey answered for a different account. Stopping the seal.");
  if (r.algorithm_id !== 2) throw new Error(`qor_getKEMKey reports algorithm ${String(r.algorithm_id)}, not 2 (ML-KEM-1024). Stopping the seal.`);
  if (typeof r.public_key !== "string" || !/^0x([0-9a-fA-F]{2})+$/.test(r.public_key)) throw new Error("qor_getKEMKey returned no hex key. Stopping the seal.");
  const key = hexToBytes(r.public_key as Hex);
  if (key.length !== ML_KEM_1024_PUBLIC_KEY_LENGTH) throw new Error(`The KEM key is ${key.length} bytes, not ${ML_KEM_1024_PUBLIC_KEY_LENGTH}. Stopping the seal.`);
  validateMlkemPublicKey(key);
  return key;
}

async function checkPqKey(client: PublicClient, deployer: Deployer): Promise<void> {
  clearPqcStatusCache();
  const rest = await fetchPqcStatus({ rest: REST, address: deployer.qor1 });
  if (!rest.registered || isRegisteredPqcKey(rest, deployer.pqc.publicKey) !== true || rest.possessionProven !== true) {
    throw new Error("The deployer's ML-DSA-87 key is not registered as this phrase's key with possession proven. Run: npm run register-deployer");
  }
  const raw = await client.call({ to: PQC_STATUS, data: encodeFunctionData({ abi: STATUS_ABI, functionName: "pqcKeyStatus", args: [deployer.evm] }) });
  if (raw.data === undefined || raw.data.length < 2 + 160 * 2) throw new Error("pqcKeyStatus answered with empty or short data.");
  const [registered, algorithmId, pubkey, proven] = decodeAbiParameters(STATUS_ABI[0].outputs, raw.data);
  if (!registered || algorithmId !== 1 || !proven || !Buffer.from(hexToBytes(pubkey)).equals(Buffer.from(deployer.pqc.publicKey))) {
    throw new Error("The pqcKeyStatus precompile does not report this phrase's key, algorithm 1, possession proven.");
  }
  console.log("PQ key:     found, possession_proven true, this phrase's ML-DSA-87 key (REST)");
  console.log("            pqcKeyStatus precompile agrees: registered, algorithm 1, 2592-byte key equal to ours, possessionProven true");
}

const STATUS_ABI = [
  {
    type: "function",
    name: "pqcKeyStatus",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [
      { name: "registered", type: "bool" },
      { name: "algorithmId", type: "uint8" },
      { name: "pubkey", type: "bytes" },
      { name: "possessionProven", type: "bool" },
    ],
  },
] as const;

function sealSection(deployer: Deployer, kemKey: Uint8Array): Uint8Array {
  console.log("\nSEAL");
  const plaintext = new Uint8Array([...new TextEncoder().encode(`Ava M1 probe payload, ${new Date().toISOString()}, `), ...randomBytes(64)]);
  const envelope = seal({ chainId: CHAIN_ID, purpose: PURPOSE, recipients: [{ mlkemPublicKey: kemKey }], plaintext, mode: "mlkem" });
  console.log(`  payload:  ${plaintext.length} bytes, sha256 ${sha256(plaintext)}`);
  console.log(`  sealed:   ${envelope.length}-byte envelope (mlkem mode, 1 recipient) to the deployer's on-chain KEM key read via qor_getKEMKey; chain ${CHAIN_ID}, purpose "${PURPOSE}"`);

  const opened = open({ chainId: CHAIN_ID, purpose: PURPOSE, envelope, keys: deployer.seal });
  const equal = Buffer.from(opened).equals(Buffer.from(plaintext));
  console.log(`  opened:   by the deployer's secret key; bytes equal: ${equal ? "yes" : "NO"}`);
  if (!equal) throw new Error("The opened bytes differ from the payload.");

  let strangerResult: string;
  try {
    open({ chainId: CHAIN_ID, purpose: PURPOSE, envelope, keys: generateSealKeys() });
    strangerResult = "OPENED";
  } catch (err) {
    strangerResult = isQoreSealError(err) ? err.code : `unexpected error: ${err instanceof Error ? err.message.slice(0, 120) : String(err)}`;
  }
  console.log(`  stranger: a fresh unregistered QoreSeal key pair fails to open it: ${strangerResult}`);
  if (strangerResult !== "NOT_A_RECIPIENT") throw new Error("A key pair that is not a recipient did not fail with NOT_A_RECIPIENT.");
  return envelope;
}

async function deployOrLoad(client: PublicClient, deployer: Deployer, artifact: Artifact): Promise<{ probe: Hex; deployTx: Hex; fresh: boolean }> {
  const recorded = loadDeployment();
  if (recorded !== undefined) {
    const code = await client.getCode({ address: recorded.PqcProbe.address });
    if (code === undefined || code.toLowerCase() !== artifact.deployedBytecode.toLowerCase()) {
      throw new Error(`The contract recorded in ${DEPLOYMENTS_PATH} does not carry the code of the current build. Refusing to use it.`);
    }
    return { probe: fromRpc(recorded.PqcProbe.address), deployTx: recorded.PqcProbe.deployTx, fresh: false };
  }

  const gas = ((await client.estimateGas({ account: deployer.evm, data: artifact.bytecode })) * GAS_HEADROOM_PERCENT + 99n) / 100n;
  const fee = await fees(client);
  const cost = evmWindowCost({ gas, maxFeePerGas: fee.maxFeePerGas });
  const windowTx = await openWindow(deployer, cost, []);
  console.log(`  window:   unscoped (contract creation needs it), ${WINDOW_TXS} tx, ${WINDOW_BLOCKS} blocks, max_value ${cost} uqor from evmWindowCost; opened in ${windowTx}`);

  const { hash, receipt } = await sendEvm(client, deployer, { data: artifact.bytecode, gas, ...fee });
  if (receipt.status !== "success" || receipt.contractAddress == null) throw new Error(`Deploy ${hash} did not succeed.`);
  const probe = fromRpc(receipt.contractAddress);
  const code = await client.getCode({ address: probe });
  if (code === undefined || code.toLowerCase() !== artifact.deployedBytecode.toLowerCase()) throw new Error("The deployed code differs from the build.");

  const record: Deployment = {
    network: CHAIN_ID,
    evmChainId: EVM_CHAIN_ID,
    PqcProbe: { address: probe, deployTx: hash, blockNumber: receipt.blockNumber.toString(), deployer: deployer.evm },
  };
  mkdirSync(dirname(DEPLOYMENTS_PATH), { recursive: true });
  writeFileSync(DEPLOYMENTS_PATH, `${JSON.stringify(record, null, 2)}\n`, "utf8");
  console.log(`  deployed: block ${receipt.blockNumber}, gas used ${receipt.gasUsed}`);
  return { probe, deployTx: hash, fresh: true };
}

async function probeSection(client: PublicClient, deployer: Deployer, envelope: Uint8Array): Promise<void> {
  console.log("\nPROBE");
  const artifact = loadArtifact();
  const { probe, deployTx, fresh } = await deployOrLoad(client, deployer, artifact);
  console.log(`  contract: ${probe} (${fresh ? "deployed in this run" : `recorded in deployments/testnet.json`}); code equals the current build: yes`);
  console.log(`  deploy tx: ${deployTx}`);
  const abi = artifact.abi;
  const digest = sha256(envelope);

  const blockNumber = await client.getBlockNumber();
  const [nonce, onChain] = await Promise.all([
    client.readContract({ address: probe, abi, functionName: "nonces", args: [deployer.evm], blockNumber }) as Promise<bigint>,
    client.readContract({ address: probe, abi, functionName: "messageFor", args: [deployer.evm, digest], blockNumber }) as Promise<Hex>,
  ]);
  const local = encodeAbiParameters(
    [{ type: "bytes32" }, { type: "uint256" }, { type: "address" }, { type: "address" }, { type: "bytes32" }, { type: "uint256" }],
    [keccak256(toBytes(DOMAIN_TAG)), BigInt(EVM_CHAIN_ID), probe, deployer.evm, digest, nonce],
  );
  const message = hexToBytes(onChain);
  if (onChain.toLowerCase() !== local.toLowerCase() || message.length !== 192) throw new Error("messageFor differs from the specified encoding. Stopping.");
  if (message[0] === 0x71) throw new Error("The message starts with q. Stopping.");
  console.log(`  digest:   ${digest} (sha256 of the sealed envelope)`);
  console.log(`  message:  192 bytes from messageFor at block ${blockNumber} (nonce ${nonce}); equals the script's own abi.encode: yes; first byte 0x${message[0]!.toString(16)}`);

  const signature = mldsa.sign(deployer.pqc.secretKey, message);
  if (signature.length !== ML_DSA_87_SIGNATURE_LENGTH || !mldsa.verify(deployer.pqc.publicKey, message, signature)) throw new Error("The local ML-DSA-87 signature is not 4,627 bytes or does not verify.");
  console.log(`  signed:   ${signature.length}-byte ML-DSA-87 signature over exactly those bytes with the deployer's key; verifies locally: yes`);

  const args = (sig: Uint8Array) => [deployer.evm, digest, bytesToHex(sig)] as const;
  const flipAt = 100;
  const [exact, preTampered] = await Promise.all([
    recordCall(client, probe, abi, deployer.evm, args(signature)),
    recordCall(client, probe, abi, deployer.evm, args(flipOneByte(signature, flipAt))),
  ]);
  if (!exact.passes || preTampered.passes || !preTampered.error.startsWith("BadSignature")) {
    throw new Error(`Pre-flight failed: exact call ${exact.passes ? "passes" : exact.error}, flipped ${preTampered.passes ? "passes" : preTampered.error}. Nothing was sent.`);
  }
  console.log(`  pre-flight: eth_call of the exact record call passes; the same call with one byte flipped reverts ${preTampered.error}`);

  const data = encodeFunctionData({ abi, functionName: "record", args: args(signature) });
  const gas = ((await client.estimateGas({ account: deployer.evm, to: probe, data })) * GAS_HEADROOM_PERCENT + 99n) / 100n;
  const fee = await fees(client);
  const cost = evmWindowCost({ gas, maxFeePerGas: fee.maxFeePerGas });
  const windowTx = await openWindow(deployer, cost, [probe]);
  console.log(`  window:   allowed_targets [${probe}], ${WINDOW_TXS} tx, ${WINDOW_BLOCKS} blocks, max_value ${cost} uqor from evmWindowCost; opened in ${windowTx}`);

  const { hash, receipt } = await sendEvm(client, deployer, { to: probe, data, gas, ...fee });
  if (receipt.status !== "success") throw new Error(`Record ${hash} reverted.`);
  const events = parseEventLogs({ abi, logs: receipt.logs, eventName: "Recorded" }).filter((l) => sameAccount(fromRpc(l.address), probe));
  const event = events.length === 1 ? (events[0]!.args as { signer: Hex; digest: Hex; nonce: bigint }) : undefined;
  if (event === undefined || !sameAccount(event.signer, deployer.evm) || event.digest.toLowerCase() !== digest || event.nonce !== nonce) {
    throw new Error(`Record ${hash} succeeded without exactly one Recorded event for this signer, digest and nonce.`);
  }
  console.log(`  record tx: ${hash}`);
  console.log(`  result:   code success, block ${receipt.blockNumber}, gas used ${receipt.gasUsed}`);
  console.log(`  event:    Recorded(signer ${event.signer}, digest ${event.digest}, nonce ${event.nonce})`);
  const after = (await client.readContract({ address: probe, abi, functionName: "nonces", args: [deployer.evm] })) as bigint;
  if (after !== nonce + 1n) throw new Error(`The nonce is ${after}, expected ${nonce + 1n}.`);
  console.log(`  nonce:    now ${after}`);

  const current = hexToBytes((await client.readContract({ address: probe, abi, functionName: "messageFor", args: [deployer.evm, digest] })) as Hex);
  const fresh2 = mldsa.sign(deployer.pqc.secretKey, current);
  const [control, tampered, replay] = await Promise.all([
    recordCall(client, probe, abi, deployer.evm, args(fresh2)),
    recordCall(client, probe, abi, deployer.evm, args(flipOneByte(fresh2, flipAt))),
    recordCall(client, probe, abi, deployer.evm, args(signature)),
  ]);
  if (!control.passes) throw new Error(`A fresh signature over the current message should pass eth_call but got ${control.error}.`);
  if (tampered.passes || !tampered.error.startsWith("BadSignature")) throw new Error(`The tampered signature was not refused with BadSignature (${tampered.passes ? "passes" : tampered.error}).`);
  if (replay.passes || !replay.error.startsWith("BadSignature")) throw new Error(`The replay was not refused with BadSignature (${replay.passes ? "passes" : replay.error}).`);
  console.log(`  tampered: a fresh signature over the current message (nonce ${after}) passes eth_call; the same signature with byte ${flipAt} flipped is refused by eth_call: ${tampered.error}`);
  console.log(`  replay:   the first signature (nonce ${nonce}) sent again is refused by eth_call: ${replay.error}`);

  const window = await fetchEvmWindow({ rest: REST, address: deployer.qor1 });
  console.log(`  window after: ${window.remainingTxs} txs left, ${window.remainingValue} uqor left`);
  console.log(`  explorer: ${EXPLORER} (switch to Testnet) and search ${probe}`);
}

async function main(): Promise<void> {
  const chainId = await assertTestnet();
  console.log(`chain id:   ${chainId} confirmed (EVM chain id ${EVM_CHAIN_ID})`);

  const deployer = await deriveDeployer(requireMnemonic());
  if (!sameAccount(privateKeyToAccount(deployer.privateKey).address, deployer.qor1)) throw new Error("The EVM signing key is not the deployer's account.");
  console.log(`deployer:   ${deployer.qor1} / ${deployer.evm}`);

  const client = evmClient();
  await checkPqKey(client, deployer);
  const kemKey = await readKemKey(deployer);
  const ours = Buffer.from(kemKey).equals(Buffer.from(deployer.seal.mlkemPublicKey));
  console.log(`KEM key:    found via qor_getKEMKey on ${EVM_RPC}: account matches as 20 bytes, algorithm 2, ${kemKey.length} bytes, validateMlkemPublicKey accepts it, this phrase's key: ${ours ? "yes" : "NO"}`);
  if (!ours) throw new Error("The on-chain KEM key is not this phrase's key.");

  const envelope = sealSection(deployer, kemKey);
  await probeSection(client, deployer, envelope);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
