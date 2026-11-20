import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { parseEnv } from "node:util";
import { KemKeyUnavailable, canonicalPhrase, fetchKemKey, generateMnemonic, sameAccount, type KemRecipient } from "@ava/core";
import {
  buildRegisterPqcKeyMsg,
  clearPqcStatusCache,
  fetchKemKey as fetchKemKeyRest,
  fetchPqcStatus,
  isRegisteredPqcKey,
  msg,
  qorechainRegistry,
  signProofOfPossession,
  verifyProofOfPossession,
  withRetry,
  type KemKeyResult,
  type PqcStatus,
} from "@qorechain/sdk";
import { buildRegisterKemKeyMessage } from "@qorechain/qoreseal";
import { decodeAbiParameters, encodeFunctionData, hexToBytes, type Hex, type PublicClient } from "viem";
import { deriveDeployer, type Deployer } from "../account.js";
import { CHAIN_ID, DENOM, ENV_PATH, REST } from "../env.js";
import { MAX_FEE_UQOR, REGISTRATION_FEE, sendTx, type Messages } from "../tx.js";
import { assertBudget, balanceOf, formatQor } from "./evm.js";

/** The three test identities of the registry proof and the .env variable that holds each phrase. */
export const IDENTITY_VARS = { chair: "PROVE_CHAIR_MNEMONIC", dana: "PROVE_DANA_MNEMONIC", eli: "PROVE_ELI_MNEMONIC" } as const;
export type Role = keyof typeof IDENTITY_VARS;

/** What the deployer sends each new identity, once, by a hybrid MsgSend. */
export const FUNDING_UQOR = 400_000n;
const PQ_FEE_UQOR = BigInt(REGISTRATION_FEE.amount[0]!.amount);
const MNEMONIC_WORDS = 24;
const PQC_STATUS = "0x0000000000000000000000000000000000000a02";

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

export interface IdentitySetup {
  role: Role;
  account: Deployer;
  /** What the deployer spent funding it in this run: the amount sent plus the send's fee, in uqor. */
  fundingSpentUqor: bigint;
}

/**
 * Reads one identity phrase from the environment, or writes a fresh one into .env when the
 * variable has no line there. Either way the phrase comes back in @ava/core's canonicalPhrase
 * form, the rule the app derives from (threat model C16). Messages name the variable, never its
 * value.
 */
function ensureMnemonic(name: string): { mnemonic: string; created: boolean } {
  const raw = process.env[name];
  if (raw !== undefined && raw.trim() !== "") {
    try {
      return { mnemonic: canonicalPhrase(raw), created: false };
    } catch {
      throw new Error(`${name} in ${ENV_PATH} is not a valid ${MNEMONIC_WORDS}-word BIP-39 phrase.`);
    }
  }
  const existing = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
  // An empty line for the name counts: a second line would leave it to the parser which one wins.
  if (new RegExp(`^\\s*(export\\s+)?${name}\\s*=`, "m").test(existing)) {
    throw new Error(`${ENV_PATH} has an empty ${name} line. Delete the line to have a new identity made, or fill it.`);
  }
  const mnemonic = generateMnemonic();
  // canonicalPhrase throws a message that never repeats the phrase, so nothing is caught here.
  if (canonicalPhrase(mnemonic) !== mnemonic) throw new Error("The new phrase is not in canonical form. Nothing was written.");
  const lead = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
  appendFileSync(ENV_PATH, `${lead}${name}="${mnemonic}"\n`, { encoding: "utf8", mode: 0o600 });
  if (parseEnv(readFileSync(ENV_PATH, "utf8"))[name] !== mnemonic) {
    throw new Error(`Read-back of ${name} from ${ENV_PATH} does not give the phrase just written. Delete that line and run again.`);
  }
  process.env[name] = mnemonic;
  return { mnemonic, created: true };
}

function isOurKemKey(kem: KemKeyResult, account: Deployer): boolean {
  return (
    kem.found &&
    kem.key !== undefined &&
    sameAccount(kem.key.address, account.qor1) &&
    kem.key.algorithmId === 2 &&
    Buffer.from(kem.key.publicKey).equals(Buffer.from(account.seal.mlkemPublicKey))
  );
}

function isOurProvenPqKey(pqc: PqcStatus, account: Deployer): boolean {
  return pqc.registered && isRegisteredPqcKey(pqc, account.pqc.publicKey) === true && pqc.possessionProven === true;
}

async function readPqc(address: string): Promise<PqcStatus> {
  clearPqcStatusCache();
  return fetchPqcStatus({ rest: REST, address });
}

function pqKeyMessages(account: Deployer): Messages {
  const proof = signProofOfPossession({ chainId: CHAIN_ID, account: account.qor1, keypair: account.pqc });
  if (!verifyProofOfPossession({ chainId: CHAIN_ID, account: account.qor1, publicKey: account.pqc.publicKey, proof })) {
    throw new Error("The proof of possession does not verify locally. Refusing to send a registration the chain would refuse after taking the fee.");
  }
  // The organisers' example leaves ecdsa_pubkey empty: the chain binds the key of the transaction's signer.
  return [buildRegisterPqcKeyMsg(account.qor1, { pqcKeypair: account.pqc, proofOfPossession: proof })];
}

function kemKeyMessages(account: Deployer): Messages {
  const message = msg.pqc.registerKemKey({ sender: account.qor1, publicKey: account.seal.mlkemPublicKey });
  // The SDK message is the one its registry can sign; QoreSeal's builder is the reference encoding.
  const reference = buildRegisterKemKeyMessage({ sender: account.qor1, mlkemPublicKey: account.seal.mlkemPublicKey });
  if (message.typeUrl !== reference.typeUrl || !Buffer.from(qorechainRegistry().encode(message)).equals(Buffer.from(reference.value))) {
    throw new Error("The SDK and QoreSeal encode the KEM registration differently. Refusing to send.");
  }
  return [message];
}

async function waitFor(what: string, check: () => Promise<boolean>): Promise<void> {
  await withRetry(
    async () => {
      if (!(await check())) throw new Error(`${what} not visible yet`);
    },
    { retries: 8, backoff: 2_000, maxBackoff: 6_000 },
  );
}

/**
 * Makes one test identity ready: its phrase in .env, its account funded once with FUNDING_UQOR,
 * and its ML-DSA-87 and ML-KEM-1024 keys registered the way scripts/register-deployer.ts
 * registers the deployer's. Each part runs only when the chain shows it is missing.
 *
 * @throws When the account holds a key that is not this phrase's, the budget guard stops the
 *   funding, or a registration fails or never becomes visible.
 */
export async function ensureIdentity(role: Role, deployer: Deployer, log: (line: string) => void): Promise<IdentitySetup> {
  const name = IDENTITY_VARS[role];
  const { mnemonic, created } = ensureMnemonic(name);
  const account = await deriveDeployer(mnemonic);
  if (created) log(`  ${role}: new unified coin-60 identity written to .env as ${name} (the phrase is never shown)`);

  const [balance, pqc, kem] = await Promise.all([balanceOf(account.qor1), readPqc(account.qor1), fetchKemKeyRest({ rest: REST, address: account.qor1 })]);
  if (pqc.registered && !isOurProvenPqKey(pqc, account)) {
    throw new Error(`${role} has an ML-DSA-87 key that is not this phrase's key with possession proven. Refusing: a second registration is refused after the fee is taken.`);
  }
  if (kem.found && !isOurKemKey(kem, account)) throw new Error(`${role} already publishes a KEM key that is not this phrase's key. Refusing to replace it.`);
  const needPq = !pqc.registered;
  const needKem = !kem.found;

  let fundingSpentUqor = 0n;
  const needed = (needPq ? PQ_FEE_UQOR : 0n) + (needKem ? MAX_FEE_UQOR : 0n);
  if (needed > 0n && balance < needed) {
    await assertBudget(deployer, FUNDING_UQOR + MAX_FEE_UQOR, `funding ${role}`);
    const send = msg.bank.send({ fromAddress: deployer.qor1, toAddress: account.qor1, amount: [{ denom: DENOM, amount: FUNDING_UQOR.toString() }] });
    const tx = await sendTx(deployer, "hybrid", [send], "");
    await waitFor(`${role} funding`, async () => (await balanceOf(account.qor1)) >= balance + FUNDING_UQOR);
    const fee = BigInt(tx.fee.amount[0]!.amount);
    fundingSpentUqor = FUNDING_UQOR + fee;
    log(`  ${role}: funded ${formatQor(FUNDING_UQOR)} QOR by the deployer, hybrid MsgSend ${tx.hash} (fee ${formatQor(fee)} QOR, pqc_hybrid_verify verified)`);
  }
  if (needPq) {
    const tx = await sendTx(account, "classical", pqKeyMessages(account), "", REGISTRATION_FEE);
    await waitFor(`${role} ML-DSA-87 key`, async () => isOurProvenPqKey(await readPqc(account.qor1), account));
    log(`  ${role}: ML-DSA-87 key registered with MsgRegisterPQCKeyV2 in ${tx.hash} (gas used ${tx.gasUsed} of ${tx.gasWanted})`);
  }
  if (needKem) {
    const tx = await sendTx(account, "hybrid", kemKeyMessages(account), "");
    await waitFor(`${role} ML-KEM-1024 key`, async () => isOurKemKey(await fetchKemKeyRest({ rest: REST, address: account.qor1 }), account));
    log(`  ${role}: ML-KEM-1024 key registered with MsgRegisterKEMKey in ${tx.hash} (gas used ${tx.gasUsed} of ${tx.gasWanted}, pqc_hybrid_verify verified)`);
  }
  return { role, account, fundingSpentUqor };
}

/** True when the REST status shows this phrase's ML-DSA-87 key with possession proven. */
export async function restShowsProvenKey(account: Deployer): Promise<boolean> {
  return isOurProvenPqKey(await readPqc(account.qor1), account);
}

/** What the registry itself reads: the pqcKeyStatus precompile's answer for the account's 0x form. */
export async function precompileKeyStatus(client: PublicClient, address: Hex): Promise<{ registered: boolean; algorithmId: number; pubkey: Uint8Array; possessionProven: boolean }> {
  const raw = await client.call({ to: PQC_STATUS, data: encodeFunctionData({ abi: STATUS_ABI, functionName: "pqcKeyStatus", args: [address] }) });
  if (raw.data === undefined || raw.data.length < 2 + 160 * 2) throw new Error("pqcKeyStatus answered with empty or short data.");
  const [registered, algorithmId, pubkey, possessionProven] = decodeAbiParameters(STATUS_ABI[0].outputs, raw.data);
  return { registered, algorithmId, pubkey: hexToBytes(pubkey), possessionProven };
}

/**
 * The account and the ML-KEM-1024 key qor_getKEMKey publishes for it, as one KemRecipient pair from
 * @ava/core's fetchKemKey (threat model C15), so a seal names only the account the key was read for.
 * Only a dropped connection or a timeout is retried; every other refusal stops at once.
 */
export async function kemRecipientOf(address: string): Promise<KemRecipient> {
  return withRetry(() => fetchKemKey(address), {
    retries: 4,
    backoff: 2_000,
    maxBackoff: 6_000,
    shouldRetry: (err) => err instanceof KemKeyUnavailable && (err.reason === "NETWORK" || err.reason === "TIMEOUT"),
  });
}
