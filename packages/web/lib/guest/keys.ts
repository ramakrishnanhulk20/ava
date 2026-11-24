import { CHAIN_ID, KemKeyUnavailable, ML_DSA_87_PUBKEY, fetchKemKey } from "@ava/core";
import { buildRegisterPqcKeyMsg, msg, signProofOfPossession, verifyProofOfPossession } from "@qorechain/sdk";
import { decodeAbiParameters, encodeFunctionData, hexToBytes } from "viem";
import { client } from "../chain";
import type { GuestAccount } from "./identity";
import { sendNative, type CommittedTx } from "./native";
import { pause, startDeadline, type Deadline } from "./time";

/**
 * The fees the server's own registrations use (packages/server/src/config.ts): the ML-DSA-87 key at
 * the organisers' Workshop 1 example, the ML-KEM-1024 key at 450,000 gas and 0.15 uqor per gas.
 * Together 0.1675 QOR, inside the sponsor's 0.25 QOR.
 */
export const KEY_REGISTRATION_FEE = { amount: [{ denom: "uqor", amount: "100000" }], gas: "800000" };
export const KEM_REGISTRATION_FEE = { amount: [{ denom: "uqor", amount: "67500" }], gas: "450000" };
export const KEY_REGISTRATION_UQOR = 100_000n;
export const KEM_REGISTRATION_UQOR = 67_500n;

/** As live-demo-check.ts gives each registration: two minutes from signing to its block. */
const SEND_BUDGET_MS = 120_000;
const KEYS_POLL_MS = 2_000;
const KEYS_WAIT_MS = 60_000;

/**
 * The pqcKeyStatus precompile with all four return values, as packages/contracts/src/interfaces/
 * IQorePQC.sol declares them; the @qorechain/evm helper drops possessionProven.
 */
const PQC_STATUS_ADDRESS = "0x0000000000000000000000000000000000000a02";
const PQC_STATUS_ABI = [
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
/** An inactive precompile answers success with empty data, so a shorter answer is refused too. */
const MIN_STATUS_BYTES = 160;
const ML_DSA_87 = 1;

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/**
 * Whether pqcKeyStatus on the public EVM RPC shows this guest's own ML-DSA-87 key registered with
 * possession proven: all four values, the registry's own test, plus the key being this device's.
 *
 * @throws When the read fails or answers short data.
 */
export async function signingKeyProven(guest: GuestAccount): Promise<boolean> {
  const { data } = await client.call({ to: PQC_STATUS_ADDRESS, data: encodeFunctionData({ abi: PQC_STATUS_ABI, functionName: "pqcKeyStatus", args: [guest.identity.evm] }) });
  if (data === undefined || (data.length - 2) / 2 < MIN_STATUS_BYTES) throw new Error("pqcKeyStatus answered with empty or short data.");
  const [registered, algorithmId, pubkey, possessionProven] = decodeAbiParameters(PQC_STATUS_ABI[0].outputs, data);
  const key = hexToBytes(pubkey);
  return registered && algorithmId === ML_DSA_87 && possessionProven && key.length === ML_DSA_87_PUBKEY && sameBytes(key, guest.identity.mldsa.publicKey);
}

/**
 * Whether qor_getKEMKey on the public EVM RPC answers this guest's own ML-KEM-1024 key, through
 * @ava/core's fetchKemKey, which checks the account, the algorithm and the key.
 *
 * @returns "mine", "none" when the account has published no key, or "other" for another key.
 * @throws KemKeyUnavailable for any lookup failure other than "not found".
 */
export async function sealKeyStanding(guest: GuestAccount): Promise<"mine" | "none" | "other"> {
  try {
    const published = await fetchKemKey(guest.identity.evm);
    return sameBytes(published.kemPublicKey, guest.identity.seal.mlkemPublicKey) ? "mine" : "other";
  } catch (error) {
    if (error instanceof KemKeyUnavailable && error.reason === "NOT_FOUND") return "none";
    throw error;
  }
}

/**
 * Registers the guest's ML-DSA-87 key, exactly as live-demo-check.ts does: a proof of possession
 * signed with the key being registered and checked locally first, then MsgRegisterPQCKeyV2 signed
 * classically, because the chain has no key of this account to check a hybrid signature against yet.
 */
export async function registerSigningKey(guest: GuestAccount, signal: AbortSignal, onSigned: (hash: string) => void): Promise<CommittedTx> {
  const { qor1, mldsa } = guest.identity;
  const proof = signProofOfPossession({ chainId: CHAIN_ID, account: qor1, keypair: mldsa });
  if (!verifyProofOfPossession({ chainId: CHAIN_ID, account: qor1, publicKey: mldsa.publicKey, proof })) throw new Error("The proof of possession does not verify locally.");
  const message = buildRegisterPqcKeyMsg(qor1, { pqcKeypair: mldsa, proofOfPossession: proof });
  return sendNative(guest, "classical", [message], KEY_REGISTRATION_FEE, startDeadline(SEND_BUDGET_MS), signal, onSigned);
}

/** Publishes the guest's ML-KEM-1024 key with msg.pqc.registerKemKey, hybrid-signed now that its ML-DSA-87 key is on chain. */
export async function registerSealKey(guest: GuestAccount, signal: AbortSignal, onSigned: (hash: string) => void): Promise<CommittedTx> {
  const { qor1, seal } = guest.identity;
  const message = msg.pqc.registerKemKey({ sender: qor1, publicKey: seal.mlkemPublicKey });
  return sendNative(guest, "hybrid", [message], KEM_REGISTRATION_FEE, startDeadline(SEND_BUDGET_MS), signal, onSigned);
}

/**
 * Waits until both keys show on the EVM side, where the registry and the demo bot read them:
 * pqcKeyStatus with possession proven, and qor_getKEMKey answering this guest's key.
 *
 * @throws Error naming what is still missing after a minute.
 */
export async function waitForKeys(guest: GuestAccount, signal: AbortSignal, deadline: Deadline = startDeadline(KEYS_WAIT_MS)): Promise<void> {
  let missing = "both keys";
  for (;;) {
    let standing: [boolean, "mine" | "none" | "other"] | undefined;
    try {
      standing = await Promise.all([signingKeyProven(guest), sealKeyStanding(guest)]);
    } catch {
      // One failed read is the network; the deadline decides when to give up.
      standing = undefined;
    }
    if (standing !== undefined) {
      const [proven, kem] = standing;
      if (proven && kem === "mine") return;
      if (kem === "other") throw new Error("The chain shows another ML-KEM key for this account.");
      missing = proven ? "the ML-KEM key" : kem === "mine" ? "the ML-DSA-87 key" : "both keys";
    }
    if (performance.now() + KEYS_POLL_MS > deadline.endsAt) throw new Error(`The chain did not show ${missing} within a minute.`);
    await pause(KEYS_POLL_MS, signal);
  }
}
