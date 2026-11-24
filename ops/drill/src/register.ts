import {
  buildRegisterPqcKeyMsg,
  clearPqcStatusCache,
  fetchPqcStatus,
  isRegisteredPqcKey,
  msg,
  proofOfPossessionSignBytes,
  qorechainRegistry,
  sha256Hex,
  signProofOfPossession,
  verifyProofOfPossession,
  withRetry,
} from "@qorechain/sdk";
import { buildRegisterKemKeyMessage } from "@qorechain/qoreseal";
import { deriveDrillAccount, type DrillAccount } from "./account.js";
import { CHAIN_ID, FUNDED_THRESHOLD_UQOR, REST, requireMnemonic } from "./env.js";
import { formatQor, printStatus, readStatus } from "./status.js";
import { FEE_RULE, REGISTRATION_FEE, sendTx, type Messages } from "./tx.js";

const dryRun = process.argv.includes("--dry-run");

interface Planned {
  label: string;
  mode: "classical" | "hybrid";
  messages: Messages;
  describe: string[];
  fixedFee?: typeof REGISTRATION_FEE;
  afterSend: () => Promise<void>;
}

function fingerprint(bytes: Uint8Array): string {
  return `${bytes.length} bytes, sha256 ${sha256Hex(bytes).replace(/^0x/, "").slice(0, 16)}...`;
}

function planPqKey(account: DrillAccount): Planned {
  const proof = signProofOfPossession({ chainId: CHAIN_ID, account: account.qor1, keypair: account.pqc });
  if (!verifyProofOfPossession({ chainId: CHAIN_ID, account: account.qor1, publicKey: account.pqc.publicKey, proof })) {
    throw new Error("The proof of possession does not verify locally. Refusing to send a registration the chain would refuse after taking the fee.");
  }
  // The organisers' example leaves ecdsa_pubkey empty: the chain binds the key of the transaction's signer.
  const message = buildRegisterPqcKeyMsg(account.qor1, { pqcKeypair: account.pqc, proofOfPossession: proof });
  const value = message.value as { sender: string; algorithmId: number; keyType: string; publicKey: Uint8Array; ecdsaPubkey: Uint8Array; proofOfPossession: Uint8Array };
  const popText = new TextDecoder().decode(proofOfPossessionSignBytes({ chainId: CHAIN_ID, account: account.qor1, publicKey: account.pqc.publicKey }));
  return {
    label: "ML-DSA-87 key",
    mode: "classical",
    messages: [message],
    fixedFee: REGISTRATION_FEE,
    describe: [
      `message: ${message.typeUrl} (signed classical: the one message the chain accepts before a key exists)`,
      `  sender:              ${value.sender}`,
      `  algorithm_id:        ${value.algorithmId} (ML-DSA-87)`,
      `  key_type:            ${value.keyType}`,
      `  public_key:          ${fingerprint(value.publicKey)}`,
      `  ecdsa_pubkey:        ${value.ecdsaPubkey.length} bytes (empty: the chain binds the signer's key, as in the organisers' example)`,
      `  proof_of_possession: ${fingerprint(value.proofOfPossession)}, verifies locally: yes`,
      `                       over "${popText.slice(0, popText.lastIndexOf("|") + 17)}..."`,
      `  fee:                 ${REGISTRATION_FEE.amount[0]!.amount} uqor for ${REGISTRATION_FEE.gas} gas (the organisers' registration fee)`,
    ],
    afterSend: async () => {
      const confirmed = await withRetry(
        async () => {
          clearPqcStatusCache();
          const s = await fetchPqcStatus({ rest: REST, address: account.qor1 });
          if (!s.registered) throw new Error("not visible yet");
          return s;
        },
        { retries: 6, backoff: 2_000, maxBackoff: 6_000 },
      );
      if (isRegisteredPqcKey(confirmed, account.pqc.publicKey) !== true || confirmed.possessionProven !== true) {
        throw new Error("After registration the chain does not report this account's key with possession proven. Stopping before the KEM key.");
      }
    },
  };
}

function planKemKey(account: DrillAccount): Planned {
  const message = msg.pqc.registerKemKey({ sender: account.qor1, publicKey: account.seal.mlkemPublicKey });
  // The SDK message is the one its registry can sign; QoreSeal's builder is the reference encoding.
  const reference = buildRegisterKemKeyMessage({ sender: account.qor1, mlkemPublicKey: account.seal.mlkemPublicKey });
  const encoded = qorechainRegistry().encode(message);
  if (message.typeUrl !== reference.typeUrl || !Buffer.from(encoded).equals(Buffer.from(reference.value))) {
    throw new Error("The SDK and QoreSeal encode the KEM registration differently. Refusing to send.");
  }
  const value = message.value as { sender: string; algorithmId: number; publicKey: Uint8Array };
  return {
    label: "ML-KEM-1024 key",
    mode: "hybrid",
    messages: [message],
    describe: [
      `message: ${message.typeUrl} (signed hybrid: eth_secp256k1 plus ML-DSA-87)`,
      `  sender:              ${value.sender}`,
      `  algorithm_id:        ${value.algorithmId} (ML-KEM-1024)`,
      `  public_key:          ${fingerprint(value.publicKey)}, same bytes as QoreSeal buildRegisterKemKeyMessage: yes`,
      `  fee:                 ${FEE_RULE}`,
    ],
    afterSend: async () => {},
  };
}

async function main(): Promise<void> {
  const account = await deriveDrillAccount(requireMnemonic());
  const status = await readStatus(account);
  printStatus(account, status);

  const pqc = await fetchPqcStatus({ rest: REST, address: account.qor1 });
  if (pqc.registered !== status.pq.found) {
    throw new Error("The two reads of the ML-DSA-87 key disagree. Refusing to register.");
  }
  if (pqc.registered && isRegisteredPqcKey(pqc, account.pqc.publicKey) !== true) {
    throw new Error("The account has an ML-DSA-87 key that is not this phrase's key (or it cannot be read). Refusing to register: a second registration is refused after the fee is taken.");
  }
  if (status.kem.found && status.kem.matchesOurKey !== true) {
    throw new Error("The account already publishes a KEM key that is not this phrase's key (or it cannot be read). Refusing to replace it.");
  }

  const plan: Planned[] = [];
  if (!pqc.registered) plan.push(planPqKey(account));
  if (!status.kem.found) plan.push(planKemKey(account));
  if (plan.length === 0) {
    console.log("Nothing to register: both keys are on chain and are this account's keys.");
    return;
  }

  plan.forEach((p, i) => {
    console.log(`\n[${i + 1}/${plan.length}] ${p.label}`);
    p.describe.forEach((line) => console.log(line));
  });
  console.log("");

  const funded = status.balanceUqor >= FUNDED_THRESHOLD_UQOR;
  if (!funded) {
    console.log(`not funded yet: send QOR to ${account.qor1} (balance ${formatQor(status.balanceUqor)} QOR, needs at least ${formatQor(FUNDED_THRESHOLD_UQOR)} QOR)`);
  }
  if (dryRun) {
    console.log("dry run: nothing was broadcast.");
    return;
  }
  if (!funded) return;

  for (const p of plan) {
    const tx = await sendTx(account, p.mode, p.messages, "", p.fixedFee);
    await p.afterSend();
    console.log(
      `${p.label} registered: ${tx.hash} (height ${tx.height}, gas used ${tx.gasUsed} of ${tx.gasWanted}, fee ${tx.fee.amount[0]!.amount} uqor${tx.hybridVerified ? ", pqc_hybrid_verify verified" : ""})`,
    );
  }
  console.log("");
  printStatus(account, await readStatus(account));
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
