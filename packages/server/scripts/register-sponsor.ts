import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import {
  buildRegisterPqcKeyMsg,
  clearPqcStatusCache,
  fetchPqcStatus,
  isRegisteredPqcKey,
  signProofOfPossession,
  verifyProofOfPossession,
  withRetry,
  type PqcStatus,
} from "@qorechain/sdk";
import { isRelayerMnemonic, relayerFromMnemonic, type RelayerAccount } from "../src/chain/account.ts";
import { startDeadline } from "../src/chain/deadline.ts";
import { assertTestnet } from "../src/chain/live.ts";
import { balanceOf, sendNative, type Fee } from "../src/chain/native.ts";
import { CHAIN_ID, DENOM, REST, SPONSOR_AMOUNT_UQOR, SPONSOR_SEND_FEE_UQOR, UQOR_PER_QOR } from "../src/config.ts";

const ENV_PATH = fileURLToPath(new URL("../.env", import.meta.url));
// The organisers' Workshop 1 example sends the registration with exactly this fee. The 2,592-byte
// key used about 300,000 gas in the docs' run.
const REGISTRATION_FEE: Fee = { amount: [{ denom: DENOM, amount: "100000" }], gas: "800000" };
// The registration itself, then room for at least one sponsorship (amount plus fee) after it.
const FUNDED_THRESHOLD_UQOR = BigInt(REGISTRATION_FEE.amount[0]?.amount ?? "0") + SPONSOR_AMOUNT_UQOR + SPONSOR_SEND_FEE_UQOR;
const SEND_BUDGET_MS = 120_000;

function formatQor(uqor: bigint): string {
  const fraction = (uqor % UQOR_PER_QOR).toString().padStart(6, "0").replace(/0+$/, "");
  return `${uqor / UQOR_PER_QOR}${fraction === "" ? "" : `.${fraction}`}`;
}

async function readPqc(address: string): Promise<PqcStatus> {
  clearPqcStatusCache();
  return fetchPqcStatus({ rest: REST, address });
}

function isOurProvenKey(pqc: PqcStatus, sponsor: RelayerAccount): boolean {
  return pqc.registered && isRegisteredPqcKey(pqc, sponsor.pqc.publicKey) === true && pqc.possessionProven === true;
}

/** Messages name the variable, never its value. */
function sponsorPhrase(): string {
  const raw = existsSync(ENV_PATH) ? parseEnv(readFileSync(ENV_PATH, "utf8")).SPONSOR_MNEMONIC : undefined;
  if (raw === undefined || !isRelayerMnemonic(raw)) throw new Error(`SPONSOR_MNEMONIC is not set to 24 valid words in ${ENV_PATH}. Run: npx tsx scripts/new-sponsor.ts`);
  return raw;
}

/**
 * Registers the sponsor's ML-DSA-87 key with a proof of possession, the way register-relayer.ts
 * registers the relayer's, so every sponsor send can be hybrid-signed. Reads first and does nothing
 * when the chain already holds this phrase's proven key. The sponsor needs no KEM key.
 */
async function main(): Promise<void> {
  const chainId = await assertTestnet();
  const sponsor = await relayerFromMnemonic(sponsorPhrase());
  const [balance, pqc] = await Promise.all([balanceOf(sponsor.qor1), readPqc(sponsor.qor1)]);
  console.log(`chain id:  ${chainId} confirmed`);
  console.log(`qor1:      ${sponsor.qor1}`);
  console.log(`0x:        ${sponsor.evm}`);
  console.log(`balance:   ${formatQor(balance)} QOR`);

  if (pqc.registered && !isOurProvenKey(pqc, sponsor)) {
    throw new Error("The account has an ML-DSA-87 key that is not this phrase's key with possession proven. Refusing: a second registration is refused after the fee is taken.");
  }
  if (pqc.registered) {
    console.log("PQ key:    found, possession_proven true, this phrase's ML-DSA-87 key. Nothing to register.");
    return;
  }
  if (balance < FUNDED_THRESHOLD_UQOR) throw new Error(`Not funded: send at least ${formatQor(FUNDED_THRESHOLD_UQOR - balance)} QOR more to ${sponsor.qor1} first.`);

  const proof = signProofOfPossession({ chainId: CHAIN_ID, account: sponsor.qor1, keypair: sponsor.pqc });
  if (!verifyProofOfPossession({ chainId: CHAIN_ID, account: sponsor.qor1, publicKey: sponsor.pqc.publicKey, proof })) {
    throw new Error("The proof of possession does not verify locally. Refusing to send a registration the chain would refuse after taking the fee.");
  }
  // The organisers' example leaves ecdsa_pubkey empty: the chain binds the key of the transaction's signer.
  const message = buildRegisterPqcKeyMsg(sponsor.qor1, { pqcKeypair: sponsor.pqc, proofOfPossession: proof });
  console.log(`ML-DSA-87: registering with MsgRegisterPQCKeyV2, signed classical, fee ${REGISTRATION_FEE.amount[0]?.amount} uqor for ${REGISTRATION_FEE.gas} gas`);
  const tx = await sendNative(sponsor, "classical", [message], REGISTRATION_FEE, startDeadline(SEND_BUDGET_MS));
  await withRetry(
    async () => {
      if (!isOurProvenKey(await readPqc(sponsor.qor1), sponsor)) throw new Error("ML-DSA-87 key not visible yet");
    },
    { retries: 8, backoff: 2_000, maxBackoff: 6_000 },
  );
  console.log(`ML-DSA-87: registered in ${tx.hash} (height ${tx.height}, gas used ${tx.gasUsed} of ${tx.gasWanted})`);
  console.log("PQ key:    found, possession_proven true, this phrase's ML-DSA-87 key");
  console.log(`balance:   ${formatQor(await balanceOf(sponsor.qor1))} QOR`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
