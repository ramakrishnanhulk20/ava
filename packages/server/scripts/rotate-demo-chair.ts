import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import { generateMnemonic } from "@ava/core";
import { mldsa87 } from "@qorechain/pqc";
import { derivePqcCanonical, rotatePqcKeyMsg, rotationSignBytes, withRetry, type PqcKeypair } from "@qorechain/sdk";
import { bytesToHex, sha256 } from "viem";
import { isRelayerMnemonic, normalizeMnemonic, relayerFromMnemonic, type RelayerAccount } from "../src/chain/account.ts";
import { startDeadline } from "../src/chain/deadline.ts";
import { evmClient } from "../src/chain/evm.ts";
import { assertTestnet } from "../src/chain/live.ts";
import { balanceOf, sendNative, type Fee, type Messages } from "../src/chain/native.ts";
import { CHAIN_ID, DENOM, UQOR_PER_QOR } from "../src/config.ts";
import { provenMldsaKey, readKeyStatus } from "../src/demoBoard.ts";

// Rotates the demo chair's ML-DSA-87 key with MsgRotatePQCKey, for the day the key leaks (threat
// model C37; steps in docs/security/runbook.md). A dry run, the default, builds and checks the
// message and sends nothing. `--live` sends it, after the word ROTATE is typed.

const ENV_PATH = fileURLToPath(new URL("../.env", import.meta.url));
const CHAIR_NAME = "DEMO_CHAIR_MNEMONIC";
/** Where a live run keeps the phrase the new key derives from, written before anything is sent. */
const NEXT_NAME = "DEMO_CHAIR_PQC_MNEMONIC";
const NEXT_LINE = new RegExp(`^\\s*(export\\s+)?${NEXT_NAME}\\s*=`, "m");
const CONFIRM_WORD = "ROTATE";
const ML_DSA_87 = 1;
/**
 * The message carries two 2,592-byte keys and two 4,627-byte signatures, and the transaction a
 * third. The docs' CLI example sends a rotation with 600,000 gas and at least 60,000 uqor; this
 * keeps a third more gas at 0.15 uqor per gas. Not yet measured on this chain.
 */
const ROTATION_FEE: Fee = { amount: [{ denom: DENOM, amount: "120000" }], gas: "800000" };
const ROTATION_FEE_UQOR = 120_000n;
const SEND_BUDGET_MS = 120_000;

function runMode(args: readonly string[]): "dry-run" | "live" {
  if (args.some((a) => a !== "--dry-run" && a !== "--live") || (args.includes("--dry-run") && args.includes("--live"))) {
    throw new Error("Options: --dry-run (the default) or --live, not both.");
  }
  return args.includes("--live") ? "live" : "dry-run";
}

function formatQor(uqor: bigint): string {
  const fraction = (uqor % UQOR_PER_QOR).toString().padStart(6, "0").replace(/0+$/, "");
  return `${uqor / UQOR_PER_QOR}${fraction === "" ? "" : `.${fraction}`}`;
}

/** The first 8 bytes of the key's SHA-256: enough to tell keys apart on screen, and public anyway. */
function fingerprint(publicKey: Uint8Array): string {
  return bytesToHex(sha256(publicKey, "bytes").slice(0, 8));
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/**
 * MsgRotatePQCKey as the SDK builds it in rotatePqcKeyMsgFromMnemonic: both keys sign the UTF-8 of
 * rotationSignBytes(chain id, algorithm 1, the qor1 account, old key, new key), pure ML-DSA-87.
 * Both signatures are checked here before anything can be sent.
 */
function rotationMessage(chair: RelayerAccount, next: PqcKeypair): Messages[number] {
  const old = chair.pqc;
  if (sameBytes(old.publicKey, next.publicKey)) throw new Error("The new key is the old key. Nothing to rotate.");
  const signBytes = new TextEncoder().encode(rotationSignBytes(CHAIN_ID, ML_DSA_87, chair.qor1, old.publicKey, next.publicKey));
  const oldSignature = mldsa87.sign(old.secretKey, signBytes);
  const newSignature = mldsa87.sign(next.secretKey, signBytes);
  if (!mldsa87.verify(old.publicKey, signBytes, oldSignature) || !mldsa87.verify(next.publicKey, signBytes, newSignature)) {
    throw new Error("A rotation signature does not verify locally. Nothing was sent.");
  }
  return rotatePqcKeyMsg({ sender: chair.qor1, oldPublicKey: old.publicKey, newPublicKey: next.publicKey, oldSignature, newSignature });
}

/** The registered key pqcKeyStatus reports, only when registered, ML-DSA-87, possession proven and 2,592 bytes. */
async function registeredKey(chair: RelayerAccount): Promise<Uint8Array | undefined> {
  try {
    return provenMldsaKey(await readKeyStatus(evmClient(), chair.evm));
  } catch {
    return undefined;
  }
}

/** Appends the new phrase to .env and reads it back, so the new key can never be lost to a failed write. */
function keepPhrase(phrase: string, chair: RelayerAccount, next: PqcKeypair): void {
  const existing = readFileSync(ENV_PATH, "utf8");
  if (NEXT_LINE.test(existing)) throw new Error(`${ENV_PATH} already has ${NEXT_NAME}. Nothing was sent.`);
  const lead = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
  appendFileSync(ENV_PATH, `${lead}${NEXT_NAME}="${phrase}"\n`, { encoding: "utf8", mode: 0o600 });
  const stored = parseEnv(readFileSync(ENV_PATH, "utf8"))[NEXT_NAME];
  if (stored === undefined || !sameBytes(derivePqcCanonical(chair.qor1, normalizeMnemonic(stored)).publicKey, next.publicKey)) {
    throw new Error(`Read-back of ${NEXT_NAME} in ${ENV_PATH} does not give the new key. Nothing was sent; delete that line and rerun.`);
  }
}

async function main(): Promise<void> {
  const mode = runMode(process.argv.slice(2));
  const env = existsSync(ENV_PATH) ? parseEnv(readFileSync(ENV_PATH, "utf8")) : {};
  const phrase = env[CHAIR_NAME];
  // Messages name the variable, never its value.
  if (phrase === undefined || !isRelayerMnemonic(phrase)) throw new Error(`${CHAIR_NAME} is not set to 24 valid words in ${ENV_PATH}.`);
  if (env[NEXT_NAME] !== undefined) {
    throw new Error(`${ENV_PATH} already has ${NEXT_NAME}: the key was rotated before, or a live run stopped. See docs/security/runbook.md before running again.`);
  }

  const chainId = await assertTestnet();
  const chair = await relayerFromMnemonic(phrase);
  const nextPhrase = generateMnemonic();
  const next = derivePqcCanonical(chair.qor1, nextPhrase);
  const message = rotationMessage(chair, next);
  const [balance, registered] = await Promise.all([balanceOf(chair.qor1), registeredKey(chair)]);

  console.log(`mode:        ${mode}`);
  console.log(`chain id:    ${chainId} confirmed`);
  console.log(`demo chair:  ${chair.qor1} (${chair.evm})`);
  console.log(`old key:     ${fingerprint(chair.pqc.publicKey)} (from ${CHAIR_NAME})`);
  console.log(`new key:     ${fingerprint(next.publicKey)} (from a new phrase${mode === "live" ? `, kept as ${NEXT_NAME}` : ", discarded after this dry run"})`);
  console.log(`message:     ${message.typeUrl}, signed by the old and the new key, both checked`);
  console.log(`fee:         ${ROTATION_FEE.amount[0]?.amount} uqor for ${ROTATION_FEE.gas} gas, hybrid-signed with the old key`);
  console.log(`balance:     ${formatQor(balance)} QOR`);
  console.log(`pqcKeyStatus: ${registered === undefined ? "no proven ML-DSA-87 key reported" : `${fingerprint(registered)}${sameBytes(registered, chair.pqc.publicKey) ? " (the old key)" : " (not the old key)"}`}`);

  const problems: string[] = [];
  if (registered === undefined || !sameBytes(registered, chair.pqc.publicKey)) problems.push(`pqcKeyStatus does not report ${CHAIR_NAME}'s key as registered and possession-proven`);
  if (balance < ROTATION_FEE_UQOR) problems.push(`the account holds under the ${formatQor(ROTATION_FEE_UQOR)} QOR fee`);

  if (mode === "dry-run") {
    console.log(problems.length === 0 ? "A live run would send this now." : `A live run would refuse now: ${problems.join("; ")}.`);
    console.log("Dry run: nothing was sent and the new phrase was not kept.");
    return;
  }
  if (problems.length > 0) throw new Error(`Refusing to send: ${problems.join("; ")}.`);

  const prompt = createInterface({ input: process.stdin, output: process.stdout });
  const typed = (await prompt.question(`Type ${CONFIRM_WORD} to rotate the demo chair's ML-DSA-87 key on ${chainId}: `)).trim();
  prompt.close();
  if (typed !== CONFIRM_WORD) throw new Error("Not confirmed. Nothing was sent.");

  keepPhrase(nextPhrase, chair, next);
  const tx = await sendNative(chair, "hybrid", [message], ROTATION_FEE, startDeadline(SEND_BUDGET_MS));
  console.log(`sent:        ${tx.hash} (height ${tx.height}, gas used ${tx.gasUsed} of ${tx.gasWanted})`);
  await withRetry(
    async () => {
      const now = await registeredKey(chair);
      if (now === undefined || !sameBytes(now, next.publicKey)) throw new Error("the new key is not reported yet");
    },
    { retries: 8, backoff: 2_000, maxBackoff: 6_000 },
  );
  console.log(`pqcKeyStatus: ${fingerprint(next.publicKey)}, registered, ML-DSA-87, possession proven: the new key`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
