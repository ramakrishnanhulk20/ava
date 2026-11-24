import { api } from "../api";
import type { GuestAccount } from "./identity";
import { KEM_REGISTRATION_UQOR, KEY_REGISTRATION_UQOR, registerSealKey, registerSigningKey, sealKeyStanding, signingKeyProven, waitForKeys } from "./keys";
import { balanceOf } from "./proxy";
import { Stopped, pause, throwIfStopped } from "./time";

export type OnboardStepKey = "sponsor" | "mldsa" | "mlkem" | "keys";

/** Where the onboarding reports its four steps: the demo's chapter tracker, or a chair screen's own. */
export interface OnboardSteps {
  start(key: OnboardStepKey, wait?: string): void;
  update(key: OnboardStepKey, patch: { detail?: string; hash?: string; hashKind?: "native" | "evm"; wait?: string }): void;
  end(key: OnboardStepKey, state: "done" | "skipped", detail: string): void;
}

const BLOCK_WAIT = "Waiting for its block. Blocks come about every 1.4 s, then the lookup runs every 2 s.";
const BALANCE_POLL_MS = 2_000;
const BALANCE_WAIT_MS = 60_000;
/** A one-shot read is tried this many times, 2 s apart, so one slow answer from a public endpoint does not end the journey. */
const READ_TRIES = 3;
const READ_RETRY_MS = 2_000;
const UQOR_PER_QOR = 1_000_000n;

export function qor(uqor: bigint): string {
  const fraction = (uqor % UQOR_PER_QOR).toString().padStart(6, "0").replace(/0+$/, "");
  return `${uqor / UQOR_PER_QOR}${fraction === "" ? "" : `.${fraction}`} QOR`;
}

/** Runs a read that sends nothing, again after a failure, at most READ_TRIES times; the last failure is thrown as it came. */
export async function retryRead<T>(read: () => Promise<T>, signal: AbortSignal): Promise<T> {
  for (let tried = 1; ; tried++) {
    throwIfStopped(signal);
    try {
      return await read();
    } catch (error) {
      if (error instanceof Stopped || signal.aborted || tried >= READ_TRIES) throw error;
      await pause(READ_RETRY_MS, signal);
    }
  }
}

async function waitForBalance(qor1: string, need: bigint, signal: AbortSignal): Promise<bigint> {
  const endsAt = performance.now() + BALANCE_WAIT_MS;
  for (;;) {
    throwIfStopped(signal);
    let balance: bigint | undefined;
    try {
      balance = await balanceOf(qor1, signal);
    } catch (error) {
      if (error instanceof Stopped) throw error;
      balance = undefined;
    }
    if (balance !== undefined && balance >= need) return balance;
    if (performance.now() + BALANCE_POLL_MS > endsAt) throw new Error(`The balance did not reach ${qor(need)} within a minute.`);
    await pause(BALANCE_POLL_MS, signal);
  }
}

async function sponsor(t: OnboardSteps, guest: GuestAccount, signal: AbortSignal): Promise<{ proven: boolean; kemMine: boolean }> {
  const { qor1 } = guest.identity;
  t.start("sponsor", "Reading what this account already holds on chain.");
  const [proven, kem, balance] = await retryRead(() => Promise.all([signingKeyProven(guest), sealKeyStanding(guest), balanceOf(qor1, signal)]), signal);
  if (kem === "other") throw new Error("The chain shows another ML-KEM key for this account.");
  const kemMine = kem === "mine";
  const need = (proven ? 0n : KEY_REGISTRATION_UQOR) + (kemMine ? 0n : KEM_REGISTRATION_UQOR);
  if (need === 0n) {
    t.end("sponsor", "skipped", "Both keys are already on chain from an earlier visit.");
    return { proven, kemMine };
  }
  if (balance >= need) {
    t.end("sponsor", "skipped", `Already holds ${qor(balance)}, enough for what is left to register (${qor(need)}).`);
    return { proven, kemMine };
  }
  t.update("sponsor", { wait: "The sponsor signs a hybrid MsgSend and waits for its block before it answers." });
  const response = await api("/api/sponsor", { json: { address: qor1 }, signal });
  const body = (await response.json().catch(() => ({}))) as { txHash?: unknown; error?: unknown };
  if (response.status === 202 && typeof body.txHash === "string" && /^[0-9A-F]{64}$/.test(body.txHash)) {
    t.update("sponsor", { hash: body.txHash, hashKind: "native", detail: "The sponsor's transfer is in a block.", wait: "Waiting for the transfer to show in this account's balance through the chain proxy." });
  } else if (response.status === 409 && body.error === "already_sponsored") {
    t.update("sponsor", { detail: "The sponsor already funded this account once.", wait: "Waiting for that earlier transfer to show in the balance." });
  } else {
    const reason = typeof body.error === "string" && /^[A-Za-z0-9_]{1,64}$/.test(body.error) ? body.error : "unknown";
    throw new Error(`The sponsor refused: HTTP ${response.status} ${reason}.`);
  }
  const funded = await waitForBalance(qor1, need, signal);
  t.end("sponsor", "done", `Balance ${qor(funded)}, enough for both registrations (${qor(need)}).`);
  return { proven, kemMine };
}

/**
 * Brings an identity to the point where it can act on a board: sponsor funds if it needs them, the
 * ML-DSA-87 signing key registered with its proof of possession, the ML-KEM-1024 sealing key
 * published, and both visible on the public EVM RPC. Each step first reads what the chain already
 * holds, so a return visit never pays twice for a key that is already there. A guest and a chair
 * start the same way.
 */
export async function fundAndRegister(guest: GuestAccount, signal: AbortSignal, t: OnboardSteps): Promise<void> {
  const held = await sponsor(t, guest, signal);

  if (held.proven) {
    t.end("mldsa", "skipped", "Already registered with possession proven.");
  } else {
    t.start("mldsa", BLOCK_WAIT);
    const sent = await registerSigningKey(guest, signal, (hash) => t.update("mldsa", { hash, hashKind: "native" }));
    t.end("mldsa", "done", `In block ${sent.height}, gas used ${sent.gasUsed} of ${sent.gasWanted}.`);
  }

  if (held.kemMine) {
    t.end("mlkem", "skipped", "This account's ML-KEM key is already published.");
  } else {
    t.start("mlkem", BLOCK_WAIT);
    const sent = await registerSealKey(guest, signal, (hash) => t.update("mlkem", { hash, hashKind: "native" }));
    t.end("mlkem", "done", `In block ${sent.height}, gas used ${sent.gasUsed} of ${sent.gasWanted}; the chain's hybrid verdict is verified.`);
  }

  t.start("keys", "Reading pqcKeyStatus and qor_getKEMKey on the public EVM RPC every 2 s.");
  await waitForKeys(guest, signal);
  t.end("keys", "done", "pqcKeyStatus shows this key registered with possession proven, and qor_getKEMKey answers this account's ML-KEM key.");
}
