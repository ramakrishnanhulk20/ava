import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { validateMnemonic } from "@qorechain/sdk";

export const CHAIN_ID = "qorechain-diana";
export const REST = "https://api-testnet.qore.host";
export const RPC = "https://rpc-testnet.qore.host";
export const EVM_RPC = "https://evm-testnet.qore.host";
export const EVM_CHAIN_ID = 9800;
export const DENOM = "uqor";
export const UQOR_PER_QOR = 1_000_000n;

// The chain refuses any transaction priced under 0.1 uqor per unit of gas.
// Prices are kept in thousandths of a uqor so fee maths stays in integers.
export const MIN_GAS_PRICE_MILLI_UQOR = 100n;

// Registration cost about 0.09 QOR in the docs' 12 Nov run and a hybrid send
// about 0.03 QOR, so 0.5 QOR covers registration, the KEM key and the drill-day
// proof with a wide margin.
export const FUNDED_THRESHOLD_UQOR = 500_000n;

export const DRILL_DAY_START = Date.parse("2026-11-18T00:00:00Z");
export const DRILL_DAY_END = Date.parse("2026-11-18T23:59:59Z");

export const ENV_PATH = fileURLToPath(new URL("../.env", import.meta.url));
// Git-ignored (.secrets/ in the root .gitignore): the classical key the drill form asks for, written once and never committed.
export const FORM_KEY_PATH = fileURLToPath(new URL("../.secrets/drill-form-key.txt", import.meta.url));

export const HTTP = { retries: 4, retryDelayMs: 2_000, timeoutMs: 20_000 } as const;

const MNEMONIC_WORDS = 24;

if (existsSync(ENV_PATH)) process.loadEnvFile(ENV_PATH);

/**
 * Error messages here name the variable, never its value: the phrase must not
 * reach a terminal or a log even when it is malformed.
 */
function readMnemonic(): string | undefined {
  const raw = process.env.DRILL_MNEMONIC;
  if (raw === undefined || raw.trim() === "") return undefined;
  const mnemonic = raw.trim().split(/\s+/).join(" ");
  const words = mnemonic.split(" ").length;
  if (words !== MNEMONIC_WORDS) {
    throw new Error(`DRILL_MNEMONIC in ${ENV_PATH} has ${words} words; it must have ${MNEMONIC_WORDS}.`);
  }
  if (!validateMnemonic(mnemonic)) {
    throw new Error(`DRILL_MNEMONIC in ${ENV_PATH} fails the BIP-39 word list or checksum check.`);
  }
  return mnemonic;
}

// Validated on first use rather than at import, so a bad phrase reaches each
// script's own error handler (message only) instead of an uncaught stack trace.
let checked: { value: string | undefined } | undefined;

function mnemonicOrUndefined(): string | undefined {
  checked ??= { value: readMnemonic() };
  return checked.value;
}

export function hasMnemonic(): boolean {
  return mnemonicOrUndefined() !== undefined;
}

export function requireMnemonic(): string {
  const mnemonic = mnemonicOrUndefined();
  if (mnemonic === undefined) {
    throw new Error(`DRILL_MNEMONIC is not set in ${ENV_PATH}. Run: npm run new-account`);
  }
  return mnemonic;
}
