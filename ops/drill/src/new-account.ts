import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { parseEnv } from "node:util";
import { generateMnemonic, validateMnemonic } from "@qorechain/sdk";
import { deriveDrillAccount } from "./account.js";
import { assertTestnet } from "./chain.js";
import { ENV_PATH, FORM_KEY_PATH, hasMnemonic } from "./env.js";

const MNEMONIC_LINE = /^\s*(export\s+)?DRILL_MNEMONIC\s*=/m;

async function main(): Promise<void> {
  const existing = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
  // Any DRILL_MNEMONIC line counts, even an empty one: a second line would
  // leave it to the .env parser which phrase wins.
  if (hasMnemonic() || MNEMONIC_LINE.test(existing)) {
    throw new Error(`${ENV_PATH} already has DRILL_MNEMONIC (or it is set in the shell). Refusing to replace the drill account.`);
  }

  const chainId = await assertTestnet();

  const mnemonic = generateMnemonic(256);
  if (mnemonic.split(" ").length !== 24 || !validateMnemonic(mnemonic)) {
    throw new Error("The SDK returned a recovery phrase that is not 24 valid words. Nothing was written.");
  }
  const account = await deriveDrillAccount(mnemonic);

  // The key file goes first: if the .env write then fails, a rerun replaces the
  // key file with the next account's key instead of leaving a phrase with no key.
  mkdirSync(dirname(FORM_KEY_PATH), { recursive: true });
  writeFileSync(FORM_KEY_PATH, Buffer.from(account.privateKey).toString("hex"), { encoding: "utf8", mode: 0o600 });

  const lead = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
  appendFileSync(ENV_PATH, `${lead}DRILL_MNEMONIC="${mnemonic}"\n`, { encoding: "utf8", mode: 0o600 });

  const stored = parseEnv(readFileSync(ENV_PATH, "utf8")).DRILL_MNEMONIC;
  if (stored === undefined || (await deriveDrillAccount(stored)).qor1 !== account.qor1) {
    throw new Error(`Read-back of ${ENV_PATH} does not give the same account. Do not fund it; delete the DRILL_MNEMONIC line and rerun.`);
  }
  const storedKey = readFileSync(FORM_KEY_PATH, "utf8");
  if (!/^[0-9a-f]{64}$/.test(storedKey)) {
    throw new Error(`${FORM_KEY_PATH} is not 64 lowercase hex characters. Do not use it.`);
  }

  console.log(`chain id:  ${chainId} confirmed`);
  console.log(`qor1:      ${account.qor1}`);
  console.log(`0x:        ${account.evm}`);
  console.log(`key file:  ${FORM_KEY_PATH}`);
  console.log("The recovery phrase is in ops/drill/.env only. Fund the qor1 address, then run: npm run register");
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
