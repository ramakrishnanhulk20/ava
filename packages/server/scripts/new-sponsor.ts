import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import { generateMnemonic, sameAccount } from "@ava/core";
import { isRelayerMnemonic, relayerFromMnemonic } from "../src/chain/account.ts";
import { assertTestnet } from "../src/chain/live.ts";

const ENV_PATH = fileURLToPath(new URL("../.env", import.meta.url));
const NAME = "SPONSOR_MNEMONIC";
const LINE = new RegExp(`^\\s*(export\\s+)?${NAME}\\s*=`, "m");

/**
 * Makes the sponsor's account: a fresh 24-word phrase written straight into .env, never shown,
 * derived the way the relayer is (one coin-60 key on both lanes plus the address-bound ML-DSA-87 key).
 */
async function main(): Promise<void> {
  const existing = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
  // Any line for the name counts, even an empty one: a second line would leave it to the parser which phrase wins.
  if ((process.env[NAME] ?? "").trim() !== "" || LINE.test(existing)) {
    throw new Error(`${ENV_PATH} already has ${NAME} (or it is set in the shell). Refusing to replace the sponsor.`);
  }

  const chainId = await assertTestnet();

  const mnemonic = generateMnemonic();
  if (!isRelayerMnemonic(mnemonic)) throw new Error("The new phrase is not 24 valid words. Nothing was written.");
  const sponsor = await relayerFromMnemonic(mnemonic);

  const lead = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
  appendFileSync(ENV_PATH, `${lead}${NAME}="${mnemonic}"\n`, { encoding: "utf8", mode: 0o600 });

  const stored = parseEnv(readFileSync(ENV_PATH, "utf8"))[NAME];
  if (stored === undefined || !sameAccount((await relayerFromMnemonic(stored)).qor1, sponsor.qor1)) {
    throw new Error(`Read-back of ${ENV_PATH} does not give the same account. Do not fund it; delete the ${NAME} line and rerun.`);
  }

  console.log(`chain id:  ${chainId} confirmed`);
  console.log(`qor1:      ${sponsor.qor1}`);
  console.log(`0x:        ${sponsor.evm}`);
  console.log(`The recovery phrase is in packages/server/.env only, as ${NAME}. This account is the sponsor and nothing else.`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
