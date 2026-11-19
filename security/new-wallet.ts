import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { generateMnemonic, sameAccount } from "@ava/core";
import { ENV_PATH, KEY_NAME, readEnvFile } from "./lib/env.ts";
import { assertTestnet, installFetchGuard } from "./lib/guard.ts";
import { isPhrase, personAt } from "./lib/identities.ts";

const LINE = new RegExp(`^\\s*(export\\s+)?${KEY_NAME}\\s*=`, "m");

/**
 * Creates the security wallet once: a fresh 24-word phrase from the QoreChain SDK's generator
 * (through @ava/core, as scripts/new-relayer.ts does), written straight into security/.env and read
 * back. Prints only the two address forms. Sends nothing.
 */
async function main(): Promise<void> {
  const existing = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
  // Any line for the name counts, even an empty one: a second line would leave it to the parser which phrase wins.
  if ((process.env[KEY_NAME] ?? "").trim() !== "" || LINE.test(existing)) {
    throw new Error(`${ENV_PATH} already has ${KEY_NAME} (or it is set in the shell). Refusing to replace the security wallet.`);
  }

  installFetchGuard();
  const chain = await assertTestnet();

  const mnemonic = generateMnemonic();
  if (!isPhrase(mnemonic)) throw new Error("The new phrase is not 24 valid words. Nothing was written.");
  const wallet = await personAt(mnemonic, 0, "wallet");

  const lead = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
  appendFileSync(ENV_PATH, `${lead}${KEY_NAME}="${mnemonic}"\n`, { encoding: "utf8", mode: 0o600 });

  const stored = readEnvFile()[KEY_NAME];
  if (stored === undefined || !sameAccount((await personAt(stored, 0, "wallet")).qor1, wallet.qor1)) {
    throw new Error(`Read-back of ${ENV_PATH} does not give the same account. Do not fund it; delete the ${KEY_NAME} line and rerun.`);
  }

  console.log(`chain id:  ${chain.cosmos} and EVM ${chain.evm} confirmed`);
  console.log(`qor1:      ${wallet.qor1}`);
  console.log(`0x:        ${wallet.evm}`);
  console.log(`The recovery phrase is in security/.env only, as ${KEY_NAME}. This account is for attack scripts on testnet and nothing else.`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
