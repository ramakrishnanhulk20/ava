import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import { generateMnemonic, sameAccount } from "@ava/core";
import { isRelayerMnemonic, relayerFromMnemonic } from "../src/chain/account.ts";
import { assertTestnet } from "../src/chain/live.ts";

const ENV_PATH = fileURLToPath(new URL("../.env", import.meta.url));
const NAME = "RELAYER_MNEMONIC";
const LINE = new RegExp(`^\\s*(export\\s+)?${NAME}\\s*=`, "m");

async function main(): Promise<void> {
  const existing = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
  // Any line for the name counts, even an empty one: a second line would leave it to the parser which phrase wins.
  if ((process.env[NAME] ?? "").trim() !== "" || LINE.test(existing)) {
    throw new Error(`${ENV_PATH} already has ${NAME} (or it is set in the shell). Refusing to replace the relayer.`);
  }

  const chainId = await assertTestnet();

  const mnemonic = generateMnemonic();
  if (!isRelayerMnemonic(mnemonic)) throw new Error("The new phrase is not 24 valid words. Nothing was written.");
  const relayer = await relayerFromMnemonic(mnemonic);

  const lead = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
  appendFileSync(ENV_PATH, `${lead}${NAME}="${mnemonic}"\n`, { encoding: "utf8", mode: 0o600 });

  const stored = parseEnv(readFileSync(ENV_PATH, "utf8"))[NAME];
  if (stored === undefined || !sameAccount((await relayerFromMnemonic(stored)).qor1, relayer.qor1)) {
    throw new Error(`Read-back of ${ENV_PATH} does not give the same account. Do not fund it; delete the ${NAME} line and rerun.`);
  }

  console.log(`chain id:  ${chainId} confirmed`);
  console.log(`qor1:      ${relayer.qor1}`);
  console.log(`0x:        ${relayer.evm}`);
  console.log(`The recovery phrase is in packages/server/.env only, as ${NAME}. This account is the relayer and nothing else.`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
