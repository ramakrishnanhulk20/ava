import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { parseEnv } from "node:util";
import { generateMnemonic, validateMnemonic } from "@qorechain/sdk";
import { deriveDeployer, sameAccount } from "./account.js";
import { assertTestnet } from "./chain.js";
import { ENV_PATH, hasMnemonic } from "./env.js";

const MNEMONIC_LINE = /^\s*(export\s+)?M1_DEPLOYER_MNEMONIC\s*=/m;

async function main(): Promise<void> {
  const existing = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
  // Any M1_DEPLOYER_MNEMONIC line counts, even an empty one: a second line
  // would leave it to the .env parser which phrase wins.
  if (hasMnemonic() || MNEMONIC_LINE.test(existing)) {
    throw new Error(`${ENV_PATH} already has M1_DEPLOYER_MNEMONIC (or it is set in the shell). Refusing to replace the deployer.`);
  }

  const chainId = await assertTestnet();

  const mnemonic = generateMnemonic(256);
  if (mnemonic.split(" ").length !== 24 || !validateMnemonic(mnemonic)) {
    throw new Error("The SDK returned a recovery phrase that is not 24 valid words. Nothing was written.");
  }
  const deployer = await deriveDeployer(mnemonic);

  const lead = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
  appendFileSync(ENV_PATH, `${lead}M1_DEPLOYER_MNEMONIC="${mnemonic}"\n`, { encoding: "utf8", mode: 0o600 });

  const stored = parseEnv(readFileSync(ENV_PATH, "utf8")).M1_DEPLOYER_MNEMONIC;
  if (stored === undefined || !sameAccount((await deriveDeployer(stored)).qor1, deployer.qor1)) {
    throw new Error(`Read-back of ${ENV_PATH} does not give the same account. Do not fund it; delete the M1_DEPLOYER_MNEMONIC line and rerun.`);
  }

  console.log(`chain id:  ${chainId} confirmed`);
  console.log(`qor1:      ${deployer.qor1}`);
  console.log(`0x:        ${deployer.evm}`);
  console.log("The recovery phrase is in packages/contracts/.env only. Fund the qor1 address, then run: npm run register-deployer");
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
