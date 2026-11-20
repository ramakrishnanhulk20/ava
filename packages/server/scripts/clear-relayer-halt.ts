import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { relayerFromMnemonic } from "../src/chain/account.ts";
import { loadEnv, requireRelayerMnemonic } from "../src/env.ts";
import { UpstashStore } from "../src/store.ts";
import { HALT_KEY, clearHalt, isHalted, nonceKey } from "../src/window.ts";

// Lifts the relayer's leak halt (threat model C25). A leak halt means the chain saw the relayer's
// nonce or window move without one of our own sends, and it never ends on its own. Run this only
// once the relayer's key has been dealt with: replaced, or shown to be safe.
//
//   npx tsx scripts/clear-relayer-halt.ts            shows what is set, clears nothing
//   npx tsx scripts/clear-relayer-halt.ts --confirm  clears it and prints what it cleared

const ENV_PATH = fileURLToPath(new URL("../.env", import.meta.url));

async function main(): Promise<number> {
  if (existsSync(ENV_PATH)) process.loadEnvFile(ENV_PATH);
  const env = loadEnv();
  const relayer = await relayerFromMnemonic(requireRelayerMnemonic(env));
  const store = UpstashStore.connect({ url: env.UPSTASH_REDIS_REST_URL, token: env.UPSTASH_REDIS_REST_TOKEN });
  const now = Date.now();
  console.log(`relayer:   ${relayer.qor1} (${relayer.evm})`);

  if (!process.argv.slice(2).includes("--confirm")) {
    console.log(`halted:    ${(await isHalted(store, now)) ? "yes" : "no"}`);
    console.log(`${HALT_KEY}: ${(await store.get(HALT_KEY)) ?? "(not set)"}`);
    console.log(`expected nonce: ${(await store.get(nonceKey(relayer.evm))) ?? "(not set)"}`);
    console.error("Refusing: nothing was cleared. Run again with --confirm once the relayer's key has been dealt with.");
    return 1;
  }

  const cleared = await clearHalt(store, relayer.evm, now);
  console.log(`cleared halt flag:          ${cleared.halt ?? "(was not set)"}`);
  console.log(`cleared day flag (old form): ${cleared.dayHalt ?? "(was not set)"}`);
  console.log(`cleared expected nonce:     ${cleared.nonce ?? "(was not set)"}; the next relay adopts the chain's`);
  return 0;
}

main().then(
  (code) => process.exit(code),
  (error: unknown) => {
    console.error(error instanceof Error ? error.message : "clear-relayer-halt failed.");
    process.exit(1);
  },
);
