import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import { accountBytes, toHex } from "@ava/core";
import type { Hex } from "viem";
import { isHttpsOrigin } from "../../packages/server/src/env.ts";
import { isPhrase, normalizePhrase } from "./identities.ts";

export const ENV_PATH = fileURLToPath(new URL("../.env", import.meta.url));
export const KEY_NAME = "SECURITY_TESTNET_KEY";

/** What the suite reads from security/.env. Holds the wallet's phrase: never log or print it. */
export interface SuiteEnv {
  mnemonic: string;
  blobOrigin?: string;
  demoBoardId?: bigint;
  demoSeeded: readonly Hex[];
  drillKey?: Hex;
}

/** security/.env as parsed, never copied into process.env, so no child process inherits the phrase. */
export function readEnvFile(): Record<string, string | undefined> {
  return existsSync(ENV_PATH) ? parseEnv(readFileSync(ENV_PATH, "utf8")) : {};
}

const blank = (v: string | undefined): string | undefined => (v === undefined || v.trim() === "" ? undefined : v.trim());

/**
 * Reads and checks security/.env once. Messages name the key, never its value.
 *
 * @throws When SECURITY_TESTNET_KEY is missing or not 24 valid words, or any optional key is set
 *   but malformed.
 */
export function loadSuiteEnv(): SuiteEnv {
  const raw = readEnvFile();
  const phrase = blank(raw[KEY_NAME]);
  if (phrase === undefined || !isPhrase(phrase)) throw new Error(`${KEY_NAME} is not set to 24 valid words in ${ENV_PATH}. Run: npx tsx new-wallet.ts`);

  const blobOrigin = blank(raw.BLOB_ORIGIN);
  if (blobOrigin !== undefined && !isHttpsOrigin(blobOrigin)) throw new Error(`BLOB_ORIGIN in ${ENV_PATH} is not an https origin with no path.`);

  const board = blank(raw.DEMO_BOARD_ID);
  if (board !== undefined && !/^[1-9][0-9]{0,77}$/.test(board)) throw new Error(`DEMO_BOARD_ID in ${ENV_PATH} is not a board id.`);

  const seeded: Hex[] = [];
  for (const part of (blank(raw.DEMO_SEEDED) ?? "").split(",").map((p) => p.trim()).filter((p) => p !== "")) {
    try {
      seeded.push(toHex(accountBytes(part)));
    } catch {
      throw new Error(`DEMO_SEEDED in ${ENV_PATH} holds an entry that is not an address.`);
    }
  }

  const drill = blank(raw.DRILL_PUBLISHED_KEY);
  const drillKey = drill === undefined ? undefined : /^(0x)?[0-9a-fA-F]{64}$/.test(drill) ? (`0x${drill.replace(/^0x/, "").toLowerCase()}` as Hex) : null;
  if (drillKey === null) throw new Error(`DRILL_PUBLISHED_KEY in ${ENV_PATH} is not 32 bytes of hex.`);

  return {
    mnemonic: normalizePhrase(phrase),
    ...(blobOrigin === undefined ? {} : { blobOrigin }),
    ...(board === undefined ? {} : { demoBoardId: BigInt(board) }),
    demoSeeded: seeded,
    ...(drillKey === undefined ? {} : { drillKey }),
  };
}
