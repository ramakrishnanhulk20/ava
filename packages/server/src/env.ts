import { REST, accountBytes, toHex } from "@ava/core";
import type { Address } from "viem";
import { z } from "zod";
import { isRelayerMnemonic, normalizeMnemonic } from "./chain/account.ts";

/**
 * Whether the value is exactly an https origin as the URL parser writes it: lowercase scheme and
 * host, no default port, no path, no query, no credentials and no trailing slash. Requiring the
 * parser's own form means a later string comparison and a parsed comparison always agree.
 */
export function isHttpsOrigin(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return url.protocol === "https:" && url.origin === value;
}

function isHttpsUrl(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return url.protocol === "https:" && url.username === "" && url.password === "";
}

const blankToUndefined = (value: unknown): unknown => (value === "" ? undefined : value);
const secret = z.preprocess(blankToUndefined, z.string().min(1));
// Optional so the proxy and upload run without these accounts; each require function below refuses
// to start its endpoint without one. When set it must be 24 valid words, kept in normalised form.
const phrase = () => z.preprocess(blankToUndefined, z.string().refine(isRelayerMnemonic).transform(normalizeMnemonic).optional());

const MAX_UINT256 = (1n << 256n) - 1n;
/** A board id: a positive whole number in canonical decimal (no sign, no leading zeros), within uint256. */
const boardId = z.preprocess(
  blankToUndefined,
  z
    .string()
    .regex(/^[1-9][0-9]{0,77}$/)
    .transform((s) => BigInt(s))
    .refine((n) => n <= MAX_UINT256)
    .optional(),
);

/** The seeded demo directors are three; the cap only stops a pasted list from being used as storage. */
const MAX_SEEDED = 16;
/**
 * A comma-separated list of accounts, each decoded by the shared address codec (threat model C16)
 * and kept in EIP-55 form. An empty entry, an entry that does not decode, or one account twice
 * makes the whole key invalid.
 */
const accountList = z.preprocess(
  blankToUndefined,
  z
    .string()
    .max(2048)
    .transform((raw, ctx): readonly Address[] => {
      const out: Address[] = [];
      for (const part of raw.split(",")) {
        let account: Address;
        try {
          account = toHex(accountBytes(part.trim()));
        } catch {
          ctx.addIssue({ code: "custom", message: "not an address" });
          return z.NEVER;
        }
        if (out.includes(account)) {
          ctx.addIssue({ code: "custom", message: "an account is listed twice" });
          return z.NEVER;
        }
        out.push(account);
      }
      if (out.length > MAX_SEEDED) {
        ctx.addIssue({ code: "custom", message: "too many accounts" });
        return z.NEVER;
      }
      return Object.freeze(out);
    })
    .optional(),
);

const schema = z.object({
  UPSTASH_REDIS_REST_URL: z.preprocess(blankToUndefined, z.string().refine(isHttpsUrl)),
  UPSTASH_REDIS_REST_TOKEN: secret,
  BLOB_READ_WRITE_TOKEN: secret,
  BLOB_ORIGIN: z.preprocess(blankToUndefined, z.string().refine(isHttpsOrigin)),
  REST_UPSTREAM: z.preprocess((value) => blankToUndefined(value) ?? REST, z.string().refine(isHttpsOrigin)),
  RELAYER_MNEMONIC: phrase(),
  SPONSOR_MNEMONIC: phrase(),
  DEMO_CHAIR_MNEMONIC: phrase(),
  // Optional until the demo board is seeded; the demo endpoints answer 503 not_ready without it.
  DEMO_BOARD_ID: boardId,
  // The seeded directors, never removed by the guest sweep.
  DEMO_SEEDED: accountList,
});

export type ServerEnv = Readonly<z.infer<typeof schema>>;

/** The server's settings are missing or malformed. The message names the keys, never their values. */
export class EnvError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvError";
  }
}

/**
 * Reads and checks the server's settings once, at boot.
 *
 * @param source The environment to read, `process.env` by default.
 * @returns The settings, frozen. REST_UPSTREAM falls back to the QoreChain testnet REST.
 * @throws EnvError naming every missing or invalid key. Values are never echoed, because some of
 *   them are secrets.
 */
export function loadEnv(source: Record<string, string | undefined> = process.env): ServerEnv {
  const parsed = schema.safeParse(source);
  if (parsed.success) return Object.freeze(parsed.data);
  const keys = [...new Set(parsed.error.issues.map((issue) => String(issue.path[0] ?? "")))].filter(Boolean);
  const missing = keys.filter((key) => source[key] === undefined || source[key] === "");
  const invalid = keys.filter((key) => !missing.includes(key));
  const parts = [
    missing.length > 0 ? `missing ${missing.join(", ")}` : "",
    invalid.length > 0 ? `invalid ${invalid.join(", ")}` : "",
  ].filter(Boolean);
  throw new EnvError(`Server settings ${parts.join("; ")}. Each key is described in packages/server/.env.example.`);
}

type PhraseKey = "RELAYER_MNEMONIC" | "SPONSOR_MNEMONIC" | "DEMO_CHAIR_MNEMONIC";

function requirePhrase(env: Partial<Pick<ServerEnv, PhraseKey>>, key: PhraseKey): string {
  const value = env[key];
  if (value === undefined) throw new EnvError(`Server settings missing ${key}. Each key is described in packages/server/.env.example.`);
  return value;
}

/**
 * The relayer's phrase from loaded settings, for wiring the relay endpoint.
 *
 * @throws EnvError naming RELAYER_MNEMONIC, never its value, when it is not set.
 */
export function requireRelayerMnemonic(env: Pick<ServerEnv, "RELAYER_MNEMONIC">): string {
  return requirePhrase(env, "RELAYER_MNEMONIC");
}

/**
 * The sponsor's phrase from loaded settings, for wiring the sponsor endpoint.
 *
 * @throws EnvError naming SPONSOR_MNEMONIC, never its value, when it is not set.
 */
export function requireSponsorMnemonic(env: Pick<ServerEnv, "SPONSOR_MNEMONIC">): string {
  return requirePhrase(env, "SPONSOR_MNEMONIC");
}

/**
 * The demo chair's phrase from loaded settings. Only the demo bot's own functions may call this
 * (threat model C37): the phrase is the demo chair account's whole protection once the drill
 * publishes its classical key.
 *
 * @throws EnvError naming DEMO_CHAIR_MNEMONIC, never its value, when it is not set.
 */
export function requireDemoChairMnemonic(env: Pick<ServerEnv, "DEMO_CHAIR_MNEMONIC">): string {
  return requirePhrase(env, "DEMO_CHAIR_MNEMONIC");
}
