// Not covered here: whether the keys work. A real Upstash database and Vercel Blob store are
// checked by the live runs, not by these tests, which never touch the network.
import { REST, generateMnemonic, identityFromMnemonic } from "@ava/core";
import { describe, expect, it } from "vitest";
import { evmAddressOf, relayerFromMnemonic } from "../src/chain/account.ts";
import { EnvError, isHttpsOrigin, loadEnv } from "../src/env.ts";

const SECRET = "secret-value-that-must-never-appear";

function complete(): Record<string, string | undefined> {
  return {
    UPSTASH_REDIS_REST_URL: "https://example-db.upstash.io",
    UPSTASH_REDIS_REST_TOKEN: SECRET,
    BLOB_READ_WRITE_TOKEN: SECRET,
    BLOB_ORIGIN: "https://store123.public.blob.vercel-storage.com",
  };
}

describe("loadEnv", () => {
  it("loads a complete environment and defaults REST_UPSTREAM to the testnet REST", () => {
    const env = loadEnv(complete());
    expect(env.REST_UPSTREAM).toBe(REST);
    expect(env.REST_UPSTREAM).toBe("https://api-testnet.qore.host");
    expect(Object.isFrozen(env)).toBe(true);
  });

  it("names each missing key and never echoes a value", () => {
    const source = { ...complete(), UPSTASH_REDIS_REST_TOKEN: "", BLOB_ORIGIN: undefined, BLOB_READ_WRITE_TOKEN: undefined };
    let message = "";
    try {
      loadEnv(source);
    } catch (error) {
      expect(error).toBeInstanceOf(EnvError);
      message = (error as Error).message;
    }
    expect(message).toContain("missing UPSTASH_REDIS_REST_TOKEN, BLOB_READ_WRITE_TOKEN, BLOB_ORIGIN");
    expect(message).not.toContain(SECRET);
    expect(message).not.toContain("upstash.io");
  });

  it("refuses a blob origin or upstream that is not exactly an https origin", () => {
    for (const bad of [
      "http://store123.public.blob.vercel-storage.com",
      "https://store123.public.blob.vercel-storage.com/",
      "https://store123.public.blob.vercel-storage.com/path",
      "https://Store123.public.blob.vercel-storage.com",
      "https://user@store123.public.blob.vercel-storage.com",
      "not a url",
    ]) {
      expect(isHttpsOrigin(bad)).toBe(false);
      expect(() => loadEnv({ ...complete(), BLOB_ORIGIN: bad })).toThrow(/invalid BLOB_ORIGIN/);
      expect(() => loadEnv({ ...complete(), REST_UPSTREAM: bad })).toThrow(/invalid REST_UPSTREAM/);
    }
    expect(() => loadEnv({ ...complete(), UPSTASH_REDIS_REST_URL: "http://example-db.upstash.io" })).toThrow(
      /invalid UPSTASH_REDIS_REST_URL/,
    );
  });

  it("takes REST_UPSTREAM only when it is exactly the testnet REST", () => {
    expect(loadEnv({ ...complete(), REST_UPSTREAM: REST }).REST_UPSTREAM).toBe(REST);
    for (const other of ["https://evil.example", "https://api-mainnet.qore.host", "https://rpc-testnet.qore.host"]) {
      expect(isHttpsOrigin(other)).toBe(true);
      expect(() => loadEnv({ ...complete(), REST_UPSTREAM: other })).toThrow(/invalid REST_UPSTREAM/);
    }
  });

  it("refuses DEMO_BOARD_ID without DEMO_SEEDED, so the seeded directors are never taken for guests", () => {
    const seeded = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
    expect(loadEnv({ ...complete(), DEMO_BOARD_ID: "12", DEMO_SEEDED: seeded }).DEMO_BOARD_ID).toBe(12n);
    for (const missing of [undefined, ""]) {
      expect(() => loadEnv({ ...complete(), DEMO_BOARD_ID: "12", DEMO_SEEDED: missing })).toThrow(/missing DEMO_SEEDED/);
    }
    expect(loadEnv(complete()).DEMO_BOARD_ID).toBeUndefined();
  });
});

describe("loadEnv: one account per role", () => {
  const relayer = generateMnemonic();
  const sponsor = generateMnemonic();
  const chair = generateMnemonic();

  it("derives each phrase's address exactly as the relayer, sponsor and demo chair accounts are derived", async () => {
    for (const phrase of [relayer, chair]) {
      expect(evmAddressOf(phrase)).toBe((await relayerFromMnemonic(phrase)).evm);
      expect(evmAddressOf(phrase)).toBe((await identityFromMnemonic(phrase)).evm);
    }
  });

  it("refuses to start when any two roles derive one account, however the phrase is spaced, and never echoes it", () => {
    const spaced = `  ${relayer.split(" ").join("   ")} `;
    const pairs: [string, Record<string, string>][] = [
      ["RELAYER_MNEMONIC, SPONSOR_MNEMONIC", { RELAYER_MNEMONIC: relayer, SPONSOR_MNEMONIC: spaced, DEMO_CHAIR_MNEMONIC: chair }],
      ["RELAYER_MNEMONIC, DEMO_CHAIR_MNEMONIC", { RELAYER_MNEMONIC: relayer, SPONSOR_MNEMONIC: sponsor, DEMO_CHAIR_MNEMONIC: relayer }],
      ["SPONSOR_MNEMONIC, DEMO_CHAIR_MNEMONIC", { SPONSOR_MNEMONIC: chair, DEMO_CHAIR_MNEMONIC: chair }],
    ];
    for (const [named, phrases] of pairs) {
      let message = "";
      try {
        loadEnv({ ...complete(), ...phrases });
      } catch (error) {
        expect(error).toBeInstanceOf(EnvError);
        message = (error as Error).message;
      }
      expect(message).toContain(named);
      expect(message).toContain("same account");
      for (const phrase of Object.values(phrases)) expect(message).not.toContain(phrase.trim().split(/\s+/).slice(0, 3).join(" "));
    }
    const env = loadEnv({ ...complete(), RELAYER_MNEMONIC: relayer, SPONSOR_MNEMONIC: sponsor, DEMO_CHAIR_MNEMONIC: chair });
    expect(env.RELAYER_MNEMONIC).toBe(relayer);
  });
});
