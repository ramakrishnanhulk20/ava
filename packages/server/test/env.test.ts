// Not covered here: whether the keys work. A real Upstash database and Vercel Blob store are
// checked by the live runs, not by these tests, which never touch the network.
import { REST } from "@ava/core";
import { describe, expect, it } from "vitest";
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
});
