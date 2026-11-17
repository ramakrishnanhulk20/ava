// Not covered here: the real endpoint (a separate live run read a registered key from testnet on
// 16 Nov 2026), and whether a genuine key belongs to the person the chair meant.
import { generateSealKeys } from "@qorechain/qoreseal";
import { bytesToHex, hexToBytes } from "viem";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AddressError, toQor1 } from "../src/address.ts";
import { EVM_RPC } from "../src/constants.ts";
import { KemKeyUnavailable, fetchKemKey, type KemKeyFailure } from "../src/kem.ts";

const REQUESTED = "0x4786dCd1301432DDFaF65e0d089CbDEFA6ccEa24";
const SOMEONE_ELSE = "0x8A37d6f2DA1F8a07f1735c568C2611205d93e973";
const KEY = generateSealKeys().mlkemPublicKey;

type Result = Record<string, unknown>;

function answer(result: Result | null, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { jsonrpc: "2.0", id: 1, result, ...extra };
}
const found = (overrides: Result = {}): Result => ({
  address: REQUESTED.toLowerCase(),
  found: true,
  algorithm_id: 2,
  algorithm_name: "ml-kem-1024",
  public_key: bytesToHex(KEY),
  registered_height: "10180000",
  ...overrides,
});

function stub(respond: (init: RequestInit) => Promise<Response> | Response) {
  const calls: { url: string; init: RequestInit }[] = [];
  vi.stubGlobal("fetch", async (url: URL | string, init: RequestInit) => {
    calls.push({ url: String(url), init });
    return respond(init);
  });
  return calls;
}
const json = (body: unknown, status = 200) => new Response(typeof body === "string" ? body : JSON.stringify(body), { status });

async function failure(promise: Promise<unknown>): Promise<KemKeyFailure | string> {
  try {
    await promise;
    return "RETURNED A KEY";
  } catch (err) {
    return err instanceof KemKeyUnavailable ? err.reason : `other: ${String(err)}`;
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchKemKey", () => {
  it("returns the key when the answer is for this account, algorithm 2, 1,568 valid bytes", async () => {
    const calls = stub(() => json(answer(found())));
    expect(await fetchKemKey(REQUESTED)).toEqual(KEY);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe(`${EVM_RPC}/`);
    expect(calls[0]!.init.method).toBe("POST");
    expect(calls[0]!.init.redirect).toBe("error");
    expect(JSON.parse(String(calls[0]!.init.body))).toEqual({ jsonrpc: "2.0", id: 1, method: "qor_getKEMKey", params: [REQUESTED] });
  });

  it("accepts the qor1 form of the same account in the answer", async () => {
    stub(() => json(answer(found({ address: toQor1(hexToBytes(REQUESTED)) }))));
    expect(await fetchKemKey(REQUESTED.toLowerCase())).toEqual(KEY);
  });

  it("refuses an answer whose address differs from the request", async () => {
    stub(() => json(answer(found({ address: SOMEONE_ELSE }))));
    expect(await failure(fetchKemKey(REQUESTED))).toBe("WRONG_ACCOUNT");
  });

  it("refuses found false", async () => {
    stub(() => json(answer({ address: REQUESTED.toLowerCase(), found: false })));
    expect(await failure(fetchKemKey(REQUESTED))).toBe("NOT_FOUND");
  });

  it("refuses another algorithm, a short key and a key that fails the ML-KEM check", async () => {
    stub(() => json(answer(found({ algorithm_id: 1 }))));
    expect(await failure(fetchKemKey(REQUESTED))).toBe("WRONG_ALGORITHM");
    stub(() => json(answer(found({ algorithm_id: "2" }))));
    expect(await failure(fetchKemKey(REQUESTED))).toBe("WRONG_ALGORITHM");
    stub(() => json(answer(found({ public_key: bytesToHex(KEY.subarray(1)) }))));
    expect(await failure(fetchKemKey(REQUESTED))).toBe("INVALID_KEY");
    stub(() => json(answer(found({ public_key: bytesToHex(new Uint8Array(1568).fill(0xff)) }))));
    expect(await failure(fetchKemKey(REQUESTED))).toBe("INVALID_KEY");
  });

  it("refuses malformed answers", async () => {
    for (const body of [
      "not json",
      answer(null),
      answer(found(), { id: 2 }),
      answer(found(), { error: { code: -32601, message: "Method not found" } }),
      answer(found({ found: "true" })),
      answer(found({ address: undefined })),
      answer(found({ address: REQUESTED.slice(0, 5) + REQUESTED.slice(5).toUpperCase() })),
      answer(found({ public_key: `0x${"zz".repeat(1568)}` })),
      `{"padding":"${"x".repeat(20_000)}"}`,
    ]) {
      stub(() => json(body));
      expect(await failure(fetchKemKey(REQUESTED))).toBe("MALFORMED");
    }
  });

  it("refuses an HTTP error and a network failure", async () => {
    stub(() => json(answer(found()), 502));
    expect(await failure(fetchKemKey(REQUESTED))).toBe("NETWORK");
    stub(() => Promise.reject(new TypeError("fetch failed")));
    expect(await failure(fetchKemKey(REQUESTED))).toBe("NETWORK");
  });

  it("gives up after the timeout", async () => {
    stub(
      (init) =>
        new Promise<Response>((_, reject) => {
          init.signal?.addEventListener("abort", () => reject(init.signal?.reason));
        }),
    );
    expect(await failure(fetchKemKey(REQUESTED, { timeoutMs: 50 }))).toBe("TIMEOUT");
  });

  it("refuses a bad address and a non-https endpoint before any request", async () => {
    const calls = stub(() => json(answer(found())));
    await expect(fetchKemKey("0x4786dcd1301432DDFaF65e0d089CbDEFA6ccEa24")).rejects.toThrow(AddressError);
    await expect(fetchKemKey(REQUESTED, { rpc: "http://evm-testnet.qore.host" })).rejects.toThrow(TypeError);
    expect(calls).toHaveLength(0);
  });
});
