// Covers when the page may say a pack is shut to this browser (threat model C38, C39, C47): only after
// every envelope of the pack's epoch refused the keys held here, and never from a read that failed.
// Does NOT cover the downloads themselves, the registry reads, or QoreSeal's own refusal (core's tests).
import { describe, expect, it } from "vitest";
import { PackOpened, hexRowsOf, tryEveryEnvelope, tryOldKey } from "./shut";

const grant = (n: number) => ({ envelopeHash: `0x${n.toString(16).padStart(64, "0")}` as `0x${string}`, envelopeSize: 100 + n, mode: 0, member: "0x0000000000000000000000000000000000000000" as `0x${string}` });
const notRecipient = (): never => {
  throw Object.assign(new Error("These keys hold no entry in the envelope."), { code: "NOT_A_RECIPIENT" });
};
const load = async (): Promise<Uint8Array> => new Uint8Array(4);

describe("tryEveryEnvelope", () => {
  it("counts an epoch as shut only when every envelope refuses the keys as not a recipient", async () => {
    const tried: string[] = [];
    const refused = await tryEveryEnvelope([grant(1), grant(2), grant(3)], load, (g) => {
      tried.push(g.envelopeHash);
      return notRecipient();
    });
    expect(refused).toBe(3);
    expect(tried).toEqual([grant(1).envelopeHash, grant(2).envelopeHash, grant(3).envelopeHash]);
  });

  it("stops with PackOpened the moment one envelope opens", async () => {
    const run = tryEveryEnvelope([grant(1), grant(2)], load, (g) => (g.envelopeHash === grant(2).envelopeHash ? new Uint8Array(32) : notRecipient()));
    await expect(run).rejects.toBeInstanceOf(PackOpened);
  });

  it("gives no verdict when an envelope cannot be read", async () => {
    const run = tryEveryEnvelope(
      [grant(1), grant(2)],
      async (g) => {
        if (g.envelopeHash === grant(2).envelopeHash) throw new Error("The blob store answered 503.");
        return new Uint8Array(4);
      },
      notRecipient,
    );
    await expect(run).rejects.toThrow("The blob store answered 503.");
  });

  it("gives no verdict when an envelope fails for any reason but not being a recipient", async () => {
    const run = tryEveryEnvelope([grant(1)], load, () => {
      throw new Error("The envelope is not the size the registry recorded.");
    });
    await expect(run).rejects.toThrow("not the size");
  });

  it("gives no verdict for an epoch with no envelope on chain", async () => {
    await expect(tryEveryEnvelope([], load, notRecipient)).rejects.toThrow(/no envelope/);
  });
});

describe("tryOldKey", () => {
  it("is refused when the pack fails to authenticate under the earlier key", async () => {
    const failed = Object.assign(new Error("The document failed to decrypt."), { name: "DocumentError" });
    await expect(tryOldKey(async () => Promise.reject(failed))).resolves.toBe("refused");
  });

  it("claims nothing when the attempt failed for another reason", async () => {
    await expect(tryOldKey(async () => Promise.reject(new Error("network")))).resolves.toBe("unknown");
  });

  it("stops with PackOpened if the earlier key opens the pack", async () => {
    await expect(tryOldKey(async () => new Uint8Array(3))).rejects.toBeInstanceOf(PackOpened);
  });
});

describe("hexRowsOf", () => {
  it("prints the bytes as rows of lowercase pairs, as many rows as the bytes fill", () => {
    const bytes = Uint8Array.from({ length: 20 }, (_, i) => i * 13);
    expect(hexRowsOf(bytes, 3, 8)).toEqual(["00 0d 1a 27 34 41 4e 5b", "68 75 82 8f 9c a9 b6 c3", "d0 dd ea f7"]);
  });

  it("prints nothing for no bytes", () => {
    expect(hexRowsOf(new Uint8Array(0), 9, 17)).toEqual([]);
  });
});
