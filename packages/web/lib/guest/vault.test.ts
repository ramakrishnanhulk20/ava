// Covers the passphrase vault's own promises (threat model C18): what it writes, what opens it and
// what never does. Does NOT cover the browser's localStorage itself, the strength of a passphrase a
// guest chooses, or how long 600,000 PBKDF2 rounds take on a slow phone.
import { describe, expect, it } from "vitest";
import { MIN_PASSPHRASE_LENGTH, PBKDF2_ITERATIONS, PassphraseTooShort, VaultLocked, openVault, sealPhrase } from "./vault";

const PHRASE = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
const QOR1 = "qor1g7rde5fszsedm7hktcxs389aa7nve63y4hpfwy";
const PASSPHRASE = "correct horse battery";

function tampered(record: string, change: (fields: Record<string, unknown>) => void): string {
  const fields = JSON.parse(record) as Record<string, unknown>;
  change(fields);
  return JSON.stringify(fields);
}

function flipFirstByte(base64: string): string {
  const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
  bytes[0] = (bytes[0] ?? 0) ^ 1;
  return btoa(String.fromCharCode(...bytes));
}

describe("the passphrase vault", () => {
  it("opens with the passphrase that sealed it and gives the phrase back", async () => {
    const record = await sealPhrase(PHRASE, PASSPHRASE, QOR1);
    await expect(openVault(record, PASSPHRASE)).resolves.toEqual({ phrase: PHRASE, qor1: QOR1 });
  });

  it("stays locked for any other passphrase", async () => {
    const record = await sealPhrase(PHRASE, PASSPHRASE, QOR1);
    await expect(openVault(record, "correct horse battery!")).rejects.toBeInstanceOf(VaultLocked);
    await expect(openVault(record, "")).rejects.toBeInstanceOf(VaultLocked);
  });

  it("refuses to seal under a passphrase shorter than the minimum, counted after normalising", async () => {
    await expect(sealPhrase(PHRASE, "a".repeat(MIN_PASSPHRASE_LENGTH - 1), QOR1)).rejects.toBeInstanceOf(PassphraseTooShort);
    await expect(sealPhrase(PHRASE, `   ${"a".repeat(MIN_PASSPHRASE_LENGTH - 1)}   `, QOR1)).rejects.toBeInstanceOf(PassphraseTooShort);
    await expect(sealPhrase(PHRASE, "a".repeat(MIN_PASSPHRASE_LENGTH), QOR1)).resolves.toBeTypeOf("string");
  });

  it("writes neither the phrase nor the passphrase, and records the fixed cost", async () => {
    const record = await sealPhrase(PHRASE, PASSPHRASE, QOR1);
    expect(record).not.toContain("legal");
    expect(record).not.toContain("sausage");
    expect(record).not.toContain(PASSPHRASE);
    const fields = JSON.parse(record) as Record<string, unknown>;
    expect(fields.kdf).toBe("PBKDF2-SHA-256");
    expect(fields.iterations).toBe(PBKDF2_ITERATIONS);
    expect(PBKDF2_ITERATIONS).toBeGreaterThanOrEqual(600_000);
    expect(fields.qor1).toBe(QOR1);
  });

  it("uses a fresh salt and nonce for every seal", async () => {
    const [a, b] = await Promise.all([sealPhrase(PHRASE, PASSPHRASE, QOR1), sealPhrase(PHRASE, PASSPHRASE, QOR1)]);
    const [fa, fb] = [JSON.parse(a), JSON.parse(b)] as [Record<string, string>, Record<string, string>];
    expect(fa.salt).not.toBe(fb.salt);
    expect(fa.iv).not.toBe(fb.iv);
    expect(fa.ct).not.toBe(fb.ct);
  });

  it("opens for the same passphrase typed in another Unicode form", async () => {
    const record = await sealPhrase(PHRASE, "café au lait 2026", QOR1);
    await expect(openVault(record, "café au lait 2026")).resolves.toMatchObject({ phrase: PHRASE });
    await expect(openVault(record, "ｃafé au lait 2026")).resolves.toMatchObject({ phrase: PHRASE });
  });

  it("stays locked when any stored field was changed", async () => {
    const record = await sealPhrase(PHRASE, PASSPHRASE, QOR1);
    const other = "qor1xss2hc8w33twyssdzejd7hepmd3qxgywvplhff";
    const changes: Array<(f: Record<string, unknown>) => void> = [
      (f) => (f.ct = flipFirstByte(f.ct as string)),
      (f) => (f.iv = flipFirstByte(f.iv as string)),
      (f) => (f.salt = flipFirstByte(f.salt as string)),
      (f) => (f.qor1 = other),
      (f) => (f.v = 2),
      (f) => (f.kdf = "PBKDF2-SHA-1"),
      (f) => (f.extra = "x"),
      (f) => delete f.salt,
    ];
    for (const change of changes) {
      await expect(openVault(tampered(record, change), PASSPHRASE)).rejects.toBeInstanceOf(VaultLocked);
    }
  });

  it("refuses a record whose cost is below the minimum or absurdly high, without deriving a key", async () => {
    const record = await sealPhrase(PHRASE, PASSPHRASE, QOR1);
    for (const iterations of [1, 1000, PBKDF2_ITERATIONS - 1, 50_000_000, 1.5, "600000"]) {
      const started = performance.now();
      await expect(openVault(tampered(record, (f) => (f.iterations = iterations)), PASSPHRASE)).rejects.toBeInstanceOf(VaultLocked);
      expect(performance.now() - started).toBeLessThan(50);
    }
  });

  it("stays locked for anything that is not a vault record", async () => {
    for (const junk of ["", "null", "[]", "{}", "not json", PHRASE, '{"v":1}']) {
      await expect(openVault(junk, PASSPHRASE)).rejects.toBeInstanceOf(VaultLocked);
    }
  });
});
