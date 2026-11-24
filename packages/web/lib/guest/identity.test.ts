// Covers what a guest's browser keeps and how it gets it back (threat model C16, C18): only a
// passphrase vault is ever written, a wrong passphrase leaves everything as it was, and a phrase an
// earlier build kept unprotected is locked on its next use. Does NOT cover a real browser's
// localStorage quotas or private-mode behaviour, or the chain side of the identity.
import { generateMnemonic } from "@ava/core";
import { describe, expect, it } from "vitest";
import {
  GuestAlreadyStored,
  LEGACY_PHRASE_KEY,
  StorageUnavailable,
  VAULT_KEY,
  createGuest,
  forgetGuest,
  guestFromPhrase,
  protectStoredPhrase,
  restoreGuest,
  storedGuest,
  openGuest,
} from "./identity";
import { PassphraseTooShort, VaultLocked, sealPhrase, vaultAddress } from "./vault";

const PASSPHRASE = "a long demo passphrase";

class MemoryStorage implements Storage {
  protected readonly items = new Map<string, string>();
  get length(): number {
    return this.items.size;
  }
  clear(): void {
    this.items.clear();
  }
  getItem(key: string): string | null {
    return this.items.get(key) ?? null;
  }
  key(index: number): string | null {
    return [...this.items.keys()][index] ?? null;
  }
  removeItem(key: string): void {
    this.items.delete(key);
  }
  setItem(key: string, value: string): void {
    this.items.set(key, value);
  }
  keys(): string[] {
    return [...this.items.keys()];
  }
}

/** A browser that accepts every write and keeps none, as some private modes do. */
class ForgetfulStorage extends MemoryStorage {
  override setItem(): void {}
}

describe("the guest identity this browser keeps", () => {
  it("writes a new identity only as a passphrase vault", async () => {
    const store = new MemoryStorage();
    const session = await createGuest(PASSPHRASE, store);
    expect(session.resumed).toBe(false);
    expect(session.words).toHaveLength(24);
    expect(store.keys()).toEqual([VAULT_KEY]);
    const record = store.getItem(VAULT_KEY) ?? "";
    expect(vaultAddress(record)).toBe(session.guest.identity.qor1);
    expect(record).not.toContain(" ");
    expect(storedGuest(store)).toEqual({ kind: "vault", qor1: session.guest.identity.qor1 });
  });

  it("opens to the same account and words with the passphrase", async () => {
    const store = new MemoryStorage();
    const made = await createGuest(PASSPHRASE, store);
    const back = await openGuest(PASSPHRASE, store);
    expect(back.resumed).toBe(true);
    expect(back.guest.identity.evm).toBe(made.guest.identity.evm);
    expect(back.guest.identity.mldsa.publicKey).toEqual(made.guest.identity.mldsa.publicKey);
    expect(back.words).toEqual(made.words);
  });

  it("stays locked for a wrong passphrase and changes nothing", async () => {
    const store = new MemoryStorage();
    await createGuest(PASSPHRASE, store);
    const before = store.getItem(VAULT_KEY);
    await expect(openGuest("another long passphrase", store)).rejects.toBeInstanceOf(VaultLocked);
    expect(store.getItem(VAULT_KEY)).toBe(before);
  });

  it("never replaces an identity that is already stored", async () => {
    const store = new MemoryStorage();
    await createGuest(PASSPHRASE, store);
    const before = store.getItem(VAULT_KEY);
    await expect(createGuest("a second long passphrase", store)).rejects.toBeInstanceOf(GuestAlreadyStored);
    expect(store.getItem(VAULT_KEY)).toBe(before);
  });

  it("stores nothing when the passphrase is too short", async () => {
    const store = new MemoryStorage();
    await expect(createGuest("short", store)).rejects.toBeInstanceOf(PassphraseTooShort);
    expect(store.keys()).toEqual([]);
  });

  it("says so when the browser keeps nothing", async () => {
    await expect(createGuest(PASSPHRASE, new ForgetfulStorage())).rejects.toBeInstanceOf(StorageUnavailable);
  });

  it("locks a phrase an earlier build kept unprotected, and removes the unprotected copy", async () => {
    const store = new MemoryStorage();
    const phrase = generateMnemonic();
    store.setItem(LEGACY_PHRASE_KEY, phrase);
    expect(storedGuest(store)).toEqual({ kind: "unprotected" });
    const expected = await guestFromPhrase(phrase);
    const session = await protectStoredPhrase(PASSPHRASE, store);
    expect(session.resumed).toBe(true);
    expect(session.guest.identity.evm).toBe(expected.identity.evm);
    expect(store.keys()).toEqual([VAULT_KEY]);
    expect((await openGuest(PASSPHRASE, store)).guest.identity.evm).toBe(expected.identity.evm);
  });

  it("keeps the unprotected copy until the vault is safely written", async () => {
    const store = new MemoryStorage();
    store.setItem(LEGACY_PHRASE_KEY, generateMnemonic());
    await expect(protectStoredPhrase("short", store)).rejects.toBeInstanceOf(PassphraseTooShort);
    expect(store.keys()).toEqual([LEGACY_PHRASE_KEY]);
  });

  it("refuses a vault whose phrase derives another account than it names", async () => {
    const store = new MemoryStorage();
    const [a, b] = await Promise.all([guestFromPhrase(generateMnemonic()), guestFromPhrase(generateMnemonic())]);
    const phraseOfA = (await createGuest(PASSPHRASE, new MemoryStorage())).words.join(" ");
    store.setItem(VAULT_KEY, await sealPhrase(phraseOfA, PASSPHRASE, b.identity.qor1));
    await expect(openGuest(PASSPHRASE, store)).rejects.toBeInstanceOf(VaultLocked);
    expect(a.identity.qor1).not.toBe(b.identity.qor1);
  });

  it("reports what is stored without opening anything, and forgets on request", async () => {
    const store = new MemoryStorage();
    expect(storedGuest(store)).toEqual({ kind: "none" });
    store.setItem(VAULT_KEY, "{not a vault");
    expect(storedGuest(store)).toEqual({ kind: "damaged" });
    await expect(openGuest(PASSPHRASE, store)).rejects.toBeInstanceOf(VaultLocked);
    store.setItem(LEGACY_PHRASE_KEY, generateMnemonic());
    forgetGuest(store);
    expect(store.keys()).toEqual([]);
    expect(storedGuest(store)).toEqual({ kind: "none" });
  });
});

describe("restoring an identity from its recovery words", () => {
  it("brings back the same account and keys on a browser that holds nothing, as a vault under the new passphrase", async () => {
    const first = new MemoryStorage();
    const made = await createGuest(PASSPHRASE, first);
    const second = new MemoryStorage();
    const restored = await restoreGuest(made.words.join(" "), "another long passphrase", second);
    expect(restored.resumed).toBe(true);
    expect(restored.guest.identity.evm).toBe(made.guest.identity.evm);
    expect(restored.guest.identity.mldsa.publicKey).toEqual(made.guest.identity.mldsa.publicKey);
    expect(restored.guest.identity.seal.mlkemPublicKey).toEqual(made.guest.identity.seal.mlkemPublicKey);
    expect(second.keys()).toEqual([VAULT_KEY]);
    expect((second.getItem(VAULT_KEY) ?? "").includes(made.words[0] ?? "")).toBe(false);
    const back = await openGuest("another long passphrase", second);
    expect(back.words).toEqual(made.words);
  });

  it("takes the words however they were pasted: extra spaces, line breaks, a no-break space", async () => {
    const made = await createGuest(PASSPHRASE, new MemoryStorage());
    const pasted = `  ${made.words.slice(0, 12).join("  ")}\n${made.words.slice(12).join("\u00a0")}  `;
    const restored = await restoreGuest(pasted, PASSPHRASE, new MemoryStorage());
    expect(restored.guest.identity.qor1).toBe(made.guest.identity.qor1);
  });

  it("refuses words that are not a valid phrase, and writes nothing", async () => {
    const made = await createGuest(PASSPHRASE, new MemoryStorage());
    const store = new MemoryStorage();
    const swapped = [...made.words];
    swapped[3] = swapped[3] === "abandon" ? "ability" : "abandon";
    for (const bad of ["", made.words.slice(0, 23).join(" "), swapped.join(" "), "not words at all"]) {
      await expect(restoreGuest(bad, PASSPHRASE, store)).rejects.toThrow("The recovery phrase is not 24 valid words.");
    }
    expect(store.keys()).toEqual([]);
  });

  it("refuses a short passphrase before anything else, and never replaces an identity the browser already holds", async () => {
    const words = generateMnemonic();
    await expect(restoreGuest(words, "short", new MemoryStorage())).rejects.toBeInstanceOf(PassphraseTooShort);
    const store = new MemoryStorage();
    const held = await createGuest(PASSPHRASE, store);
    await expect(restoreGuest(words, PASSPHRASE, store)).rejects.toBeInstanceOf(GuestAlreadyStored);
    expect((await openGuest(PASSPHRASE, store)).guest.identity.qor1).toBe(held.guest.identity.qor1);
  });

  it("says so when the browser keeps nothing", async () => {
    await expect(restoreGuest(generateMnemonic(), PASSPHRASE, new ForgetfulStorage())).rejects.toBeInstanceOf(StorageUnavailable);
  });
});
