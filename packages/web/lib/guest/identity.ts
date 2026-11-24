import { canonicalPhrase, generateMnemonic, identityFromMnemonic, sameAccount, type Identity } from "@ava/core";
import { deriveUnifiedAccount, type UnifiedAccount } from "@qorechain/sdk";
import { VaultLocked, openVault, passphraseLongEnough, PassphraseTooShort, sealPhrase, vaultAddress } from "./vault";

/** Where the guest's passphrase vault lives in this browser, so a return visit can open the same identity. */
export const VAULT_KEY = "ava.guest.vault";
/**
 * Where an earlier build kept the phrase unprotected. Nothing writes it any more; it is read once,
 * to lock that phrase in a vault, and then removed (threat model C18).
 */
export const LEGACY_PHRASE_KEY = "ava.guest.phrase";

/**
 * Every key the guest has, rebuilt from its one recovery phrase. Holds secrets: never log, render,
 * send or serialise an instance of this.
 */
export interface GuestAccount {
  identity: Identity;
  /** The SDK's unified account, which the eth-native signer needs for the two key registrations. */
  unified: UnifiedAccount;
}

/** An open guest, held in memory for this page view only. A reload asks for the passphrase again. */
export interface GuestSession {
  guest: GuestAccount;
  /** The 24 recovery words, for the guest to read on request. Never stored, sent or logged. */
  words: readonly string[];
  /** Whether the identity was already in this browser before this page view. */
  resumed: boolean;
}

/** What this browser holds, told without opening anything. */
export type StoredGuest = { kind: "none" } | { kind: "vault"; qor1: string } | { kind: "unprotected" } | { kind: "damaged" };

/** This browser does not let the page keep anything, so a reload would lose the identity. */
export class StorageUnavailable extends Error {
  constructor() {
    super("This browser does not let the page keep your identity, so a reload would lose it. Try a normal window, not a private one.");
    this.name = "StorageUnavailable";
  }
}

/** An identity is already stored here; making a new one would destroy it. Forget me clears it first. */
export class GuestAlreadyStored extends Error {
  constructor() {
    super("This browser already holds an identity. Open it with your passphrase, or use Forget me first.");
    this.name = "GuestAlreadyStored";
  }
}

function browserStorage(): Storage {
  try {
    const store = window.localStorage;
    if (store === null || store === undefined) throw new StorageUnavailable();
    return store;
  } catch {
    throw new StorageUnavailable();
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/**
 * Rebuilds the guest from a phrase through @ava/core's identityFromMnemonic, plus the SDK's unified
 * account from the same canonical phrase (threat model C16), and refuses unless both name one
 * account and one ML-DSA-87 key, so the key the registration proves is the key that signs.
 *
 * @throws Error from canonicalPhrase for anything but 24 valid words, and when the two
 *   derivations disagree.
 */
export async function guestFromPhrase(phrase: string): Promise<GuestAccount> {
  const canonical = canonicalPhrase(phrase);
  const [identity, unified] = await Promise.all([identityFromMnemonic(canonical), deriveUnifiedAccount(canonical, 0)]);
  if (!sameAccount(unified.cosmos, identity.qor1) || !sameAccount(unified.evm, identity.evm)) {
    throw new Error("The identity and the signer derive different accounts. Refusing to continue.");
  }
  if (!sameBytes(unified.pqc.publicKey, identity.mldsa.publicKey)) {
    throw new Error("The identity and the signer derive different ML-DSA-87 keys. Refusing to continue.");
  }
  return { identity, unified };
}

/**
 * What this browser holds for the guest, read without a passphrase: only the vault's public
 * address ever leaves storage here. Never throws; a browser that keeps nothing holds none.
 */
export function storedGuest(store?: Storage): StoredGuest {
  try {
    const from = store ?? browserStorage();
    const vault = from.getItem(VAULT_KEY);
    if (vault !== null) {
      const qor1 = vaultAddress(vault);
      return qor1 === undefined ? { kind: "damaged" } : { kind: "vault", qor1 };
    }
    return from.getItem(LEGACY_PHRASE_KEY) === null ? { kind: "none" } : { kind: "unprotected" };
  } catch {
    return { kind: "none" };
  }
}

/** Writes the vault and reads it back, because some browsers accept a write and keep nothing. */
function keep(store: Storage, record: string): void {
  try {
    store.setItem(VAULT_KEY, record);
  } catch {
    throw new StorageUnavailable();
  }
  if (store.getItem(VAULT_KEY) !== record) throw new StorageUnavailable();
}

async function sealed(phrase: string, passphrase: string): Promise<{ guest: GuestAccount; canonical: string; record: string }> {
  const canonical = canonicalPhrase(phrase);
  const guest = await guestFromPhrase(canonical);
  return { guest, canonical, record: await sealPhrase(canonical, passphrase, guest.identity.qor1) };
}

/**
 * Makes a new guest identity and keeps it in this browser as a passphrase vault and nothing else
 * (threat model C18). The phrase never touches storage unencrypted.
 *
 * @throws PassphraseTooShort before anything is made. GuestAlreadyStored when this browser holds
 *   an identity of any kind, which is never replaced. StorageUnavailable when the browser keeps nothing.
 */
export async function createGuest(passphrase: string, store?: Storage): Promise<GuestSession> {
  const into = store ?? browserStorage();
  if (!passphraseLongEnough(passphrase)) throw new PassphraseTooShort();
  if (into.getItem(VAULT_KEY) !== null || into.getItem(LEGACY_PHRASE_KEY) !== null) throw new GuestAlreadyStored();
  const made = await sealed(generateMnemonic(), passphrase);
  keep(into, made.record);
  return { guest: made.guest, words: made.canonical.split(" "), resumed: false };
}

/**
 * Brings an identity back from its 24 recovery words on a browser that holds none, and keeps it
 * there as a passphrase vault (threat model C16, C18). The words are read through canonicalPhrase,
 * so they give the same account and the same keys however they were pasted, and they never touch
 * storage unencrypted. The account's keys and seats are on chain already; nothing is registered here.
 *
 * @throws PassphraseTooShort before anything is read. GuestAlreadyStored when this browser holds an
 *   identity of any kind, which is never replaced. Error "The recovery phrase is not 24 valid
 *   words." for anything else than a valid phrase. StorageUnavailable when the browser keeps nothing.
 */
export async function restoreGuest(phrase: string, passphrase: string, store?: Storage): Promise<GuestSession> {
  const into = store ?? browserStorage();
  if (!passphraseLongEnough(passphrase)) throw new PassphraseTooShort();
  if (into.getItem(VAULT_KEY) !== null || into.getItem(LEGACY_PHRASE_KEY) !== null) throw new GuestAlreadyStored();
  const made = await sealed(phrase, passphrase);
  keep(into, made.record);
  return { guest: made.guest, words: made.canonical.split(" "), resumed: true };
}

/**
 * Opens the identity this browser keeps. The vault is input: after it opens, the account is
 * derived again from the phrase and must be the one the vault names.
 *
 * @throws VaultLocked for a wrong passphrase, no vault, a changed or malformed one, or a phrase
 *   that derives another account. Storage is left exactly as it was.
 */
export async function openGuest(passphrase: string, store?: Storage): Promise<GuestSession> {
  const from = store ?? browserStorage();
  const record = from.getItem(VAULT_KEY);
  if (record === null) throw new VaultLocked();
  const opened = await openVault(record, passphrase);
  let guest: GuestAccount;
  let canonical: string;
  try {
    canonical = canonicalPhrase(opened.phrase);
    guest = await guestFromPhrase(canonical);
  } catch {
    throw new VaultLocked();
  }
  if (guest.identity.qor1 !== opened.qor1) throw new VaultLocked();
  return { guest, words: canonical.split(" "), resumed: true };
}

/**
 * Locks a phrase an earlier build kept unprotected: seals it under the passphrase, and removes the
 * unprotected copy only once the vault has been written and read back.
 *
 * @throws PassphraseTooShort, StorageUnavailable, or an Error when the kept phrase is not 24 valid
 *   words. In each case the unprotected copy is still there.
 */
export async function protectStoredPhrase(passphrase: string, store?: Storage): Promise<GuestSession> {
  const into = store ?? browserStorage();
  if (!passphraseLongEnough(passphrase)) throw new PassphraseTooShort();
  const kept = into.getItem(LEGACY_PHRASE_KEY);
  if (kept === null) throw new Error("This browser holds no unprotected phrase.");
  const made = await sealed(kept, passphrase);
  keep(into, made.record);
  into.removeItem(LEGACY_PHRASE_KEY);
  return { guest: made.guest, words: made.canonical.split(" "), resumed: true };
}

/** Deletes the guest from this browser. The account and its keys stay on chain, unreachable from here without the recovery words. */
export function forgetGuest(store?: Storage): void {
  const from = store ?? browserStorage();
  from.removeItem(VAULT_KEY);
  from.removeItem(LEGACY_PHRASE_KEY);
}
