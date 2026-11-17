// Not covered here: that a KEM key belongs to the address it is sealed to (kem.test.ts and the live
// check), that the hash and size passed in are the ones the registry recorded (the caller reads them
// from chain), and QoreSeal's own cryptography, which its maintainers test and which is pending
// external review.
import { generateSealKeys, isQoreSealError, parseEnvelope, seal, type SealKeyPair } from "@qorechain/qoreseal";
import { bytesToHex, hexToBytes, type Hex } from "viem";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { MAX_ENVELOPE_SIZE, MAX_MEMBERS } from "../src/constants.ts";
import { HashMismatch, assertHash, sameHash, sha256 } from "../src/hash.ts";
import {
  DocumentError,
  EnvelopeError,
  decryptDocument,
  encryptDocument,
  newBoardRef,
  newDocRef,
  newEpochKey,
  openEpochKey,
  placeOf,
  purposeFor,
  sealEpochKey,
} from "../src/seal.ts";

const REGISTRY = "0x00000000000000000000000000000000000a0a0a";
const OTHER_REGISTRY = "0x00000000000000000000000000000000000b0b0b";
const ALICE = "0x1111111111111111111111111111111111111111";
const BOB = "0x2222222222222222222222222222222222222222";
const ZERO_REF = `0x${"00".repeat(32)}` as Hex;

let alice: SealKeyPair;
let bob: SealKeyPair;
let stranger: SealKeyPair;
let boardRef: Uint8Array;

beforeAll(() => {
  alice = generateSealKeys();
  bob = generateSealKeys();
  stranger = generateSealKeys();
  boardRef = newBoardRef();
});

afterEach(() => {
  vi.restoreAllMocks();
});

function qoreSealCode(fn: () => unknown): string {
  try {
    fn();
    return "OPENED";
  } catch (err) {
    return isQoreSealError(err) ? err.code : err instanceof Error ? err.name : "unknown";
  }
}

/** A stand-in for a key that records, and refuses, any use at all. */
function trap<T extends object>(target: T): { value: T; touched: () => boolean } {
  let touched = false;
  const refuse = (): never => {
    touched = true;
    throw new Error("KEY TOUCHED");
  };
  const value = new Proxy(target, { get: refuse, has: refuse, ownKeys: refuse, getPrototypeOf: refuse, getOwnPropertyDescriptor: refuse });
  return { value, touched: () => touched };
}

function sealTwo(epochKey: Uint8Array, epoch = 4n, ref: Uint8Array = boardRef): Uint8Array {
  return sealEpochKey({
    registry: REGISTRY,
    boardRef: ref,
    epoch,
    epochKey,
    recipients: [
      { address: ALICE, kemPublicKey: alice.mlkemPublicKey },
      { address: BOB, kemPublicKey: bob.mlkemPublicKey },
    ],
  });
}

/** What the registry recorded for an envelope: its SHA-256 and its size. */
const recorded = (bytes: Uint8Array) => ({ expectedHash: sha256(bytes), expectedSize: bytes.length });

describe("random references and keys", () => {
  it("are 32 fresh, non-zero random bytes each time", () => {
    for (const make of [newEpochKey, newDocRef, newBoardRef]) {
      const a = make();
      const b = make();
      expect(a).toHaveLength(32);
      expect(a.some((x) => x !== 0)).toBe(true);
      expect(sameHash(a, b)).toBe(false);
    }
  });
});

describe("place and purpose", () => {
  it("place is SHA-256(registry 20 bytes || boardRef 32 bytes)", async () => {
    const input = Uint8Array.from([...hexToBytes(REGISTRY), ...boardRef]);
    const expected = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", input));
    expect(placeOf(REGISTRY, boardRef)).toEqual(expected);
    expect(placeOf(REGISTRY, bytesToHex(boardRef).toUpperCase().replace("0X", "0x") as Hex)).toEqual(expected);
  });

  it("purpose is ava/<place hex>/<epoch>, at most 89 characters", () => {
    const placeHex = bytesToHex(placeOf(REGISTRY, boardRef)).slice(2);
    expect(purposeFor(REGISTRY, boardRef, 4n)).toBe(`ava/${placeHex}/4`);
    expect(purposeFor(REGISTRY, boardRef, (1n << 64n) - 1n)).toHaveLength(89);
    expect(() => purposeFor(REGISTRY, boardRef, 1n << 64n)).toThrow(EnvelopeError);
  });

  it("refuses a zero or malformed boardRef everywhere", async () => {
    expect(() => placeOf(REGISTRY, ZERO_REF)).toThrow(EnvelopeError);
    expect(() => placeOf(REGISTRY, new Uint8Array(31).fill(1))).toThrow(EnvelopeError);
    expect(() => purposeFor(REGISTRY, ZERO_REF, 0n)).toThrow(EnvelopeError);
    expect(() => sealTwo(newEpochKey(), 0n, hexToBytes(ZERO_REF))).toThrow(EnvelopeError);
    const plaintext = new Uint8Array(10);
    await expect(encryptDocument({ epochKey: newEpochKey(), registry: REGISTRY, boardRef: ZERO_REF, epoch: 0n, docRef: newDocRef(), plaintext })).rejects.toThrow(DocumentError);
  });
});

describe("sealEpochKey and openEpochKey", () => {
  it("seal to two recipients, and each one opens it", () => {
    const epochKey = newEpochKey();
    const envelope = sealTwo(epochKey);
    const parsed = parseEnvelope(envelope);
    expect(parsed.mode).toBe("mlkem");
    expect(parsed.anonymous).toBe(false);
    expect(parsed.entries).toHaveLength(2);
    expect(envelope).toHaveLength(97 + 2 * 1632);
    for (const keys of [alice, bob]) {
      expect(openEpochKey({ registry: REGISTRY, boardRef, epoch: 4n, envelope, ...recorded(envelope), sealKeys: keys })).toEqual(epochKey);
    }
  });

  it("a third key pair fails with NOT_A_RECIPIENT", () => {
    const envelope = sealTwo(newEpochKey());
    expect(qoreSealCode(() => openEpochKey({ registry: REGISTRY, boardRef, epoch: 4n, envelope, ...recorded(envelope), sealKeys: stranger }))).toBe("NOT_A_RECIPIENT");
  });

  it("opening with the wrong epoch, board or registry fails (C13)", () => {
    const envelope = sealTwo(newEpochKey());
    for (const moved of [
      { registry: REGISTRY, boardRef, epoch: 5n },
      { registry: REGISTRY, boardRef: newBoardRef(), epoch: 4n },
      { registry: OTHER_REGISTRY, boardRef, epoch: 4n },
    ]) {
      expect(qoreSealCode(() => openEpochKey({ ...moved, envelope, ...recorded(envelope), sealKeys: alice }))).toBe("DECRYPTION_FAILED");
    }
  });

  it("an envelope moved between two boards the same chair created fails to open", () => {
    const first = newBoardRef();
    const second = newBoardRef();
    const envelope = sealTwo(newEpochKey(), 0n, first);
    expect(openEpochKey({ registry: REGISTRY, boardRef: first, epoch: 0n, envelope, ...recorded(envelope), sealKeys: alice })).toHaveLength(32);
    expect(qoreSealCode(() => openEpochKey({ registry: REGISTRY, boardRef: second, epoch: 0n, envelope, ...recorded(envelope), sealKeys: alice }))).toBe("DECRYPTION_FAILED");
  });

  it("an envelope moved to another epoch fails even when its purpose was rebuilt for that epoch", () => {
    const key = newEpochKey();
    const build = (version: number, payloadEpoch: number) =>
      seal({
        chainId: "qorechain-diana",
        purpose: purposeFor(REGISTRY, boardRef, 5n),
        recipients: [{ mlkemPublicKey: alice.mlkemPublicKey }],
        plaintext: Uint8Array.from([version, 0, 0, 0, 0, 0, 0, 0, payloadEpoch, ...key]),
        mode: "mlkem",
      });
    for (const envelope of [build(0x01, 4), build(0x02, 5)]) {
      expect(() => openEpochKey({ registry: REGISTRY, boardRef, epoch: 5n, envelope, ...recorded(envelope), sealKeys: alice })).toThrow(EnvelopeError);
    }
  });

  it("one changed byte or a wrong size is refused before the keys are touched (C12)", () => {
    const envelope = sealTwo(newEpochKey());
    const changed = Uint8Array.from(envelope);
    changed[changed.length - 1] = changed[changed.length - 1]! ^ 0x01;
    const keys = trap(alice);
    const place = { registry: REGISTRY, boardRef, epoch: 4n, sealKeys: keys.value };
    expect(() => openEpochKey({ ...place, envelope: changed, ...recorded(envelope) })).toThrow(HashMismatch);
    expect(() => openEpochKey({ ...place, envelope, expectedHash: sha256(envelope), expectedSize: envelope.length + 1 })).toThrow(EnvelopeError);
    expect(() => openEpochKey({ ...place, envelope: envelope.subarray(1), ...recorded(envelope) })).toThrow(EnvelopeError);
    expect(() => openEpochKey({ ...place, envelope, expectedHash: sha256(envelope), expectedSize: MAX_ENVELOPE_SIZE + 1 })).toThrow(EnvelopeError);
    expect(keys.touched()).toBe(false);
    expect(() => openEpochKey({ ...place, envelope, ...recorded(envelope) })).toThrow("KEY TOUCHED");
    expect(keys.touched()).toBe(true);
  });

  it("refuses a short key, no recipients, too many, a repeated account and a bad KEM key", () => {
    const one = [{ address: ALICE, kemPublicKey: alice.mlkemPublicKey }];
    const args = { registry: REGISTRY, boardRef, epoch: 4n };
    expect(() => sealEpochKey({ ...args, epochKey: new Uint8Array(31), recipients: one })).toThrow(EnvelopeError);
    expect(() => sealEpochKey({ ...args, epochKey: newEpochKey(), recipients: [] })).toThrow(EnvelopeError);
    expect(() => sealEpochKey({ ...args, epochKey: newEpochKey(), recipients: Array(MAX_MEMBERS + 1).fill(one[0]) })).toThrow(EnvelopeError);
    expect(() =>
      sealEpochKey({ ...args, epochKey: newEpochKey(), recipients: [one[0]!, { address: ALICE.toLowerCase(), kemPublicKey: bob.mlkemPublicKey }] }),
    ).toThrow(EnvelopeError);
    expect(qoreSealCode(() => sealEpochKey({ ...args, epochKey: newEpochKey(), recipients: [{ address: ALICE, kemPublicKey: new Uint8Array(1568).fill(0xff) }] }))).toBe(
      "INVALID_KEY",
    );
  });
});

describe("documents", () => {
  const plaintext = new TextEncoder().encode("Q3 board pack: confidential");
  const where = () => ({ registry: REGISTRY, boardRef, epoch: 4n });

  it("encrypt then decrypt", async () => {
    const epochKey = newEpochKey();
    const docRef = newDocRef();
    const ciphertext = await encryptDocument({ ...where(), epochKey, docRef, plaintext });
    expect(ciphertext).toHaveLength(12 + plaintext.length + 16);
    expect(await decryptDocument({ ...where(), epochKey, docRef, ciphertext, ...recorded(ciphertext) })).toEqual(plaintext);
  });

  it("follows the spec layout: HKDF salt docRef, info ava-doc-v1 || place || epoch, AAD place || epoch || docRef", async () => {
    const epochKey = newEpochKey();
    const docRef = newDocRef();
    const ciphertext = await encryptDocument({ ...where(), epochKey, docRef, plaintext });
    const subtle = globalThis.crypto.subtle;
    const place = new Uint8Array(await subtle.digest("SHA-256", Uint8Array.from([...hexToBytes(REGISTRY), ...boardRef])));
    const epoch = new Uint8Array(8);
    epoch[7] = 4;
    const info = Uint8Array.from([...new TextEncoder().encode("ava-doc-v1"), ...place, ...epoch]);
    const aad = Uint8Array.from([...place, ...epoch, ...docRef]);
    const ikm = await subtle.importKey("raw", Uint8Array.from(epochKey), "HKDF", false, ["deriveBits"]);
    const raw = await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: Uint8Array.from(docRef), info }, ikm, 256);
    const key = await subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
    const opened = await subtle.decrypt({ name: "AES-GCM", iv: ciphertext.slice(0, 12), additionalData: aad }, key, ciphertext.slice(12));
    expect(new Uint8Array(opened)).toEqual(plaintext);
  });

  it("decrypt with a moved docRef, epoch, board or registry fails (C13)", async () => {
    const epochKey = newEpochKey();
    const docRef = newDocRef();
    const ciphertext = await encryptDocument({ ...where(), epochKey, docRef, plaintext });
    for (const moved of [
      { ...where(), docRef: newDocRef() },
      { ...where(), docRef, epoch: 5n },
      { ...where(), docRef, boardRef: newBoardRef() },
      { ...where(), docRef, registry: OTHER_REGISTRY },
      { ...where(), docRef, epochKey: newEpochKey() },
    ]) {
      await expect(decryptDocument({ epochKey, ...moved, ciphertext, ...recorded(ciphertext) })).rejects.toThrow(DocumentError);
    }
  });

  it("a document moved between two boards the same chair created fails to decrypt", async () => {
    const epochKey = newEpochKey();
    const docRef = newDocRef();
    const first = newBoardRef();
    const second = newBoardRef();
    const ciphertext = await encryptDocument({ registry: REGISTRY, boardRef: first, epoch: 0n, epochKey, docRef, plaintext });
    const read = (ref: Uint8Array) => decryptDocument({ registry: REGISTRY, boardRef: ref, epoch: 0n, epochKey, docRef, ciphertext, ...recorded(ciphertext) });
    expect(await read(first)).toEqual(plaintext);
    await expect(read(second)).rejects.toThrow(DocumentError);
  });

  it("two encryptions of the same plaintext give different ciphertexts (C14)", async () => {
    const epochKey = newEpochKey();
    const docRef = newDocRef();
    const a = await encryptDocument({ ...where(), epochKey, docRef, plaintext });
    const b = await encryptDocument({ ...where(), epochKey, docRef, plaintext });
    expect(sameHash(sha256(a), sha256(b))).toBe(false);
    expect(a.subarray(0, 12)).not.toEqual(b.subarray(0, 12));
  });

  it("one changed byte or a wrong size is refused before any key is used (C12)", async () => {
    const realKey = newEpochKey();
    const docRef = newDocRef();
    const ciphertext = await encryptDocument({ ...where(), epochKey: realKey, docRef, plaintext });
    const changed = Uint8Array.from(ciphertext);
    changed[20] = changed[20]! ^ 0x01;
    const key = trap(realKey);
    const importKey = vi.spyOn(globalThis.crypto.subtle, "importKey");
    const decrypt = vi.spyOn(globalThis.crypto.subtle, "decrypt");
    const doc = { ...where(), epochKey: key.value, docRef };
    await expect(decryptDocument({ ...doc, ciphertext: changed, ...recorded(ciphertext) })).rejects.toThrow(HashMismatch);
    await expect(decryptDocument({ ...doc, ciphertext, expectedHash: sha256(ciphertext), expectedSize: ciphertext.length - 1 })).rejects.toThrow(DocumentError);
    await expect(decryptDocument({ ...doc, ciphertext: ciphertext.subarray(0, 27), ...recorded(ciphertext.subarray(0, 27)) })).rejects.toThrow(DocumentError);
    expect(key.touched()).toBe(false);
    expect(importKey).not.toHaveBeenCalled();
    expect(decrypt).not.toHaveBeenCalled();
    expect(await decryptDocument({ ...where(), epochKey: realKey, docRef, ciphertext, ...recorded(ciphertext) })).toEqual(plaintext);
    expect(importKey).toHaveBeenCalled();
    expect(decrypt).toHaveBeenCalled();
  });

  it("refuses a zero docRef", async () => {
    await expect(encryptDocument({ ...where(), epochKey: newEpochKey(), docRef: new Uint8Array(32), plaintext })).rejects.toThrow(DocumentError);
  });
});

describe("hashes (C12)", () => {
  it("assertHash accepts the exact bytes and throws on one changed byte", () => {
    const envelope = sealTwo(newEpochKey());
    const hash = sha256(envelope);
    expect(hash).toHaveLength(32);
    expect(() => assertHash(envelope, hash)).not.toThrow();
    const changed = Uint8Array.from(envelope);
    changed[changed.length - 1] = changed[changed.length - 1]! ^ 0x01;
    expect(() => assertHash(changed, hash)).toThrow(HashMismatch);
    expect(() => assertHash(envelope, new Uint8Array(31))).toThrow(HashMismatch);
  });

  it("compares hashes as bytes, whatever the hex case", () => {
    const h = sha256(new TextEncoder().encode("abc"));
    expect(sameHash(h, "0xBA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD")).toBe(true);
    expect(sameHash(h, "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")).toBe(true);
    expect(() => sameHash(h, "0xba78")).toThrow(TypeError);
  });
});
