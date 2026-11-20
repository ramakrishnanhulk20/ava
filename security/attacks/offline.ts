import {
  ACTION_MESSAGE_LENGTH,
  Action,
  BOARD_TAG,
  CHAIN_ID,
  CHALLENGE_MESSAGE_LENGTH,
  CHALLENGE_TAG,
  MAX_DEADLINE_AHEAD,
  actionMessage,
  canonicalPhrase,
  challengeMessage,
  generateMnemonic,
  identityFromMnemonic,
  paramsPost,
  paramsRotate,
  signAction,
  signBoardAction,
  signChallenge,
  verifyAction,
  type Identity,
} from "@ava/core";
import {
  BRIDGE_ATTESTATION_V2_DOMAIN,
  HYBRID_SIGN_BYTES_V2_DOMAIN,
  LEGACY_SIGN_BYTES_CHAINS,
  MIGRATION_SIGN_BYTES_V2_DOMAIN,
  PROOF_OF_POSSESSION_DOMAIN,
  authenticatorLinkMessageBytes,
  bridgeAttestationSignBytesV1,
  bridgeAttestationSignBytesV2,
  cosmosAuthSignBytes,
  derivePqcCanonical,
  evmAuthSignBytes,
  evmAuthSignBytesV2,
  hybridSignBytesV1,
  hybridSignBytesV2,
  migrationSignBytesV1,
  migrationSignBytesV2,
  proofOfPossessionSignBytes,
  rotationSignBytes,
} from "@qorechain/sdk";
import { bytesToHex, hexToBytes, type Hex } from "viem";
import { verdict, type OfflineAttack, type Probe } from "../lib/attack.ts";
import { REGISTRY } from "../lib/guard.ts";
import { personAt } from "../lib/identities.ts";

const utf8 = new TextEncoder();
const MAX_U64 = (1n << 64n) - 1n;
const MAX_U256 = (1n << 256n) - 1n;
const YEAR_SECONDS = 365n * 86_400n;

const fact = (ok: boolean, line: string): Probe => ({ ok, line });
const random = (n: number): Uint8Array => globalThis.crypto.getRandomValues(new Uint8Array(n));
const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => a.length === b.length && Buffer.from(a).equals(Buffer.from(b));
const startsWith = (bytes: Uint8Array, prefix: Uint8Array): boolean => bytes.length >= prefix.length && prefix.every((x, i) => bytes[i] === x);

/** 32 random bytes, never all zero, which every Ava hash field refuses. */
function random32(): Hex {
  const b = random(32);
  b[0] = b[0]! | 0x01;
  return bytesToHex(b);
}

/** The name of whatever `attempt` threw, or undefined when it returned. */
function thrown(attempt: () => unknown): string | undefined {
  try {
    attempt();
    return undefined;
  } catch (err) {
    return err instanceof Error ? err.name : String(err);
  }
}

/**
 * No chain is read offline, so the clock stands in for the latest block's timestamp. The signers
 * only compare a deadline with this value, so any plausible time tests the same rule.
 */
const standInLatest = (): bigint => BigInt(Math.floor(Date.now() / 1000));

const freshIdentity = (): Promise<Identity> => identityFromMnemonic(generateMnemonic());

/** Walks bytes in one of the SDK's length-prefixed layouts. Every read fails closed past the end. */
class Cursor {
  readonly #bytes: Uint8Array;
  #at = 0;

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  expect(prefix: Uint8Array): boolean {
    if (!startsWith(this.#bytes.subarray(this.#at), prefix)) return false;
    this.#at += prefix.length;
    return true;
  }

  skip(n: bigint): boolean {
    if (n < 0n || BigInt(this.#at) + n > BigInt(this.#bytes.length)) return false;
    this.#at += Number(n);
    return true;
  }

  /** A big-endian length of `width` bytes, then that many bytes. */
  chunk(width: 4 | 8): boolean {
    if (this.#at + width > this.#bytes.length) return false;
    const view = new DataView(this.#bytes.buffer, this.#bytes.byteOffset + this.#at, width);
    const length = width === 4 ? BigInt(view.getUint32(0, false)) : view.getBigUint64(0, false);
    this.#at += width;
    return this.skip(length);
  }

  get done(): boolean {
    return this.#at === this.#bytes.length;
  }
}

const isUtf8 = (bytes: Uint8Array): boolean => {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
};

/**
 * The index of the first byte that makes `bytes` invalid UTF-8 whatever comes after them, or
 * undefined when every byte so far could still start valid text. A sequence cut off by the end is
 * not counted, because the bytes after it decide it.
 */
function invalidUtf8At(bytes: Uint8Array): number | undefined {
  for (let i = 0; i < bytes.length; ) {
    const lead = bytes[i]!;
    const extra = lead < 0x80 ? 0 : lead >= 0xc2 && lead <= 0xdf ? 1 : lead >= 0xe0 && lead <= 0xef ? 2 : lead >= 0xf0 && lead <= 0xf4 ? 3 : -1;
    if (extra < 0) return i;
    for (let k = 1; k <= extra; k++) {
      if (i + k >= bytes.length) return undefined;
      const next = bytes[i + k]!;
      // The second byte's range is narrower after these leads (no overlong forms, no surrogates, nothing past U+10FFFF).
      const lo = k === 1 && lead === 0xe0 ? 0xa0 : k === 1 && lead === 0xf0 ? 0x90 : 0x80;
      const hi = k === 1 && lead === 0xed ? 0x9f : k === 1 && lead === 0xf4 ? 0x8f : 0xbf;
      if (next < lo || next > hi) return i + k;
    }
    i += extra + 1;
  }
  return undefined;
}

/** The output of `build(n)` that is exactly `size` bytes, for a builder that grows by one byte per step of n. */
function sizedTo(size: number, build: (n: number) => Uint8Array): Uint8Array | undefined {
  for (let n = 0; n <= size; n++) {
    const bytes = build(n);
    if (bytes.length === size) return bytes;
    if (bytes.length > size) return undefined;
  }
  return undefined;
}

interface Form {
  name: string;
  /** The builder's output for real-looking inputs. */
  natural: Uint8Array;
  /** The same builder grown through one variable-length input to exactly `size` bytes. */
  sized?: (size: number) => Uint8Array | undefined;
  /** Whether bytes could have come out of this builder: its fixed text, then lengths that end exactly at the end. */
  parses: (bytes: Uint8Array) => boolean;
}

const textForm = (prefix: string) => {
  const head = utf8.encode(prefix);
  return (bytes: Uint8Array): boolean => isUtf8(bytes) && startsWith(bytes, head);
};

/**
 * Every sign-bytes builder @qorechain/sdk 0.14.0 exports, each with a parser for its layout. Every
 * sample here comes out of the SDK's own builder, and each parser must accept them, so a parser that
 * misreads its form shows up as a failing control rather than as a silent pass.
 */
function sdkForms(who: Identity): Form[] {
  const chainId = CHAIN_ID;
  const account = who.qor1;
  const pub = who.mldsa.publicKey;
  const authInfo = random(60);
  const txHash = `0x${"ab".repeat(32)}`;
  const grow = (build: (n: number) => Uint8Array) => (size: number) => sizedTo(size, build);
  const pad = (n: number): string => `${account}${"q".repeat(n)}`;
  return [
    {
      name: `hybrid transaction sign bytes v1 (the legacy layout, and ${chainId} is ${LEGACY_SIGN_BYTES_CHAINS.includes(chainId) ? "" : "NOT "}in LEGACY_SIGN_BYTES_CHAINS)`,
      natural: hybridSignBytesV1(random(180), random(120)),
      sized: grow((n) => hybridSignBytesV1(random(n), authInfo)),
      parses: (b) => {
        const c = new Cursor(b);
        return c.chunk(4) && c.chunk(4) && c.done;
      },
    },
    {
      name: "hybrid transaction sign bytes v2",
      natural: hybridSignBytesV2(chainId, random(180), random(120)),
      sized: grow((n) => hybridSignBytesV2(chainId, random(n), authInfo)),
      parses: (b) => {
        const c = new Cursor(b);
        return c.expect(utf8.encode(HYBRID_SIGN_BYTES_V2_DOMAIN)) && c.chunk(8) && c.chunk(4) && c.chunk(4) && c.done;
      },
    },
    {
      name: "proof of possession",
      natural: proofOfPossessionSignBytes({ chainId, account, publicKey: pub }),
      sized: grow((n) => proofOfPossessionSignBytes({ chainId, account: pad(n), publicKey: random(1) })),
      parses: textForm(`${PROOF_OF_POSSESSION_DOMAIN}|`),
    },
    {
      // The SDK does not export ROTATE_DOMAIN; the control below proves this is the text it writes.
      name: "key rotation",
      natural: utf8.encode(rotationSignBytes(chainId, 1, account, pub, random(pub.length))),
      sized: grow((n) => utf8.encode(rotationSignBytes(chainId, 1, pad(n), random(1), random(1)))),
      parses: textForm("qorechain-pqc-rotate-v1|"),
    },
    {
      name: "key migration v1",
      natural: migrationSignBytesV1({ chainId, account, fromAlgorithmId: 1, toAlgorithmId: 1, height: 123_456n }),
      sized: grow((n) => migrationSignBytesV1({ chainId, account: pad(n), fromAlgorithmId: 1, toAlgorithmId: 1, height: 1n })),
      parses: textForm("qorechain-key-migration:chain="),
    },
    {
      name: "key migration v2",
      natural: migrationSignBytesV2({ chainId, account, fromAlgorithmId: 1, toAlgorithmId: 1, height: 123_456n, oldPublicKey: pub, newPublicKey: random(pub.length) }),
      sized: grow((n) => migrationSignBytesV2({ chainId, account, fromAlgorithmId: 1, toAlgorithmId: 1, height: 1n, oldPublicKey: random(1), newPublicKey: random(n) })),
      parses: (b) => {
        const c = new Cursor(b);
        return c.expect(utf8.encode(MIGRATION_SIGN_BYTES_V2_DOMAIN)) && c.chunk(8) && c.chunk(8) && c.skip(4n) && c.skip(4n) && c.skip(8n) && c.chunk(4) && c.chunk(4) && c.done;
      },
    },
    {
      // Validators sign these, never an account; listed because it is a sign-bytes form the SDK builds.
      name: "bridge attestation v1",
      natural: bridgeAttestationSignBytesV1({ chain: "ethereum", eventType: "deposit", operationId: "op-1", txHash, amount: "1000", asset: "uqor" }),
      sized: grow((n) => bridgeAttestationSignBytesV1({ chain: "ethereum", eventType: "deposit", operationId: "o".repeat(n), txHash, amount: "1000", asset: "uqor" })),
      parses: (b) => isUtf8(b) && new TextDecoder().decode(b).split("|").length >= 6,
    },
    {
      name: "bridge attestation v2",
      natural: bridgeAttestationSignBytesV2({ chainId, chain: "ethereum", eventType: "deposit", operationId: "op-1", txHash, amount: "1000", asset: "uqor" }),
      sized: grow((n) => bridgeAttestationSignBytesV2({ chainId, chain: "ethereum", eventType: "deposit", operationId: "o".repeat(n), txHash, amount: "1000", asset: "uqor" })),
      parses: (b) => {
        const c = new Cursor(b);
        if (!c.expect(utf8.encode(BRIDGE_ATTESTATION_V2_DOMAIN))) return false;
        for (let field = 0; field < 7; field++) if (!c.chunk(8)) return false;
        return c.done;
      },
    },
    {
      name: "EVM authenticator digest v1 (SHA-256, 32 bytes)",
      natural: evmAuthSignBytes({ chainId, account, pubkey: random(32), to: who.evm, value: "0", data: random(36), nonce: 0n }),
      parses: (b) => b.length === 32,
    },
    {
      name: "EVM authenticator digest v2 (SHA-256, 32 bytes)",
      natural: evmAuthSignBytesV2({ chainId, account, pubkey: random(32), to: who.evm, value: "0", data: random(36), nonce: 0n, gasLimit: 300_000n }),
      parses: (b) => b.length === 32,
    },
    {
      name: "Cosmos authenticator digest (SHA-256, 32 bytes)",
      natural: cosmosAuthSignBytes({ chainId, account, pubkey: random(32), to: account, amount: "1uqor", nonce: 0n }),
      parses: (b) => b.length === 32,
    },
    {
      name: "authenticator link message",
      natural: authenticatorLinkMessageBytes(chainId, account, "ed25519", random(32)),
      sized: grow((n) => authenticatorLinkMessageBytes(chainId, pad(n), "ed25519", random(32))),
      parses: textForm("QoreChain authenticator link v1\n"),
    },
  ];
}

/** The reserved prefixes threat model C3 names that this SDK version builds no form for, and any future one. */
function documentedForms(): Form[] {
  const named = ["qorechain:pqc:recovery:v1", "qorechain-siwq-v1|", "qorechain-msg-v1|", "qorechain-svm-auth-v2"].map(
    (prefix): Form => ({
      name: `"${prefix}" (named in the threat model, not built by this SDK)`,
      natural: utf8.encode(`${prefix}example`),
      sized: (size) => sizedTo(size, (n) => utf8.encode(`${prefix}${"x".repeat(n)}`)),
      parses: (b) => startsWith(b, utf8.encode(prefix)),
    }),
  );
  const future: Form = {
    name: 'any future prefix starting "qorechain", in any letter case',
    natural: utf8.encode("QoreChain-future-v9|example"),
    sized: (size) => sizedTo(size, (n) => utf8.encode(`qorechain-future-v9|${"x".repeat(n)}`)),
    parses: (b) => b.length >= 9 && String.fromCharCode(...b.subarray(0, 9)).toLowerCase() === "qorechain",
  };
  return [...named, future];
}

/** Board actions of every kind and guest challenges, at ordinary and at extreme field values. */
function avaMessages(guest: Identity): Uint8Array[] {
  const out: Uint8Array[] = [];
  for (const action of Object.values(Action)) {
    const create = action === Action.CREATE;
    out.push(actionMessage({ registry: REGISTRY, action, boardId: create ? 0n : 15n, paramsHash: random32(), nonce: 7n, deadline: 1_795_000_000n }));
    out.push(actionMessage({ registry: REGISTRY, action, boardId: create ? 0n : MAX_U256, paramsHash: random32(), nonce: MAX_U64, deadline: MAX_U64 }));
  }
  out.push(challengeMessage({ registry: REGISTRY, boardId: 15n, guest: guest.evm, botNonce: random32(), expiry: 1_795_000_000n }));
  out.push(challengeMessage({ registry: REGISTRY, boardId: MAX_U256, guest: guest.evm, botNonce: `0x${"ff".repeat(32)}`, expiry: MAX_U64 }));
  return out;
}

function formProbe(form: Form, ava: readonly Uint8Array[], secretKey: Uint8Array): Probe {
  const outputs = [form.natural];
  for (const size of [ACTION_MESSAGE_LENGTH, CHALLENGE_MESSAGE_LENGTH]) {
    const grown = form.sized?.(size);
    if (grown !== undefined) outputs.push(grown);
  }
  const parsed = outputs.every((b) => form.parses(b));
  const refusals = outputs.map((b) => thrown(() => signAction(secretKey, b)) ?? "SIGNED");
  const refused = refusals.every((r) => r === "ActionError");
  const avaParsed = ava.filter((m) => form.parses(m)).length;
  return fact(
    parsed && refused && avaParsed === 0,
    `${form.name}: samples of ${outputs.map((b) => b.length).join(", ")} bytes ${parsed ? "parse" : "DO NOT ALL PARSE"} as this form, ` +
      `signAction refuses ${refused ? "each (ActionError)" : `NOT EACH (${refusals.join(", ")})`}, ` +
      `${avaParsed === 0 ? `none of the ${ava.length} Ava messages parses as one` : `${avaParsed} OF THE ${ava.length} AVA MESSAGES PARSE AS ONE`}`,
  );
}

/** A v1 body length read from the tag's first four bytes, against the fixed message length. */
function lengthProbe(name: string, tag: Hex, messageLength: number): Probe {
  const head = new DataView(hexToBytes(tag).buffer, 0, 4).getUint32(0, false);
  return fact(
    head + 8 > messageLength,
    `${name}'s first four bytes, read as a v1 body length, say ${head.toLocaleString("en-US")} bytes, ${head + 8 > messageLength ? "past" : "INSIDE"} the ${messageLength}-byte message, so no such message is v1 sign bytes whatever its fields`,
  );
}

function utf8Probe(name: string, tag: Hex): Probe {
  const at = invalidUtf8At(hexToBytes(tag));
  return fact(
    at !== undefined,
    at === undefined
      ? `${name} IS NOT INVALID UTF-8 BY ITSELF: only their fixed text keeps text forms apart from these messages`
      : `${name} is invalid UTF-8 at byte ${at} whatever follows, so no text the SDK encodes is ever such a message`,
  );
}

const framing: OfflineAttack = {
  id: "C3-v1-framing",
  claim:
    "App signatures can never be anything else: for every sign-bytes form the pinned @qorechain/sdk builds (hybrid v1 and v2, proof of possession, key rotation, migration v1 and v2, and the rest it exports) and every reserved prefix the threat model names, no Ava board message or challenge parses as that form, and signAction refuses that form's bytes, even at exactly 256 and 224 bytes.",
  async run() {
    const signer = await freshIdentity();
    const ava = avaMessages(signer);
    const sk = signer.mldsa.secretKey;
    const board = ava[0]!;
    const challenge = ava.at(-2)!;
    return verdict([
      fact(verifyAction(signer.mldsa.publicKey, board, signAction(sk, board)), "control: signAction signs a real 256-byte board action, and it verifies"),
      fact(verifyAction(signer.mldsa.publicKey, challenge, signAction(sk, challenge)), "control: signAction signs a real 224-byte challenge, and it verifies"),
      lengthProbe("BOARD_TAG", BOARD_TAG, ACTION_MESSAGE_LENGTH),
      lengthProbe("CHALLENGE_TAG", CHALLENGE_TAG, CHALLENGE_MESSAGE_LENGTH),
      utf8Probe("BOARD_TAG", BOARD_TAG),
      utf8Probe("CHALLENGE_TAG", CHALLENGE_TAG),
      ...[...sdkForms(signer), ...documentedForms()].map((form) => formProbe(form, ava, sk)),
    ]);
  },
};

const mirror: OfflineAttack = {
  id: "C33-mirror",
  claim:
    "No client signs bytes a server handed it: signBoardAction and signChallenge build what they sign from typed fields, so a paramsHash or message passed in beside them is ignored, and a ROTATE for another board handed in as a challenge answer is signed only as a 224-byte challenge.",
  async run() {
    const guest = await freshIdentity();
    const pk = guest.mldsa.publicKey;
    const sk = guest.mldsa.secretKey;
    const latest = standInLatest();
    // The guest chairs board 42. A hostile challenge endpoint wants a ROTATE of it to an envelope the attacker chose.
    const theirs = { envelopeHash: random32(), envelopeSize: 1_729, epochAfter: 3n };
    const rotate = actionMessage({ registry: REGISTRY, action: Action.ROTATE, boardId: 42n, paramsHash: paramsRotate(theirs), nonce: 9n, deadline: latest + 600n });
    const hostile = { paramsHash: paramsRotate(theirs), message: bytesToHex(rotate) };

    const own = { action: Action.ROTATE, envelopeHash: random32(), envelopeSize: 2_048, epochAfter: 3n } as const;
    const typed = { registry: REGISTRY, boardId: 42n, nonce: 9n, deadline: latest + 600n, latestBlockTimestamp: latest };
    const action = signBoardAction(sk, { ...own, ...typed, ...hostile });
    const rebuilt = actionMessage({ registry: REGISTRY, action: Action.ROTATE, boardId: 42n, paramsHash: paramsRotate(own), nonce: 9n, deadline: latest + 600n });

    const answer = { registry: REGISTRY, boardId: 15n, botNonce: random32(), expiry: latest + 300n };
    const challenge = signChallenge(sk, { ...answer, guest: guest.evm, latestBlockTimestamp: latest, ...hostile });
    const expected = challengeMessage({ ...answer, guest: guest.evm });
    // Every field of the ROTATE handed in, and its values under the challenge's own names too, so nothing of it is left out.
    const rotateFields = { ...theirs, action: Action.ROTATE, nonce: 9n, deadline: latest + 600n, ...hostile };
    const crammed = signChallenge(sk, { ...rotateFields, registry: REGISTRY, boardId: 42n, guest: guest.evm, botNonce: hostile.paramsHash, expiry: latest + 600n, latestBlockTimestamp: latest });
    const tagged = (m: Uint8Array): boolean => m.length === CHALLENGE_MESSAGE_LENGTH && startsWith(m, hexToBytes(CHALLENGE_TAG));

    return verdict([
      fact(action.paramsHash === paramsRotate(own) && action.paramsHash !== hostile.paramsHash, "signBoardAction: the paramsHash it signs is paramsRotate of the typed fields, not the one passed in beside them"),
      fact(sameBytes(action.message, rebuilt) && !sameBytes(action.message, rotate), "signBoardAction: the message it signs is actionMessage of the typed fields, not the message passed in"),
      fact(verifyAction(pk, action.message, action.signature) && !verifyAction(pk, rotate, action.signature), "signBoardAction: its signature verifies over its own message and not over the hostile ROTATE"),
      fact(sameBytes(challenge.message, expected) && tagged(challenge.message), "signChallenge with the hostile answer: it signs challengeMessage of the answer's fields, 224 bytes under CHALLENGE_TAG"),
      fact(!verifyAction(pk, rotate, challenge.signature), "signChallenge with the hostile answer: the signature does not verify as the ROTATE of board 42"),
      fact(tagged(crammed.message) && !sameBytes(crammed.message, rotate) && !verifyAction(pk, rotate, crammed.signature), "signChallenge with every ROTATE field crammed in: still a 224-byte challenge, and its signature is not one over the ROTATE"),
      fact(verifyAction(pk, rotate, signAction(sk, rotate)), "what the typed signers close: raw signAction, which application code no longer calls, would sign that ROTATE"),
    ]);
  },
};

const deadline: OfflineAttack = {
  id: "C2-deadline",
  claim: `No signature from the app outlives an hour: signBoardAction refuses a deadline a year past the latest block and one at the latest block plus ${MAX_DEADLINE_AHEAD + 1} seconds, and signs one at plus ${MAX_DEADLINE_AHEAD}.`,
  async run() {
    const chair = await freshIdentity();
    const latest = standInLatest();
    const post = { action: Action.POST, docRef: random32(), cipherHash: random32(), cipherSize: 4_096n, epoch: 3n } as const;
    const at = (deadlineAt: bigint) => ({ ...post, registry: REGISTRY, boardId: 7n, nonce: 11n, deadline: deadlineAt, latestBlockTimestamp: latest });
    const year = thrown(() => signBoardAction(chair.mldsa.secretKey, at(latest + YEAR_SECONDS)));
    const over = thrown(() => signBoardAction(chair.mldsa.secretKey, at(latest + BigInt(MAX_DEADLINE_AHEAD) + 1n)));
    const edge = signBoardAction(chair.mldsa.secretKey, at(latest + BigInt(MAX_DEADLINE_AHEAD)));
    const edgeMessage = actionMessage({ registry: REGISTRY, action: Action.POST, boardId: 7n, paramsHash: paramsPost(post), nonce: 11n, deadline: latest + BigInt(MAX_DEADLINE_AHEAD) });
    const dormant = actionMessage({ registry: REGISTRY, action: Action.POST, boardId: 7n, paramsHash: paramsPost(post), nonce: 11n, deadline: latest + YEAR_SECONDS });
    return verdict([
      fact(year === "ActionError", `a deadline ${YEAR_SECONDS.toLocaleString("en-US")} seconds (a year) past the latest block: ${year ?? "SIGNED"}`),
      fact(over === "ActionError", `a deadline ${MAX_DEADLINE_AHEAD + 1} seconds past it: ${over ?? "SIGNED"}`),
      fact(sameBytes(edge.message, edgeMessage) && verifyAction(chair.mldsa.publicKey, edge.message, edge.signature), `control: a deadline ${MAX_DEADLINE_AHEAD} seconds past it signs, and verifies`),
      fact(verifyAction(chair.mldsa.publicKey, dormant, signAction(chair.mldsa.secretKey, dormant)), "what the window closes: raw signAction over actionMessage still signs the year-ahead deadline, which the registry would take from 3,600 seconds before it"),
    ]);
  },
};

/** The first letter of a lowercase word in its full-width form, which NFKD maps back. */
const fullWidthFirst = (word: string): string => `${String.fromCodePoint(word.codePointAt(0)! - 0x61 + 0xff41)}${word.slice(1)}`;

const phrase: OfflineAttack = {
  id: "C16-phrase",
  claim:
    "One phrase, one account and one key set: a freshly generated phrase pasted with no-break spaces (U+00A0), ideographic spaces (U+3000) and a full-width letter gives the same identity through identityFromMnemonic, and through this suite's own reader, as the phrase as generated.",
  async run() {
    const generated = generateMnemonic();
    const words = generated.split(" ");
    const gaps = [" ", "　", "  "];
    const pasted = `　${words.map((w, i) => (i === 0 ? fullWidthFirst(w) : w)).reduce((acc, w, i) => `${acc}${gaps[i % gaps.length]!}${w}`)} `;
    const want = await identityFromMnemonic(generated);
    const got = await identityFromMnemonic(pasted);
    const suite = await personAt(pasted, 0, "phrase-probe");
    const raw = derivePqcCanonical(want.qor1, pasted);
    // Secrets are compared here and never printed.
    return verdict([
      fact(pasted !== generated && pasted.includes(" ") && pasted.includes("　") && /[ａ-ｚ]/.test(pasted), "control: the pasted form is another string, with U+00A0, U+3000 and a full-width letter in it"),
      fact(canonicalPhrase(pasted) === generated, "canonicalPhrase of the pasted form is the phrase as generated"),
      fact(got.qor1 === want.qor1 && got.evm === want.evm, `identityFromMnemonic: the same account, ${want.qor1}`),
      fact(sameBytes(got.privateKey, want.privateKey), "the same secp256k1 key (compared, never printed)"),
      fact(sameBytes(got.mldsa.publicKey, want.mldsa.publicKey) && sameBytes(got.mldsa.secretKey, want.mldsa.secretKey), "the same ML-DSA-87 key pair"),
      fact(sameBytes(got.seal.mlkemPublicKey, want.seal.mlkemPublicKey) && sameBytes(got.seal.x25519PublicKey, want.seal.x25519PublicKey), "the same ML-KEM-1024 and X25519 keys"),
      fact(suite.qor1 === want.qor1 && sameBytes(suite.pqc.publicKey, want.mldsa.publicKey) && sameBytes(suite.seal.mlkemPublicKey, want.seal.mlkemPublicKey), "this suite's personAt reads the pasted form the same way"),
      fact(!sameBytes(raw.publicKey, want.mldsa.publicKey), "what canonicalPhrase averts: the SDK's derivePqcCanonical over the pasted form as typed gives another ML-DSA-87 key"),
    ]);
  },
};

/** Every attack that runs with no network, wallet or server, in the order they run. */
export const attacks: readonly OfflineAttack[] = [framing, mirror, deadline, phrase];
