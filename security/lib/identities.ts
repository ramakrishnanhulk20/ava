import { accountBytes, canonicalPhrase, sameAccount, toHex, toQor1 } from "@ava/core";
import { deriveSealKeys, type SealKeyPair } from "@qorechain/qoreseal";
import { derivePqcCanonical, deriveUnifiedAccount, type PqcKeypair, type UnifiedAccount } from "@qorechain/sdk";
import type { Hex } from "viem";

/**
 * One account this suite controls: the security wallet (index 0) or a test identity it funds,
 * all derived from SECURITY_TESTNET_KEY, so the suite holds no other secret. Holds secrets: never
 * log, print or serialise an instance of this.
 */
export interface Person {
  role: string;
  index: number;
  /** The Native-lane address, `qor1...`. */
  qor1: string;
  /** The same 20 bytes on the EVM lane, EIP-55 `0x...`. */
  evm: Hex;
  /** The secp256k1 key of m/44'/60'/0'/0/index, shared by both lanes. */
  privateKey: Hex;
  /** The address-bound ML-DSA-87 key pair. */
  pqc: PqcKeypair;
  unified: UnifiedAccount;
  /** The ML-KEM-1024 and X25519 keys at this index. */
  seal: SealKeyPair;
}

/**
 * The one form every reader derives from: @ava/core's canonicalPhrase (C16), so a phrase pasted with
 * other spaces or full-width letters gives this suite the same keys it gives the app.
 *
 * @throws Error when the phrase is not 24 valid words; the message never repeats the phrase.
 */
export function normalizePhrase(raw: string): string {
  return canonicalPhrase(raw);
}

export function isPhrase(raw: string): boolean {
  try {
    canonicalPhrase(raw);
    return true;
  } catch {
    return false;
  }
}

/**
 * Derives one account the way the relayer and the drill account are derived (unified, coin type
 * 60), at `index`: so qor1, 0x and the key that signs EVM transactions are one account, with its
 * address-bound ML-DSA-87 key and its QoreSeal keys at the same index.
 *
 * @throws When the phrase is not 24 valid words (never repeating it), when the canonical ML-DSA-87
 *   derivation and the unified account disagree, or the two address forms are not one account.
 */
export async function personAt(mnemonic: string, index: number, role: string): Promise<Person> {
  if (!isPhrase(mnemonic)) throw new Error("The security phrase is not 24 valid BIP-39 words.");
  if (!Number.isSafeInteger(index) || index < 0 || index > 10_000) throw new Error("An identity index is a whole number from 0 to 10,000.");
  const phrase = normalizePhrase(mnemonic);
  const unified = await deriveUnifiedAccount(phrase, index);
  const pqc = derivePqcCanonical(unified.cosmos, phrase);
  if (!Buffer.from(pqc.publicKey).equals(Buffer.from(unified.pqc.publicKey))) {
    throw new Error("derivePqcCanonical and deriveUnifiedAccount give different ML-DSA-87 keys. Refusing to continue.");
  }
  if (!sameAccount(unified.cosmos, unified.evm)) throw new Error("The derived qor1 and 0x addresses are not one account. Refusing to continue.");
  if (!/^0x[0-9a-fA-F]{64}$/.test(unified.privateKey)) throw new Error("The derived private key is not 32 bytes of hex.");
  const account = accountBytes(unified.cosmos);
  return { role, index, qor1: toQor1(account), evm: toHex(account), privateKey: unified.privateKey as Hex, pqc, unified, seal: deriveSealKeys({ mnemonic: phrase, index }) };
}

/** What a test identity must hold on chain before an attack uses it. */
export interface Profile {
  /** "proven" registers with a proof of possession; "unproven" registers without one (C1). */
  mldsa: "proven" | "unproven" | "none";
  kem: boolean;
  /** uqor the wallet sends it once, when it holds less than its registrations need. */
  fundUqor: bigint;
}

/** Enough for MsgRegisterPQCKeyV2 at its fixed 0.1 QOR fee and MsgRegisterKEMKey at its simulated fee, with room. */
export const FUND_FULL_UQOR = 220_000n;
export const FUND_MLDSA_UQOR = 130_000n;

const FULL: Profile = { mldsa: "proven", kem: true, fundUqor: FUND_FULL_UQOR };

/**
 * Who is who. Fixed indices, so a second run finds the same identities on chain and registers
 * nothing twice. The sponsored identity is the first fresh index in its range, because the sponsor
 * funds an address once, ever.
 */
export const ROLES = {
  wallet: { index: 0, profile: FULL },
  dana: { index: 1, profile: FULL },
  eli: { index: 2, profile: FULL },
  fay: { index: 3, profile: FULL },
  nopop: { index: 4, profile: { mldsa: "unproven", kem: false, fundUqor: FUND_MLDSA_UQOR } },
  nokem: { index: 6, profile: { mldsa: "proven", kem: false, fundUqor: FUND_MLDSA_UQOR } },
  dust: { index: 7, profile: { mldsa: "none", kem: false, fundUqor: 1n } },
  stranger: { index: 8, profile: { mldsa: "none", kem: false, fundUqor: 0n } },
} as const satisfies Record<string, { index: number; profile: Profile }>;

export type Role = keyof typeof ROLES;

/** The sponsor's once-only test: the first of these with no balance and no key is asked for. */
export const SPONSORED_RANGE = { from: 100, to: 119 } as const;
/**
 * C33-no-kem-guest's guests: one fresh index a run, funded by our own sponsor, because the bot
 * counts failed joins per address per UTC day and an address used before may already have some.
 */
export const NOKEM_SPONSORED_RANGE = { from: 120, to: 199 } as const;
/**
 * C15-shared-kem-guest's copiers: one fresh index a run, funded by our own sponsor, kept clear of
 * every other range so a copier is never reused as a guest or a fill identity.
 */
export const SHARED_KEM_SPONSORED_RANGE = { from: 3_000, to: 3_099 } as const;
/** A sponsored guest pays its own ML-DSA-87 registration from what the sponsor sent, and registers no ML-KEM key. */
export const SPONSORED_NOKEM_PROFILE: Profile = { mldsa: "proven", kem: false, fundUqor: 0n };
/**
 * Demo guests. The bot admits an address once, ever, so each run takes the next indices here whose
 * address the demo board's events have never named.
 */
export const DEMO_POOL = { from: 300, to: 2_999 } as const;
/** Members that fill a board to the cap (C7) and the demo board to its guest cap (C41). */
export const FILL_RANGE = { from: 200, count: 63 } as const;
export const FILL_PROFILE: Profile = FULL;
