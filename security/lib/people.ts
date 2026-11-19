import { KemKeyUnavailable, fetchKemKey } from "@ava/core";
import { buildRegisterKemKeyMessage } from "@qorechain/qoreseal";
import { buildRegisterPqcKeyMsg, isRegisteredPqcKey, msg, qorechainRegistry, signProofOfPossession, verifyProofOfPossession, withRetry, type PqcStatus } from "@qorechain/sdk";
import { DENOM, KEY_REGISTRATION_FEE } from "../../packages/server/src/config.ts";
import { balanceOf, feeOf, nativeTx, pqcStatus, type CommittedTx, type Messages } from "./chain.ts";
import { COSMOS_CHAIN_ID } from "./guard.ts";
import { FILL_PROFILE, FILL_RANGE, ROLES, personAt, type Person, type Profile, type Role } from "./identities.ts";

/** The registration fee, the organisers' Workshop 1 figure the relayer and the deployer use. */
export const MLDSA_FEE_UQOR = BigInt(KEY_REGISTRATION_FEE.amount[0]?.amount ?? "100000");
/** The server's figure for a guest's MsgRegisterKEMKey; the real fee is simulated and usually lower. */
export const KEM_FEE_EST_UQOR = 67_500n;
/** Recipients per funding transaction: one hybrid signature and fee for many sends. */
const SENDS_PER_TX = 20;
const PARALLEL = 4;

export function isOurKey(pqc: PqcStatus, person: Person): boolean {
  return pqc.registered && isRegisteredPqcKey(pqc, person.pqc.publicKey) === true;
}

export function isOurProvenKey(pqc: PqcStatus, person: Person): boolean {
  return isOurKey(pqc, person) && pqc.possessionProven === true;
}

/** The ML-KEM-1024 key qor_getKEMKey returns for the address, or undefined when it has none. Any other failure is thrown. */
export async function kemOf(address: string): Promise<Uint8Array | undefined> {
  try {
    return await withRetry(() => fetchKemKey(address), {
      retries: 4,
      backoff: 2_000,
      maxBackoff: 6_000,
      shouldRetry: (err) => err instanceof KemKeyUnavailable && (err.reason === "NETWORK" || err.reason === "TIMEOUT"),
    });
  } catch (err) {
    if (err instanceof KemKeyUnavailable && err.reason === "NOT_FOUND") return undefined;
    throw err;
  }
}

const sameBytes = (a: Uint8Array | undefined, b: Uint8Array): boolean => a !== undefined && Buffer.from(a).equals(Buffer.from(b));

async function waitFor(what: string, check: () => Promise<boolean>): Promise<void> {
  await withRetry(
    async () => {
      if (!(await check())) throw new Error(`${what} not visible yet`);
    },
    { retries: 8, backoff: 2_000, maxBackoff: 6_000 },
  );
}

/**
 * Registers the person's ML-DSA-87 key with MsgRegisterPQCKeyV2, signed classical at the fixed
 * registration fee, the way scripts/register-relayer.ts registers the relayer's. With `proven`
 * the message carries a proof of possession, checked locally first; without it, none (the C1
 * attack's unproven key, which the chain still accepts today).
 */
export async function registerMldsa(person: Person, proven: boolean): Promise<CommittedTx> {
  let proofOfPossession: Uint8Array | undefined;
  if (proven) {
    proofOfPossession = signProofOfPossession({ chainId: COSMOS_CHAIN_ID, account: person.qor1, keypair: person.pqc });
    if (!verifyProofOfPossession({ chainId: COSMOS_CHAIN_ID, account: person.qor1, publicKey: person.pqc.publicKey, proof: proofOfPossession })) {
      throw new Error("The proof of possession does not verify locally. Refusing to send a registration the chain would refuse after taking the fee.");
    }
  }
  // The organisers' example leaves ecdsa_pubkey empty: the chain binds the key of the transaction's signer.
  const message = buildRegisterPqcKeyMsg(person.qor1, proofOfPossession === undefined ? { pqcKeypair: person.pqc } : { pqcKeypair: person.pqc, proofOfPossession });
  const tx = await nativeTx(person, "classical", [message], KEY_REGISTRATION_FEE);
  await waitFor(`${person.role} ML-DSA-87 key`, async () => {
    const pqc = await pqcStatus(person.qor1);
    return proven ? isOurProvenKey(pqc, person) : isOurKey(pqc, person);
  });
  return tx;
}

function kemMessages(person: Person): Messages {
  const message = msg.pqc.registerKemKey({ sender: person.qor1, publicKey: person.seal.mlkemPublicKey });
  // The SDK message is the one its registry can sign; QoreSeal's builder is the reference encoding.
  const reference = buildRegisterKemKeyMessage({ sender: person.qor1, mlkemPublicKey: person.seal.mlkemPublicKey });
  if (message.typeUrl !== reference.typeUrl || !Buffer.from(qorechainRegistry().encode(message)).equals(Buffer.from(reference.value))) {
    throw new Error("The SDK and QoreSeal encode the KEM registration differently. Refusing to send.");
  }
  return [message];
}

/** Registers the person's ML-KEM-1024 key with MsgRegisterKEMKey, hybrid-signed, and waits until qor_getKEMKey returns it. */
export async function registerKem(person: Person): Promise<CommittedTx> {
  const tx = await nativeTx(person, "hybrid", kemMessages(person));
  await waitFor(`${person.role} ML-KEM-1024 key`, async () => sameBytes(await kemOf(person.evm), person.seal.mlkemPublicKey));
  return tx;
}

/** Withdraws the person's ML-KEM key (the C42 attack's guest with a missing key) and waits until the lookup finds none. */
export async function removeKem(person: Person): Promise<CommittedTx> {
  const tx = await nativeTx(person, "hybrid", [msg.pqc.removeKemKey({ sender: person.qor1 })]);
  await waitFor(`${person.role} ML-KEM-1024 key removal`, async () => (await kemOf(person.evm)) === undefined);
  return tx;
}

/** What one person's on-chain state is now, as the setup sees it. */
export interface Standing {
  balance: bigint;
  pqc: PqcStatus;
  kem: Uint8Array | undefined;
}

export async function standingOf(person: Person): Promise<Standing> {
  const [balance, pqc, kem] = await Promise.all([balanceOf(person.qor1), pqcStatus(person.qor1), kemOf(person.evm)]);
  return { balance, pqc, kem };
}

function mldsaDone(s: Standing, person: Person, profile: Profile): boolean {
  if (profile.mldsa === "none") return true;
  return profile.mldsa === "proven" ? isOurProvenKey(s.pqc, person) : isOurKey(s.pqc, person);
}

/** uqor the person still needs for the registrations its profile asks for. */
function registrationsNeed(s: Standing, person: Person, profile: Profile): bigint {
  return (mldsaDone(s, person, profile) ? 0n : MLDSA_FEE_UQOR) + (profile.kem && s.kem === undefined ? KEM_FEE_EST_UQOR : 0n);
}

/**
 * The test identities, set up on demand and only as far as the chain shows they are missing, so a
 * second run spends nothing on identities the first one finished. The wallet funds them; nobody
 * else does, and every send goes to an identity derived from the wallet's own phrase.
 */
export class People {
  readonly fundedUqor: { person: string; uqor: bigint }[] = [];
  readonly fees: { what: string; uqor: bigint; hash: string }[] = [];
  readonly touched = new Map<string, Person>();
  private readonly ready = new Set<string>();
  readonly #mnemonic: string;
  readonly wallet: Person;
  readonly log: (line: string) => void;

  constructor(mnemonic: string, wallet: Person, log: (line: string) => void) {
    this.#mnemonic = mnemonic;
    this.wallet = wallet;
    this.log = log;
  }

  async role(role: Role): Promise<Person> {
    return this.derive(ROLES[role].index, role);
  }

  /** Whether this run already got the person to its profile. */
  isReady(person: Person): boolean {
    return this.ready.has(person.qor1);
  }

  async derive(index: number, role: string): Promise<Person> {
    const person = await personAt(this.#mnemonic, index, role);
    this.touched.set(person.qor1, person);
    return person;
  }

  /** The identities that fill a board: indices FILL_RANGE.from onwards. */
  async fill(count: number): Promise<Person[]> {
    if (count > FILL_RANGE.count) throw new Error(`At most ${FILL_RANGE.count} fill identities exist.`);
    const out: Person[] = [];
    for (let i = 0; i < count; i++) out.push(await this.derive(FILL_RANGE.from + i, `fill${i + 1}`));
    return out;
  }

  /** One role, ready for its profile. */
  async ensure(role: Role): Promise<Person> {
    const person = await this.role(role);
    await this.ensureAll([{ person, profile: ROLES[role].profile }]);
    return person;
  }

  /**
   * Gets every person to its profile: one funding transaction per SENDS_PER_TX recipients that
   * need it, then each person's own registrations, a few people at a time.
   *
   * @throws When an account holds a key that is not this phrase's: a second registration is
   *   refused by the chain after it takes the fee, so nothing is sent.
   */
  async ensureAll(items: readonly { person: Person; profile: Profile }[]): Promise<void> {
    // One entry per account, so a person asked for twice is never funded twice.
    const todo = [...new Map(items.filter((i) => !this.ready.has(i.person.qor1)).map((i) => [i.person.qor1, i])).values()];
    const standings = new Map<string, Standing>();
    for (let start = 0; start < todo.length; start += PARALLEL) {
      const batch = todo.slice(start, start + PARALLEL);
      const read = await Promise.all(batch.map((i) => standingOf(i.person)));
      batch.forEach((i, n) => standings.set(i.person.qor1, read[n]!));
    }
    for (const { person, profile } of todo) {
      const s = standings.get(person.qor1)!;
      if (s.pqc.registered && !isOurKey(s.pqc, person)) throw new Error(`${person.role} has an ML-DSA-87 key that is not this phrase's. Refusing to touch it.`);
      if (profile.mldsa === "proven" && isOurKey(s.pqc, person) && !s.pqc.possessionProven) throw new Error(`${person.role} holds this phrase's key without a proof of possession; it cannot be proven now.`);
      if (s.kem !== undefined && !sameBytes(s.kem, person.seal.mlkemPublicKey)) throw new Error(`${person.role} publishes a KEM key that is not this phrase's. Refusing to replace it.`);
    }

    const toFund = todo.flatMap(({ person, profile }) => {
      const s = standings.get(person.qor1)!;
      const need = registrationsNeed(s, person, profile);
      if (need > 0n && s.balance < need) return [{ person, uqor: (profile.fundUqor > need ? profile.fundUqor : need) - s.balance }];
      if (need === 0n && s.balance < profile.fundUqor) return [{ person, uqor: profile.fundUqor - s.balance }];
      return [];
    });
    for (let start = 0; start < toFund.length; start += SENDS_PER_TX) {
      const batch = toFund.slice(start, start + SENDS_PER_TX);
      const sends = batch.map(({ person, uqor }) => msg.bank.send({ fromAddress: this.wallet.qor1, toAddress: person.qor1, amount: [{ denom: DENOM, amount: uqor.toString() }] }));
      const tx = await nativeTx(this.wallet, "hybrid", sends);
      this.fees.push({ what: `fund ${batch.length}`, uqor: feeOf(tx), hash: tx.hash });
      for (const { person, uqor } of batch) {
        this.fundedUqor.push({ person: person.role, uqor });
        const before = standings.get(person.qor1)!.balance;
        await waitFor(`${person.role} funding`, async () => (await balanceOf(person.qor1)) >= before + uqor);
      }
      this.log(`  funded:   ${batch.map((b) => `${b.person.role} ${b.uqor} uqor`).join(", ")} in ${tx.hash}`);
    }

    for (let start = 0; start < todo.length; start += PARALLEL) {
      await Promise.all(
        todo.slice(start, start + PARALLEL).map(async ({ person, profile }) => {
          const s = standings.get(person.qor1)!;
          if (!mldsaDone(s, person, profile)) {
            const tx = await registerMldsa(person, profile.mldsa === "proven");
            this.fees.push({ what: `${person.role} ML-DSA-87`, uqor: feeOf(tx), hash: tx.hash });
            this.log(`  ${person.role}: ML-DSA-87 key registered ${profile.mldsa === "proven" ? "with" : "WITHOUT"} a proof of possession in ${tx.hash}`);
          }
          if (profile.kem && s.kem === undefined) {
            const tx = await registerKem(person);
            this.fees.push({ what: `${person.role} ML-KEM-1024`, uqor: feeOf(tx), hash: tx.hash });
            this.log(`  ${person.role}: ML-KEM-1024 key registered in ${tx.hash}`);
          }
          this.ready.add(person.qor1);
        }),
      );
    }
  }

  /** Fill identities with the full profile, ready. */
  async ensureFill(count: number): Promise<Person[]> {
    const people = await this.fill(count);
    await this.ensureAll(people.map((person) => ({ person, profile: FILL_PROFILE })));
    return people;
  }
}
