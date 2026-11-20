import type { Ctx } from "./context.ts";
import { FUND_FULL_UQOR, FUND_MLDSA_UQOR } from "./identities.ts";

/** What one attack found. `held` is true only when the attack was refused or had no effect. */
export interface Result {
  held: boolean;
  /** The tx hash, revert name, HTTP status and code, or the state read back. */
  evidence: string;
}

/** Shared setup an attack needs; each item is paid once a run, by the first attack that asks. */
export type SetupName = "dana" | "eli" | "fay" | "nokem" | "dust" | "boards";

export interface Attack {
  /** `C<n>-<short>`: the threat-model invariant it tries to break, then a short name. */
  id: `C${number}-${string}`;
  claim: string;
  /** Test QOR the security wallet spends on this attack's own transactions, in uqor, beyond its setup. */
  costUqor: bigint;
  /** Test QOR our own relayer or sponsor spends because of it, in uqor. Never the wallet's. */
  serverUqor?: bigint;
  /** What the cost depends on, when it is not fixed. */
  costNote?: string;
  needs?: readonly SetupName[];
  run(ctx: Ctx): Promise<Result>;
}

/**
 * An attack that needs no network, no wallet and no server: it works on @ava/core and the pinned
 * QoreChain SDK alone. `npx tsx run.ts --offline` runs these with every network call refused, and a
 * live run runs them first, so their rows sit in the same results file.
 */
export interface OfflineAttack {
  id: `C${number}-${string}`;
  claim: string;
  run(): Promise<Result>;
}

/** An offline attack in the shape the live run's loop takes. It costs nothing. */
export const asAttack = (a: OfflineAttack): Attack => ({ id: a.id, claim: a.claim, costUqor: 0n, run: () => a.run() });

/** The evidence of an attack that did not run starts with this, and the run counts it as not held. */
export const NOT_RUN = "not run: ";

export const notRun = (why: string): Result => ({ held: false, evidence: `${NOT_RUN}${why}` });

/** One probe of an attack: whether it came out as refused, and the line that says so. */
export interface Probe {
  ok: boolean;
  line: string;
}

/** Held only when every probe was refused; the evidence keeps every line, the failing ones first. */
export function verdict(probes: readonly Probe[], prefix = ""): Result {
  const failing = probes.filter((p) => !p.ok).map((p) => `NOT REFUSED ${p.line}`);
  const passing = probes.filter((p) => p.ok).map((p) => p.line);
  return { held: probes.length > 0 && failing.length === 0, evidence: `${prefix}${[...failing, ...passing].join("; ")}` };
}

/**
 * Cost estimates in uqor, from the 17 Nov prove-registry run where measured (gas used times the
 * price paid), rounded up. A window open or close is the server's fixed fee.
 */
export const COST = {
  /** One recipient's share of a batched hybrid funding transaction. */
  sendShare: 10_000n,
  /** A whole funding transaction for one recipient. */
  sendAlone: 40_000n,
  windowOpen: 80_000n,
  windowClose: 40_000n,
  create: 50_000n,
  addRotate: 45_000n,
  addSeal: 40_000n,
  remove: 36_000n,
  /** A transaction that reverts part way pays for the gas it used. */
  reverted: 20_000n,
  /** One relayed demo admission: the bot's addMember through our relayer. */
  join: 45_000n,
  /** What the sponsor sends a new identity plus the fee of that send. */
  sponsor: 310_000n,
  /** A hybrid MsgRemoveKEMKey. */
  kemRemove: 40_000n,
} as const;

const identity = (fund: bigint): bigint => fund + COST.sendShare;

export const SETUP: Readonly<Record<SetupName, { what: string; costUqor: bigint }>> = {
  dana: { what: "test identity dana: funded once, ML-DSA-87 (proven) and ML-KEM-1024 registered", costUqor: identity(FUND_FULL_UQOR) },
  eli: { what: "test identity eli: funded once, both keys registered", costUqor: identity(FUND_FULL_UQOR) },
  fay: { what: "test identity fay: funded once, both keys registered", costUqor: identity(FUND_FULL_UQOR) },
  nokem: { what: "demo guest with an ML-DSA-87 key and no ML-KEM key", costUqor: identity(FUND_MLDSA_UQOR) },
  dust: { what: "an address funded with 1 uqor and no key, for the sponsor's funded-address test", costUqor: 1n + COST.sendAlone },
  boards: {
    what: "test boards A and B, chaired by the wallet: two creates, Dana added by rotation, Eli by seal-current, one window",
    costUqor: 2n * COST.create + COST.addRotate + COST.addSeal + COST.windowOpen,
  },
};

/** The fill identities C7 and C41 share: 63 people with both keys. */
export const FILL_COST_EACH = identity(FUND_FULL_UQOR);
