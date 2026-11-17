import { evmWindowCost } from "@qorechain/evm";
import { CHAIN_ID, EVM_CHAIN_ID, EVM_RPC, REST } from "@ava/core";

export { CHAIN_ID, EVM_CHAIN_ID, EVM_RPC, REST };

/** The consensus RPC native-lane transactions are broadcast to. @ava/core has no use for it. */
export const RPC = "https://rpc-testnet.qore.host";
export const DENOM = "uqor";

/**
 * The one contract the relayer ever sends to (threat model C24, C25). A build-time constant, so no
 * request, setting or upstream answer can point the relayer anywhere else.
 */
export const REGISTRY_ADDRESS = "0x2bB34f60B29C7bC10f7ECC0B5050329E808DAcBa" as const;
/** The block the registry was deployed in, as recorded in packages/contracts/deployments/testnet.json: no event of it is older. */
export const REGISTRY_DEPLOY_BLOCK = 10_235_963n;
/** keccak256 of the registry's runtime code, as recorded at deploy in packages/contracts/deployments/testnet.json. */
export const REGISTRY_CODE_KECCAK = "0x157b97bfe8fdc2477a2326a26cee20683bf25ca44a96f98ee5c233745f844a9b" as const;

export type RelayAction = "create" | "add" | "remove" | "rotate" | "post" | "transfer";

/**
 * Gas limit per action: the gas the 17 Nov prove-it run measured on chain, times 1.5, rounded up.
 * Every relayed transaction is sent with exactly its action's ceiling as its gas limit.
 */
export const GAS_CEILING: Readonly<Record<RelayAction, bigint>> = {
  create: 650_000n,
  add: 560_000n,
  remove: 450_000n,
  rotate: 450_000n,
  post: 500_000n,
  transfer: 450_000n,
};
export const MAX_GAS_CEILING = 650_000n;

/** 250 gwei. The testnet base fee is 100 gwei; a fee cap above this means something is wrong. */
export const MAX_FEE_PER_GAS = 250_000_000_000n;

/**
 * 8 QOR a day (UTC), in uqor: the most the relayer may lose in a day, sized for judging-day volume
 * (each guest admission is one addMember). The ledger counts window opens and closes and the worst
 * case of every relayed transaction, and no window is ever allowed more value than is left of it.
 */
export const DAILY_SPEND_CEILING_UQOR = 8_000_000n;

/**
 * Relay requests per hour (threat model C23, C24, C40). Every request counts against its IP. Only an
 * action whose exact pre-flight passes counts per chair, per board and against `total`; one whose
 * pre-flight fails counts against `rejected` instead, so junk naming a chair cannot spend that
 * chair's budget. Each rejected request costs one eth_call, and 3,000 an hour is under one a second.
 */
export const RELAY_LIMITS = { perIp: 20, perChair: 60, perBoard: 60, total: 600, rejected: 3000, windowSeconds: 3600 } as const;

/** 16 KiB. A relay body is about 9.5 KB: the 4,627-byte signature as hex plus a few short fields. */
export const RELAY_BODY_CAP = 16_384;

/** The most one relayed transaction can take from a window: the largest gas ceiling at the highest fee cap. */
export const WORST_TX_COST_UQOR = evmWindowCost({ gas: MAX_GAS_CEILING, maxFeePerGas: MAX_FEE_PER_GAS });

/**
 * The relayer's EVM window (threat model C25). Always scoped to REGISTRY_ADDRESS alone. `maxValue`
 * is the most a window is ever given; the day's remaining budget can make it smaller. Renewed when
 * fewer than 3 transactions, 600 blocks (about 14 minutes at 1.4 s) or 3 worst-case transactions of
 * value are left, so a relay never runs into the end of a window.
 */
export const WINDOW = {
  maxTxs: 40,
  blocks: 12_000,
  maxValue: 40n * WORST_TX_COST_UQOR,
  renewBelowTxs: 3n,
  renewBelowBlocks: 600n,
  renewBelowValue: 3n * WORST_TX_COST_UQOR,
} as const;

/** The docs' CLI fee for MsgCloseEVMWindow: 400,000 gas at the 0.1 uqor floor. A close used about 170,000 gas in the docs' run. */
export const WINDOW_CLOSE_FEE = { amount: [{ denom: DENOM, amount: "40000" }], gas: "400000" };
export const WINDOW_CLOSE_FEE_UQOR = 40_000n;

/**
 * The fee a window open is sent with: the 400,000 gas and 80,000 uqor the docs' CLI example uses.
 * A hybrid-signed open used about 190,000 gas in the docs' run and in ours.
 */
export const WINDOW_OPEN_FEE = { amount: [{ denom: DENOM, amount: "80000" }], gas: "400000" };
export const WINDOW_OPEN_FEE_UQOR = 80_000n;
/** The docs say a new window takes effect a few blocks after it opens. */
export const WAIT_AFTER_WINDOW_MS = 10_000;

/** No native-lane fee may exceed this, whatever a caller passes. */
export const MAX_NATIVE_FEE_UQOR = 200_000n;
/** The chain refuses any native transaction priced under 0.1 uqor per gas, kept in thousandths of a uqor. */
export const MIN_GAS_PRICE_MILLI_UQOR = 100n;

export const UQOR_PER_QOR = 1_000_000n;

/** Server-side network calls: a 4 s timeout and one retry after a pause, so one read takes at most 8.5 s. */
export const HTTP = { retries: 1, retryDelayMs: 500, timeoutMs: 4_000 } as const;

/**
 * The relay's time budget, from the moment the request arrives. Serverless functions stop at about
 * 60 s and the locks expire at 60 s, so the whole path ends by 55 s. A send never starts after 45 s
 * (the send itself takes at most 10 s), and a window is never opened after 20 s, because the open
 * (at most 15 s), its 10 s settle and the send must all still fit.
 */
export const RELAY_DEADLINE_MS = 55_000;
export const SEND_CUTOFF_MS = 45_000;
export const NATIVE_TX_BUDGET_MS = 15_000;
export const OPEN_CUTOFF_MS = 20_000;
export const LOCK_TTL_SECONDS = 60;
export const SEND_LOCK_WAIT_MS = 20_000;
export const WINDOW_LOCK_WAIT_MS = 5_000;

/**
 * What the sponsor sends a new identity, once (threat model C27): 0.25 QOR. Registering its ML-DSA-87
 * key costs 0.1 QOR and its ML-KEM-1024 key about 0.052 QOR, and guests never send EVM transactions,
 * so a scripted identity is left with under 0.1 QOR.
 */
export const SPONSOR_AMOUNT_UQOR = 250_000n;

/**
 * What a sponsored identity pays for its two registrations. The ML-DSA-87 fee is the organisers'
 * Workshop 1 example (the key used about 300,000 gas in the docs' run). The ML-KEM-1024 fee is
 * 450,000 gas at 0.15 uqor per gas; about 0.052 QOR at that price implies some 267,000 gas, not yet
 * measured on this chain. Together 0.1675 QOR, inside SPONSOR_AMOUNT_UQOR.
 */
export const KEY_REGISTRATION_FEE = { amount: [{ denom: DENOM, amount: "100000" }], gas: "800000" };
export const KEM_REGISTRATION_FEE = { amount: [{ denom: DENOM, amount: "67500" }], gas: "450000" };

/**
 * The fee of one sponsor send, a hybrid MsgSend: 300,000 gas at 0.2 uqor per gas, the window open's
 * price. The SDK measured a hybrid MsgSend at about 164,000 gas.
 */
export const SPONSOR_SEND_FEE = { amount: [{ denom: DENOM, amount: "60000" }], gas: "300000" };
export const SPONSOR_SEND_FEE_UQOR = 60_000n;

/**
 * Sponsor limits (C23, C27): 3 requests per IP per hour; 100 sends and 25 QOR per UTC day. The day's
 * QOR counts the amount and the fee of every send, so 25 QOR is the most the sponsor can lose in a day.
 */
export const SPONSOR_LIMITS = { perIp: 3, windowSeconds: 3600, perDay: 100, dailyCapUqor: 25_000_000n } as const;

/**
 * The sponsor's time budget from the moment a request arrives, inside the 60 s lock. No send starts
 * with less than NATIVE_TX_BUDGET_MS left, because a send waits for its block.
 */
export const SPONSOR_DEADLINE_MS = 55_000;
export const SPONSOR_LOCK_WAIT_MS = 20_000;

/** Members the demo board may hold in total, chair and seeded directors included (C34), below MAX_MEMBERS. */
export const DEMO_GUEST_CAP = 40;
/** A guest is removed six hours after admission. */
export const DEMO_GUEST_TTL_SECONDS = 6 * 3600;
/** A guest challenge lives five minutes. */
export const DEMO_CHALLENGE_SECONDS = 300;
/** Demo joins (C34): 3 per IP per hour, 200 in total per UTC day. */
export const DEMO_JOIN_LIMITS = { perIp: 3, windowSeconds: 3600, perDay: 200 } as const;
/**
 * Challenge requests (C23), per IP and in total, per hour. Each one writes one five-minute record.
 * The total is 100 times the per-IP limit, so only an attacker with 100 or more addresses can reach
 * it and stop judges from asking for a challenge (docs/security/runbook.md, Known limits).
 */
export const DEMO_CHALLENGE_LIMITS = { perIp: 10, total: 1_000, windowSeconds: 3600 } as const;

/**
 * One join or one sweep runs on one 120 s deadline, under a "demo:join" lock that lives 150 s, so
 * the lock always outlives the work. The relay inside keeps its own 55 s budget (RELAY_DEADLINE_MS),
 * so a relay starts only while that much is left, by 65 s; later the bot refuses with out_of_time.
 */
export const DEMO_DEADLINE_MS = 120_000;
export const DEMO_RELAY_CUTOFF_MS = DEMO_DEADLINE_MS - RELAY_DEADLINE_MS;
export const DEMO_LOCK_TTL_SECONDS = 150;
export const DEMO_LOCK_WAIT_MS = 20_000;
/** The bot's own signed actions are valid for ten minutes after the latest block. */
export const DEMO_ACTION_SECONDS = 600;
/**
 * The longest the bot waits for its own transaction to land before the next queued action reads
 * the board, because the board nonce is sequential (C34).
 */
export const DEMO_RECEIPT_WAIT_MS = 30_000;
