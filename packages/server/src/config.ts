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
 * 20 QOR a day (UTC), in uqor: the most the relayer may lose in a day, all traffic together (threat
 * model C24, C25). It counts window opens and closes and every relayed transaction, and no window is
 * ever given more value than is left of it, so a leaked classical key can burn at most what is left.
 * A transaction is booked at its worst case (gas ceiling times fee cap) before it is sent and
 * settled down to its receipt's real fee after; one with no receipt keeps its worst case. The two
 * shares below add up to this ceiling, and window fees come out of it too, so the shares are
 * limits on each kind of traffic, never a promise that both can be spent in full on one day.
 */
export const RELAYER_DAILY_CEILING_UQOR = 20_000_000n;
/** The earlier name of RELAYER_DAILY_CEILING_UQOR, kept so older imports still read the one total. */
export const DAILY_SPEND_CEILING_UQOR = RELAYER_DAILY_CEILING_UQOR;

/**
 * 8 QOR a day of public chair relays, all chairs together (C41): the demo bot's traffic can never
 * spend it, so judges acting on their own boards are served whatever the demo board does. At the
 * real fees measured on 17 Nov (an addMember about 0.04 QOR) that is some 200 actions a day.
 */
export const CHAIRS_DAILY_CEILING_UQOR = 8_000_000n;

/** 12 QOR a day of the demo bot's relays (C41), its own share, so the chairs' traffic cannot starve it either. */
export const DEMO_DAILY_CEILING_UQOR = 12_000_000n;

/**
 * 1.5 QOR a day for one chair address, public relays only, so no single chair can spend the chairs'
 * share for everyone (C40, C41). About 37 actions at today's real fees, and still 11 creates if
 * every receipt were lost and each stayed at its worst case of 0.13 QOR.
 */
export const PER_CHAIR_DAILY_UQOR = 1_500_000n;

/**
 * Relay requests per hour (threat model C23, C24, C40). Every request counts against its IP. Only an
 * action whose exact pre-flight passes counts per chair, per board and against `total`; one whose
 * pre-flight fails counts against `rejected` instead, so junk naming a chair cannot spend that
 * chair's budget. Each rejected request costs one eth_call, and 3,000 an hour is under one a second.
 */
export const RELAY_LIMITS = { perIp: 20, perChair: 60, perBoard: 60, total: 600, rejected: 3000, windowSeconds: 3600 } as const;

/**
 * The demo bot's own relays per clock hour (threat model C41): 120, room for 60 guests an hour to be
 * admitted and later removed, one relay each. The bot reserves each relay just before it makes it,
 * and its relays count against none of RELAY_LIMITS, so public traffic cannot use this room.
 */
export const DEMO_RELAYS_PER_HOUR = 120;

/**
 * Bytes of documents one chair may post in a UTC day (threat model C44): 100 MiB, four documents at
 * the registry's 25 MiB cap per document. Every posted document is kept for good at our cost, so a
 * post is budgeted by the bytes it makes permanent, not only by the fee it burns; the chairs' 8 QOR
 * a day would otherwise buy some 5 GiB of permanent storage a day.
 */
export const PER_CHAIR_DAILY_POST_BYTES = 104_857_600n;
/** Bytes of documents all chairs together may post in a UTC day (C44): 1 GiB, forty documents at the 25 MiB cap, kept for good. */
export const TOTAL_DAILY_POST_BYTES = 1_073_741_824n;

/**
 * Bytes of document upload tokens one client may be issued in a UTC day (threat model C28, C44):
 * 25 MiB, one full-size board pack at the registry's cap. Every document that is posted is kept for
 * good, whoever sends the post: the relay's post bytes budget sees only posts it relays, and a chair
 * can post from its own account. So the bytes are budgeted where they enter the store: each token
 * allows exactly the size its request states, that size is booked before the token is issued, and
 * a token whose upload never arrived gives it back once it can no longer be used.
 */
export const DOC_BYTES_PER_CLIENT_DAY = 26_214_400;
/** Every /64 of one IPv6 /48 shares four times a client's day, the factor every per-IP count here uses for a /48. */
export const DOC_BYTES_PER_NET48_DAY = 4 * DOC_BYTES_PER_CLIENT_DAY;
/**
 * Bytes of document upload tokens all clients together may be issued in a UTC day (C44): fifty
 * clients' days, 1,250 MiB. The runbook's rule for every shared total: only an attacker with 50 or
 * more addresses can spend it and stop everyone else's uploads (docs/security/runbook.md, Known
 * limits). At 100 MiB a client and 1 GiB in all, eleven addresses could.
 */
export const DOC_BYTES_TOTAL_DAY = 50 * DOC_BYTES_PER_CLIENT_DAY;

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
 * How long a relay waits for its own receipt after the send, outside the send lock, so the day's
 * ledgers can be settled to the real fee. About ten blocks; a receipt not seen by then, or by the
 * relay's deadline, leaves the worst case booked.
 */
export const RECEIPT_WAIT_MS = 15_000;

/**
 * How long a nonce check waits for the relayer's own earlier transactions to reach a block before it
 * decides (threat model C24): 10 s, about seven blocks, looked up once a second. The relay right
 * after a send usually finds that send still waiting, so it waits about a block. One of ours still
 * waiting after this is refused for now and asked about again by the next relay; a recorded hash the
 * chain does not know after this is someone else's use of the nonce, and halts. A send never starts
 * after SEND_CUTOFF_MS whatever this wait took.
 */
export const NONCE_CONFIRM_WAIT_MS = 10_000;
export const NONCE_CONFIRM_POLL_MS = 1_000;

/**
 * The widest gap between the chain's nonce and the stored one that can still be all ours. Each
 * check confirms every one of ours before anything new is signed, and one pass under the send lock
 * signs at most a close, an open and a send, so a wider gap halts without a lookup per nonce.
 */
export const NONCE_GAP_CAP = 8n;

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
/**
 * Seats the background pressure pass keeps free below DEMO_GUEST_CAP (C41): six joins can land
 * between background passes before a judge waits; each pass restores them.
 */
export const DEMO_FREE_SEATS = 6;
/** A guest is removed six hours after admission. */
export const DEMO_GUEST_TTL_SECONDS = 6 * 3600;
/** A guest challenge lives five minutes. */
export const DEMO_CHALLENGE_SECONDS = 300;
/**
 * Demo joins (C34): 3 per IP per hour, 120 in total per UTC day. A join is one addMember (at most
 * 373,334 gas measured, GAS_CEILING.add / 1.5), and each guest it seats is later removed by one
 * removeMember (at most 300,000 gas), so about 673,000 gas a guest, 0.068 QOR at the 101 gwei the
 * testnet charges today. 120 guests are 8.16 QOR, inside DEMO_DAILY_CEILING_UQOR's 12 QOR with
 * 3.84 QOR to spare.
 */
export const DEMO_JOIN_LIMITS = { perIp: 3, windowSeconds: 3600, perDay: 120 } as const;
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
