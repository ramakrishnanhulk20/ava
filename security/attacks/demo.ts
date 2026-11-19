import { Mode, accountBytes, openEpochKey, sameAccount, sameHash, sha256, toQor1 } from "@ava/core";
import { evmWindowCost } from "@qorechain/evm";
import { parseEnvelope, recipientHint } from "@qorechain/qoreseal";
import { bytesToHex, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { DAILY_SPEND_CEILING_UQOR, DEMO_GUEST_CAP, GAS_CEILING, MAX_FEE_PER_GAS } from "../../packages/server/src/config.ts";
import { COST, FILL_COST_EACH, notRun, verdict, type Attack, type Probe, type Result } from "../lib/attack.ts";
import { readBlob } from "../lib/blobs.ts";
import { ethCall, formatQor, readEvmWindow, refusalOf, registryEvents } from "../lib/chain.ts";
import type { Ctx } from "../lib/context.ts";
import { admit, askChallenge, demoHistory, fillGuests, freshGuest, join, joinBody, key, signBytes, txHashOf } from "../lib/demo.ts";
import { notConfigured, said, type DevAnswer } from "../lib/dev.ts";
import { REGISTRY } from "../lib/guard.ts";
import { FILL_RANGE, type Person } from "../lib/identities.ts";
import { removeKem } from "../lib/people.ts";
import { ZERO_SIGNATURE, boardAt, calldata, flipByte } from "../lib/registry.ts";

/** What one admission can reserve against the relayer's daily ceiling: the addMember gas ceiling at the highest fee cap. */
const WORST_JOIN_UQOR = evmWindowCost({ gas: GAS_CEILING.add, maxFeePerGas: MAX_FEE_PER_GAS });
const ONE_UQOR_WEI = 10n ** 12n;

const expect = (label: string, a: DevAnswer, status: number, error?: string): Probe => ({ ok: a.status === status && (error === undefined || a.error === error), line: `${label} -> ${said(a)}` });

const isMember = async (ctx: Ctx, boardId: bigint, who: Hex): Promise<boolean> => (await boardAt(ctx.client, boardId)).members.some((m) => sameAccount(m, who));

/** The demo board id, or the reason the demo attacks cannot run. */
function demoBoard(ctx: Ctx): bigint | Result {
  return ctx.env.demoBoardId ?? notRun("DEMO_BOARD_ID is not set in security/.env");
}

const otherBytes: Attack = {
  id: "C33-other-bytes",
  claim: "The bot is not a signing oracle: a fresh guest's join carrying its own valid signature over other bytes (the challenge for another board), and a join carrying another identity's signature over the right bytes, are both refused and admit nobody.",
  costUqor: FILL_COST_EACH,
  costNote: "one fresh guest identity, both keys registered",
  needs: ["dana"],
  async run(ctx) {
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    const dana = await ctx.need("dana");
    const guest = await freshGuest(ctx, boardId, "guest");
    const asked = await askChallenge(guest, ctx.ips.fresh());
    if (notConfigured(asked.answer)) return notRun(`the challenge endpoint answers ${said(asked.answer)}`);
    if (asked.challenge === undefined) return verdict([{ ok: false, line: `challenge -> ${said(asked.answer)}, not a challenge @ava/core rebuilds byte for byte` }]);
    const c = asked.challenge;
    ctx.state.demoGuest = { person: guest, challenge: c };
    // Byte 100 sits in the board id word, so these are the bytes of a challenge for another board.
    const other = await join(joinBody(guest, c, signBytes(guest, flipByte(c.message, 100))), ctx.ips.fresh());
    const stranger = await join(joinBody(guest, c, signBytes(dana, c.message)), ctx.ips.fresh());
    return verdict([
      { ok: true, line: `challenge for ${guest.evm}: 224 bytes, equal to @ava/core's challengeMessage for board ${c.boardId}` },
      expect("the guest's own signature over the bytes of another board's challenge", other, 403, "bad_signature"),
      expect("Dana's valid signature over the guest's real challenge", stranger, 403, "bad_signature"),
      { ok: !(await isMember(ctx, boardId, guest.evm)), line: "the guest is not a member" },
    ]);
  },
};

const challengeSurvives: Attack = {
  id: "C43-challenge-survives",
  claim: "A challenge is consumed only by a join that proves it: after the two refused joins of C33, the guest's own signature over the same challenge admits it.",
  costUqor: 0n,
  serverUqor: COST.join,
  async run(ctx) {
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    const g = ctx.state.demoGuest;
    if (g === undefined) return notRun("C33-other-bytes issued no challenge");
    const body = joinBody(g.person, g.challenge, signBytes(g.person, g.challenge.message));
    const a = await join(body, ctx.ips.fresh());
    const hash = txHashOf(a);
    if (hash === undefined) return verdict([{ ok: false, line: `the valid join with the same challenge -> ${said(a)}` }]);
    const receipt = await ctx.client.waitForTransactionReceipt({ hash, timeout: 120_000, pollingInterval: 2_000 });
    ctx.state.join = { body, txHash: hash };
    return verdict([
      { ok: receipt.status === "success", line: `the valid join with the same challenge -> 202 ${hash}, ${receipt.status}` },
      { ok: await isMember(ctx, boardId, g.person.evm), line: `${g.person.evm} is a member of board ${boardId}` },
    ]);
  },
};

const replay: Attack = {
  id: "C43-replay",
  claim: "A challenge serves one join at most: the exact join that admitted the guest, sent again, is refused and changes nothing.",
  costUqor: 0n,
  async run(ctx) {
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    const j = ctx.state.join;
    if (j === undefined) return notRun("C43-challenge-survives admitted nobody");
    const before = await boardAt(ctx.client, boardId);
    const a = await join(j.body, ctx.ips.fresh());
    const after = await boardAt(ctx.client, boardId);
    return verdict([expect("the landed join replayed", a, 409, "no_challenge"), { ok: after.nonce === before.nonce, line: `board nonce ${before.nonce} before, ${after.nonce} after` }]);
  },
};

const once: Attack = {
  id: "C34-once",
  claim: "One admission per address: the admitted guest asks for a fresh challenge, signs it correctly, and is refused.",
  costUqor: 0n,
  async run(ctx) {
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    const g = ctx.state.demoGuest;
    if (g === undefined || ctx.state.join === undefined) return notRun("no guest was admitted earlier in this run");
    const asked = await askChallenge(g.person, ctx.ips.fresh());
    if (asked.challenge === undefined) return verdict([{ ok: false, line: `fresh challenge -> ${said(asked.answer)}` }]);
    const a = await join(joinBody(g.person, asked.challenge, signBytes(g.person, asked.challenge.message)), ctx.ips.fresh());
    return verdict([{ ok: true, line: `a fresh challenge for the admitted ${g.person.evm} -> 200` }, expect("its valid join", a, 409, "already_admitted")]);
  },
};

const perIp: Attack = {
  id: "C34-per-ip",
  claim: "Joins are rate limited per address the platform reports: the fourth join from one address within the hour is refused before its body is read.",
  costUqor: 0n,
  async run(ctx) {
    if (ctx.env.demoBoardId === undefined) return notRun("DEMO_BOARD_ID is not set in security/.env");
    const from = ctx.ips.fresh();
    const answers: DevAnswer[] = [];
    for (let i = 0; i < 4; i++) answers.push(await join("{}", from));
    if (answers.some(notConfigured)) return notRun(`the join endpoint answers ${said(answers.find(notConfigured)!)}`);
    return verdict([
      { ok: answers.slice(0, 3).every((a) => a.status === 400), line: `joins 1 to 3 with an empty body: ${answers.slice(0, 3).map(said).join(", ")}` },
      expect("join 4", answers[3]!, 429, "rate_limited"),
    ], `from ${from}: `);
  },
};

const sealed: Attack = {
  id: "C35-sealed-to-guest",
  claim: "The bot reseals only what it checked, only to the genuine key: the envelope it granted the admitted guest hashes to its on-chain record, holds exactly one recipient whose hint matches the guest's on-chain ML-KEM key, and opens with the guest's keys to that epoch's key.",
  costUqor: 0n,
  async run(ctx) {
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    if (ctx.env.blobOrigin === undefined) return notRun("BLOB_ORIGIN is not set in security/.env");
    const g = ctx.state.demoGuest;
    const j = ctx.state.join;
    if (g === undefined || j === undefined) return notRun("no guest was admitted earlier in this run");
    const receipt = await ctx.client.getTransactionReceipt({ hash: j.txHash });
    const grant = registryEvents(receipt).find((e) => e.eventName === "EnvelopeGranted")?.args;
    if (grant === undefined) return verdict([{ ok: false, line: `${j.txHash} carries no EnvelopeGranted` }]);
    const envelopeHash = String(grant.envelopeHash) as Hex;
    const envelopeSize = Number(grant.envelopeSize);
    const epoch = BigInt(String(grant.epoch));
    const board = await boardAt(ctx.client, boardId);
    const read = await readBlob(`${ctx.env.blobOrigin}/envelope/${envelopeHash.slice(2).toLowerCase()}`, envelopeSize + 1);
    const bytes = read.bytes;
    const hashOk = bytes !== undefined && bytes.length === envelopeSize && sameHash(bytesToHex(sha256(bytes)), envelopeHash);
    const parsed = hashOk ? parseEnvelope(bytes) : undefined;
    const mine = parsed === undefined ? undefined : bytesToHex(recipientHint(parsed.salt, g.person.seal.mlkemPublicKey));
    let opened = false;
    if (hashOk) {
      const k = openEpochKey({ registry: REGISTRY, boardRef: board.boardRef, epoch, envelope: bytes, expectedHash: envelopeHash, expectedSize: envelopeSize, sealKeys: g.person.seal });
      opened = k.length === 32;
    }
    return verdict([
      { ok: Number(grant.mode) === Mode.SEAL_CURRENT && sameAccount(String(grant.member), g.person.evm), line: `EnvelopeGranted in ${j.txHash}: MODE_SEAL_CURRENT, member ${String(grant.member)}, epoch ${epoch}` },
      { ok: hashOk, line: `the envelope from the blob origin: ${read.status}, ${bytes?.length ?? 0} bytes, sha256 ${hashOk ? "equals" : "DIFFERS FROM"} the on-chain record` },
      { ok: parsed?.entries.length === 1 && mine !== undefined && bytesToHex(parsed.entries[0]!.hint) === mine, line: `${parsed?.entries.length ?? 0} recipient entries; the one hint ${mine !== undefined && parsed?.entries[0] !== undefined && bytesToHex(parsed.entries[0].hint) === mine ? "matches" : "DOES NOT MATCH"} the guest's on-chain ML-KEM key` },
      { ok: opened, line: `the guest's own keys open it to a 32-byte key for epoch ${epoch}` },
    ]);
  },
};

const noKem: Attack = {
  id: "C15-guest-no-kem",
  claim: "Every recipient key is genuine and found on chain: a guest with a proven ML-DSA key but no published ML-KEM key passes the signature checks and is still refused, so the bot never seals the epoch key to a key it could not look up.",
  costUqor: 0n,
  needs: ["nokem"],
  async run(ctx) {
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    const nokem = await ctx.need("nokem");
    const asked = await askChallenge(nokem, ctx.ips.fresh());
    if (notConfigured(asked.answer)) return notRun(`the challenge endpoint answers ${said(asked.answer)}`);
    if (asked.challenge === undefined) return verdict([{ ok: false, line: `challenge -> ${said(asked.answer)}` }]);
    const a = await join(joinBody(nokem, asked.challenge, signBytes(nokem, asked.challenge.message)), ctx.ips.fresh());
    return verdict([expect(`a valid join by ${nokem.evm}, which publishes no ML-KEM key`, a, 403, "no_kem_key"), { ok: !(await isMember(ctx, boardId, nokem.evm)), line: "it is not a member" }]);
  },
};

const drill: Attack = {
  id: "C36-drill-key",
  claim: "The drill key buys nothing: the demo chair's published secp256k1 key belongs to the chair's account, which holds no live EVM window, and from that very account a replay of the bot's last landed action, fresh board actions without the ML-DSA signature, and a value transfer are all refused.",
  costUqor: 0n,
  costNote: "eth_call only; nothing is ever signed with the drill key",
  async run(ctx) {
    if (ctx.env.drillKey === undefined) return notRun("not yet published: DRILL_PUBLISHED_KEY stays empty until the drill's attack log is out");
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    const chair = privateKeyToAccount(ctx.env.drillKey).address;
    const board = await boardAt(ctx.client, boardId);
    if (!sameAccount(chair, board.chair)) return notRun(`the published key's account ${chair} is not the demo chair ${board.chair}`);
    const h = await demoHistory(ctx, boardId, true);
    const w = await readEvmWindow(toQor1(accountBytes(chair)));
    const call = async (label: string, data: Hex, expected: readonly string[], value?: bigint): Promise<Probe> => {
      const outcome = await ethCall(ctx.client, { from: chair, to: REGISTRY, data, ...(value === undefined ? {} : { value }) });
      const r = refusalOf(outcome);
      return { ok: !outcome.ok && (expected.length === 0 || expected.includes(r.name)), line: `${label}: ${r.text}` };
    };
    const member = board.members.find((m) => !sameAccount(m, board.chair));
    const deadline = await ctx.deadline();
    const probes: Probe[] = [{ ok: !w.found || !w.live, line: `the chair's EVM window: found ${w.found}, live ${w.live}` }];
    if (h.lastTx !== undefined) {
      const tx = await ctx.client.getTransaction({ hash: h.lastTx });
      probes.push(await call(`the bot's last landed action ${h.lastTx}, replayed from the chair's own account`, tx.input, []));
    }
    if (member !== undefined) {
      probes.push(await call("removeMember from the chair's account, no ML-DSA signature", calldata.removeMember({ boardId, member, envelopeHash: `0x${"11".repeat(32)}`, envelopeSize: 1000, epochAfter: board.epoch + 1n, deadline, signature: ZERO_SIGNATURE }), ["BadSignature"]));
      probes.push(await call("transferChair from the chair's account, no ML-DSA signature", calldata.transferChair({ boardId, newChair: member, deadline, signature: ZERO_SIGNATURE }), ["BadSignature", "PossessionNotProven", "NoPqcKey"]));
    }
    probes.push(await call("postDocument from the chair's account, no ML-DSA signature", calldata.postDocument({ boardId, docRef: `0x${"22".repeat(32)}`, cipherHash: `0x${"33".repeat(32)}`, cipherSize: 1000n, epoch: board.epoch, deadline, signature: ZERO_SIGNATURE }), ["BadSignature"]));
    probes.push(await call("1 uqor from the chair's account to the registry", "0x", [""], ONE_UQOR_WEI));
    return verdict(probes, "nothing broadcast, nothing signed with the drill key: ");
  },
};

/** The current guests, oldest admission first, from the registry's events: everyone but the chair and the seeded directors. */
async function guestsByAge(ctx: Ctx, boardId: bigint): Promise<Hex[]> {
  const board = await boardAt(ctx.client, boardId);
  const h = await demoHistory(ctx, boardId, true);
  const protectedOnes = [board.chair, ...ctx.env.demoSeeded];
  const guests = board.members.filter((m) => !protectedOnes.some((p) => sameAccount(p, m)));
  return guests.sort((a, b) => {
    const x = h.addedAt.get(key(a)) ?? 0n;
    const y = h.addedAt.get(key(b)) ?? 0n;
    return x < y ? -1 : x > y ? 1 : 0;
  });
}

/** What filling the board costs the wallet now: identities this run has not already made ready, plus the judge. */
async function fillCost(ctx: Ctx, boardId: bigint, need: number): Promise<bigint> {
  const h = await demoHistory(ctx, boardId);
  const reusable = (await ctx.people.fill(FILL_RANGE.count)).filter((p) => !h.admitted.has(key(p.evm)) && ctx.people.isReady(p)).length;
  return BigInt(Math.max(0, need - reusable) + 1) * FILL_COST_EACH;
}

const full: Attack = {
  id: "C41-full-board",
  claim: `A fresh judge can always join: with the demo board filled to its cap of ${DEMO_GUEST_CAP}, a new judge's join still admits, and the guest removed to make room is the oldest one.`,
  costUqor: FILL_COST_EACH,
  serverUqor: BigInt(DEMO_GUEST_CAP - 3) * COST.join + COST.remove,
  costNote: `the judge; the fill reuses C7-exceed-64's identities, else up to ${DEMO_GUEST_CAP - 4} more at 0.23 QOR each; our relayer pays every admission, reserving up to ${formatQor(WORST_JOIN_UQOR)} QOR each against its ${formatQor(DAILY_SPEND_CEILING_UQOR)} QOR daily ceiling; runs only if both hold it`,
  async run(ctx) {
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    if (ctx.env.demoSeeded.length === 0) return notRun("DEMO_SEEDED is not set in security/.env; telling guests from seeded directors needs it");
    const start = await boardAt(ctx.client, boardId);
    const need = DEMO_GUEST_CAP - start.members.length;
    if (need < 0) return notRun(`the board holds ${start.members.length} members, above the cap of ${DEMO_GUEST_CAP}`);
    const reserve = BigInt(need + 2) * WORST_JOIN_UQOR;
    if (reserve > DAILY_SPEND_CEILING_UQOR) return notRun(`the fill would reserve up to ${formatQor(reserve)} QOR of relayer spend, past its ${formatQor(DAILY_SPEND_CEILING_UQOR)} QOR daily ceiling`);
    const cost = await fillCost(ctx, boardId, need);
    const { ok, balance } = await ctx.affordable(cost);
    if (!ok) return notRun(`would cost ${formatQor(cost)} QOR; the wallet holds ${formatQor(balance)} QOR`);

    const guests = await fillGuests(ctx, boardId, need);
    for (const [i, guest] of guests.entries()) {
      const r = await admit(ctx, guest);
      if (!r.landed) return verdict([{ ok: false, line: `filling: guest ${i + 1} of ${need}, ${guest.evm}: ${r.steps}` }]);
    }
    ctx.state.filled = { guests };
    const before = await guestsByAge(ctx, boardId);
    const filled = await boardAt(ctx.client, boardId);
    const judge = await freshGuest(ctx, boardId, "judge1");
    const r = await admit(ctx, judge);
    const after = await boardAt(ctx.client, boardId);
    const gone = before.filter((g) => !after.members.some((m) => sameAccount(m, g)));
    return verdict([
      { ok: filled.members.length === DEMO_GUEST_CAP, line: `the board was filled from ${start.members.length} to ${filled.members.length} members by ${need} admissions` },
      { ok: r.landed, line: `a new judge ${judge.evm} joins the full board: ${r.steps}` },
      { ok: after.members.some((m) => sameAccount(m, judge.evm)) && after.members.length === DEMO_GUEST_CAP, line: `the judge is a member; the board holds ${after.members.length}` },
      { ok: gone.length === 1 && before[0] !== undefined && sameAccount(gone[0]!, before[0]), line: `removed to make room: ${gone.join(", ") || "nobody"}; the oldest guest was ${before[0] ?? "none"}` },
    ]);
  },
};

const badKey: Attack = {
  id: "C42-bad-key-guest",
  claim: "No member's key state can block another's removal: on the full board, a guest that is not the oldest withdraws its ML-KEM key, and the next judge's join removes that guest rather than the oldest one.",
  costUqor: FILL_COST_EACH + COST.kemRemove,
  serverUqor: COST.join + COST.remove,
  costNote: "a second judge, and the withdrawal paid from the guest's own leftover funds; runs only after C41 filled the board",
  async run(ctx) {
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    const filled = ctx.state.filled;
    if (filled === undefined) return notRun("C41-full-board did not fill the board in this run");
    const { ok, balance } = await ctx.affordable(FILL_COST_EACH);
    if (!ok) return notRun(`would cost ${formatQor(FILL_COST_EACH)} QOR; the wallet holds ${formatQor(balance)} QOR`);
    const byAge = await guestsByAge(ctx, boardId);
    const oldest = byAge[0];
    const board = await boardAt(ctx.client, boardId);
    const target: Person | undefined = [...filled.guests].reverse().find((g) => board.members.some((m) => sameAccount(m, g.evm)) && (oldest === undefined || !sameAccount(g.evm, oldest)));
    if (target === undefined || oldest === undefined) return notRun("none of this run's guests is left on the board besides the oldest");
    const withdrawn = await removeKem(target);
    const judge = await freshGuest(ctx, boardId, "judge2");
    const r = await admit(ctx, judge);
    const after = await boardAt(ctx.client, boardId);
    return verdict([
      { ok: true, line: `${target.evm} withdrew its ML-KEM key in ${withdrawn.hash}` },
      { ok: r.landed, line: `a new judge ${judge.evm} joins the full board: ${r.steps}` },
      { ok: !after.members.some((m) => sameAccount(m, target.evm)), line: `${target.evm} (key missing) ${after.members.some((m) => sameAccount(m, target.evm)) ? "IS STILL A MEMBER" : "was removed"}` },
      { ok: after.members.some((m) => sameAccount(m, oldest)), line: `the oldest guest ${oldest} ${after.members.some((m) => sameAccount(m, oldest)) ? "stays" : "WAS REMOVED"}` },
    ]);
  },
};

export const attacks: readonly Attack[] = [otherBytes, challengeSurvives, replay, once, perIp, sealed, noKem, drill, full, badKey];
