import { Mode, accountBytes, openEpochKey, sameAccount, sameHash, sha256, toQor1 } from "@ava/core";
import { evmWindowCost } from "@qorechain/evm";
import { parseEnvelope, recipientHint } from "@qorechain/qoreseal";
import { bytesToHex, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { DEMO_DAILY_CEILING_UQOR, DEMO_GUEST_CAP, GAS_CEILING, MAX_FEE_PER_GAS } from "../../packages/server/src/config.ts";
import { COST, FILL_COST_EACH, notRun, verdict, type Attack, type Probe, type Result } from "../lib/attack.ts";
import { readBlob } from "../lib/blobs.ts";
import { ethCall, feeForGas, formatQor, nativeTx, readEvmWindow, refusalOf, registryEvents, simulateNative, sleep, type CommittedTx } from "../lib/chain.ts";
import type { Ctx } from "../lib/context.ts";
import { PASS_WITHIN_MS, SEATS_AFTER_PASS, admit, askChallenge, demoHistory, fillGuests, freshGuest, join, joinBody, key, ourGuests, passLine, signBytes, sponsoredGuest, typedJoinBody, type PassSeen } from "../lib/demo.ts";
import { notConfigured, said, type DevAnswer } from "../lib/dev.ts";
import { REGISTRY } from "../lib/guard.ts";
import { FILL_RANGE, NOKEM_SPONSORED_RANGE, SHARED_KEM_SPONSORED_RANGE, SPONSORED_NOKEM_PROFILE, type Person } from "../lib/identities.ts";
import { KEM_FEE_EST_UQOR, isOurProvenKey, kemMessages, kemOf, removeKem, standingOf } from "../lib/people.ts";
import { ZERO_SIGNATURE, boardAt, calldata, flipByte, type Board } from "../lib/registry.ts";

/** What one admission can reserve against the relayer's daily ceiling: the addMember gas ceiling at the highest fee cap. */
const WORST_JOIN_UQOR = evmWindowCost({ gas: GAS_CEILING.add, maxFeePerGas: MAX_FEE_PER_GAS });
/** The same for one removal by a pressure pass. */
const WORST_REMOVE_UQOR = evmWindowCost({ gas: GAS_CEILING.remove, maxFeePerGas: MAX_FEE_PER_GAS });
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
  claim:
    "A challenge is consumed only by a join that proves it: after the two refused joins of C33, the guest's own signature over the same challenge passes the challenge check and admits it. At a full board the bot answers 503 board_full before it reads the challenge, so the same join admits the guest once the background pass has freed seats.",
  costUqor: 0n,
  serverUqor: COST.join + COST.remove,
  costNote: "our relayer pays the admission, and the removal of the pass it starts when it leaves the board above 34",
  async run(ctx) {
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    const g = ctx.state.demoGuest;
    if (g === undefined) return notRun("C33-other-bytes issued no challenge");
    const r = await admit(ctx, g.person, joinBody(g.person, g.challenge, signBytes(g.person, g.challenge.message)));
    if (r.landed && r.body !== undefined && r.txHash !== undefined) ctx.state.join = { body: r.body, txHash: r.txHash };
    const first = r.full === undefined ? "admitted it" : "answered 503 board_full, which the bot gives before it reads the challenge or counts anything";
    return verdict([
      { ok: r.landed, line: `the valid join with the same challenge ${first}: ${r.steps}` },
      { ok: r.pass === undefined || r.pass.reached, line: r.pass === undefined ? "the admission left the board at 34 members or fewer, so it started no pass" : `the pass the admission started ${passLine(r.pass)}` },
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

/** Failed joins the bot takes from one address in a UTC day before it answers too_many_failures. */
const FAILED_JOINS_ALLOWED = 5;

const membersOf = (b: Board): string => b.members.map(key).sort().join(",");

const noKemGuest: Attack = {
  id: "C33-no-kem-guest",
  claim: `A guest with no ML-KEM key gets nothing from the bot and cannot wear it down: a fresh sponsored guest with a proven ML-DSA-87 key and no ML-KEM key makes ${FAILED_JOINS_ALLOWED + 1} valid joins of the demo board; the first ${FAILED_JOINS_ALLOWED} answer 403 no_kem_key, the last 429 too_many_failures, and the board's members and nonce never move: a refused join seats nobody, removes nobody and starts no background pass.`,
  costUqor: 0n,
  serverUqor: COST.sponsor,
  costNote: "our sponsor funds one fresh guest, which pays its own ML-DSA-87 registration from that; the bot sends nothing",
  async run(ctx) {
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    const sponsored = await sponsoredGuest(ctx, NOKEM_SPONSORED_RANGE, "nokem-guest");
    if ("why" in sponsored) return notRun(sponsored.why);
    const guest = sponsored.person;
    await ctx.people.ensureAll([{ person: guest, profile: SPONSORED_NOKEM_PROFILE }]);
    const standing = await standingOf(guest);
    const start = await boardAt(ctx.client, boardId);
    const probes: Probe[] = [
      { ok: isOurProvenKey(standing.pqc, guest) && standing.kem === undefined, line: `${sponsored.line}, its ML-DSA-87 key registered with a proof of possession, no ML-KEM key published` },
    ];
    let moved: string | undefined;
    for (let i = 1; i <= FAILED_JOINS_ALLOWED + 1; i++) {
      const asked = await askChallenge(guest, ctx.ips.fresh());
      if (notConfigured(asked.answer)) return notRun(`the challenge endpoint answers ${said(asked.answer)}`);
      if (asked.challenge === undefined) {
        probes.push({ ok: false, line: `join ${i}: its challenge -> ${said(asked.answer)}` });
        continue;
      }
      const a = await join(await typedJoinBody(ctx, guest, asked.challenge), ctx.ips.fresh());
      probes.push(i <= FAILED_JOINS_ALLOWED ? expect(`join ${i}, signed by signChallenge`, a, 403, "no_kem_key") : expect(`join ${i}, signed the same way`, a, 429, "too_many_failures"));
      const now = await boardAt(ctx.client, boardId);
      if (moved === undefined && (now.nonce !== start.nonce || membersOf(now) !== membersOf(start))) moved = `after join ${i}: nonce ${now.nonce}, ${now.members.length} members`;
    }
    probes.push({
      ok: moved === undefined,
      line:
        moved === undefined
          ? `board ${boardId} after every join: nonce ${start.nonce} and the same ${start.members.length} members (a judge joining in these minutes would move it too)`
          : `board ${boardId} CHANGED ${moved}, from nonce ${start.nonce} with ${start.members.length} members`,
    });
    probes.push({
      ok: true,
      line:
        start.members.length >= SEATS_AFTER_PASS
          ? `the board held ${start.members.length}, where any admission would have started a background pass, so the still board also shows none started`
          : `the board held ${start.members.length}, under ${SEATS_AFTER_PASS}, where even an admission starts no pass: this run shows no pass was started only through the members and nonce`,
    });
    return verdict(probes);
  },
};

const sameBytes = (a: Uint8Array | undefined, b: Uint8Array): boolean => a !== undefined && Buffer.from(a).equals(Buffer.from(b));
/** How long a landed MsgRegisterKEMKey may take to show through qor_getKEMKey. */
const KEM_VISIBLE_WITHIN_MS = 30_000;

const sharedKem: Attack = {
  id: "C15-shared-kem-guest",
  claim:
    "One ML-KEM key, one member: a fresh sponsored guest with a proven ML-DSA-87 key registers the seeded director Asha's published ML-KEM key as its own with MsgRegisterKEMKey. The chain refuses the copy, or, if it takes it, the bot refuses the copier's join 403 key_shared and the board's members and nonce do not move.",
  costUqor: 0n,
  serverUqor: COST.sponsor,
  costNote: `our sponsor funds one fresh guest from indices ${SHARED_KEM_SPONSORED_RANGE.from} to ${SHARED_KEM_SPONSORED_RANGE.to}, which pays its own ML-DSA-87 registration from that, and its MsgRegisterKEMKey too (up to about ${formatQor(KEM_FEE_EST_UQOR)} QOR) only if the chain's simulation takes the copy; then one join the bot must refuse before any relay`,
  async run(ctx) {
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    // DEMO_SEEDED lists Asha, Ben and Chen in that order (packages/server/scripts/seed-demo-board.ts).
    const asha = ctx.env.demoSeeded[0];
    if (asha === undefined) return notRun("DEMO_SEEDED is not set in security/.env; the attack copies the first seeded director's key");
    if (!(await isMember(ctx, boardId, asha))) return notRun(`Asha ${asha} is not a member of board ${boardId}`);
    const published = await kemOf(asha);
    if (published === undefined) return notRun(`Asha ${asha} publishes no ML-KEM key`);
    const sponsored = await sponsoredGuest(ctx, SHARED_KEM_SPONSORED_RANGE, "copier");
    if ("why" in sponsored) return notRun(sponsored.why);
    const guest = sponsored.person;
    await ctx.people.ensureAll([{ person: guest, profile: SPONSORED_NOKEM_PROFILE }]);
    const standing = await standingOf(guest);
    const probes: Probe[] = [
      { ok: isOurProvenKey(standing.pqc, guest) && standing.kem === undefined, line: `${sponsored.line}, its ML-DSA-87 key registered with a proof of possession, no ML-KEM key published` },
    ];
    // A refusal counts only if the same guest registering its own key would pass, so it is the copy that is refused.
    const control = await simulateNative(guest, "hybrid", kemMessages(guest));
    probes.push({ ok: control.ok, line: `control: the chain simulates the guest registering its own ML-KEM key: ${control.ok ? `passes, ${control.gasUsed} gas` : `REFUSED HTTP ${control.status}: ${control.message}`}` });
    const copy = kemMessages(guest, published.kemPublicKey);
    const simulated = await simulateNative(guest, "hybrid", copy);
    const unchanged = async (): Promise<Probe> => {
      const now = await kemOf(guest.evm);
      return { ok: now === undefined, line: now === undefined ? `qor_getKEMKey(${guest.evm}) still finds no key` : `qor_getKEMKey(${guest.evm}) NOW ANSWERS A KEY` };
    };
    if (!simulated.ok) {
      probes.push({ ok: true, line: `MsgRegisterKEMKey from ${guest.qor1} carrying Asha's key (${asha}), simulated by the chain, nothing broadcast: refused HTTP ${simulated.status}: ${simulated.message}` });
      probes.push(await unchanged());
      return verdict(probes, "the chain refuses the copy: ");
    }
    let tx: CommittedTx;
    try {
      tx = await nativeTx(guest, "hybrid", copy, feeForGas(simulated.gasUsed));
    } catch (err) {
      const text = err instanceof Error ? err.message.replace(/\s+/g, " ").slice(0, 300) : String(err);
      if (!/Refused before inclusion|failed on chain/.test(text)) throw err;
      probes.push({ ok: true, line: `MsgRegisterKEMKey carrying Asha's key passed the simulation (${simulated.gasUsed} gas), then the chain refused it: ${text}` });
      probes.push(await unchanged());
      return verdict(probes, "the chain refuses the copy: ");
    }
    let seen = await kemOf(guest.evm);
    for (const started = Date.now(); seen === undefined && Date.now() - started < KEM_VISIBLE_WITHIN_MS; seen = await kemOf(guest.evm)) await sleep(3_000);
    probes.push({
      ok: seen !== undefined && sameBytes(seen.kemPublicKey, published.kemPublicKey),
      line: `the chain TAKES the copy: MsgRegisterKEMKey ${tx.hash} (fee ${tx.fee.amount[0]?.amount ?? "?"} uqor, paid by the guest); qor_getKEMKey(${guest.evm}) answers ${seen === undefined ? "no key" : sameBytes(seen.kemPublicKey, published.kemPublicKey) ? "Asha's key, byte for byte" : "a key that is not Asha's"}`,
    });
    const before = await boardAt(ctx.client, boardId);
    const asked = await askChallenge(guest, ctx.ips.fresh());
    if (notConfigured(asked.answer)) return notRun(`the challenge endpoint answers ${said(asked.answer)}, after the chain took the copy in ${tx.hash}`);
    if (asked.challenge === undefined) {
      probes.push({ ok: false, line: `the copier's challenge -> ${said(asked.answer)}` });
      return verdict(probes, "the chain takes a copied key: ");
    }
    const a = await join(await typedJoinBody(ctx, guest, asked.challenge), ctx.ips.fresh());
    const after = await boardAt(ctx.client, boardId);
    probes.push(expect(`the copier's valid join of board ${boardId}, signed by signChallenge`, a, 403, "key_shared"));
    probes.push({
      ok: after.nonce === before.nonce && membersOf(after) === membersOf(before),
      line: `board ${boardId}: nonce ${before.nonce} before and ${after.nonce} after, ${before.members.length} members before and ${after.members.length} after, ${membersOf(after) === membersOf(before) ? "the same members" : "MEMBERS CHANGED"} (a judge joining in these minutes would move it too)`,
    });
    return verdict(probes, "the chain takes a copied key, so the bot's rule is what holds: ");
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

/** What the joins cost the wallet now: fill identities this run has not already made ready, plus the judge. */
async function fillCost(ctx: Ctx, boardId: bigint, need: number): Promise<bigint> {
  const h = await demoHistory(ctx, boardId);
  const reusable = (await ctx.people.fill(FILL_RANGE.count)).filter((p) => !h.admitted.has(key(p.evm)) && ctx.people.isReady(p)).length;
  return BigInt(Math.max(0, need - reusable) + 1) * FILL_COST_EACH;
}

/**
 * The guests whose key a pressure pass would remove first, as far as this suite can see from
 * outside: no ML-KEM key published, or one byte-equal to another member's. A key that changed
 * since the epoch was sealed to it shows only to the bot, which opens the envelopes.
 */
async function keyProblems(board: Board, guests: readonly Hex[]): Promise<Set<string>> {
  const keys = new Map<string, string | undefined>();
  for (let start = 0; start < board.members.length; start += 4) {
    const batch = board.members.slice(start, start + 4);
    const found = await Promise.all(batch.map((m) => kemOf(m)));
    batch.forEach((m, i) => keys.set(key(m), found[i] === undefined ? undefined : bytesToHex(found[i]!.kemPublicKey)));
  }
  const holders = new Map<string, number>();
  for (const k of keys.values()) if (k !== undefined) holders.set(k, (holders.get(k) ?? 0) + 1);
  return new Set(
    guests.map(key).filter((g) => {
      const k = keys.get(g);
      return k === undefined || (holders.get(k) ?? 0) > 1;
    }),
  );
}

/** The order a pressure pass takes guests in (planRemoval in packages/server/src/demo.ts): key problems first, then the oldest admission. */
const passOrder = (byAge: readonly Hex[], problems: ReadonlySet<string>): Hex[] => [...byAge.filter((g) => problems.has(key(g))), ...byAge.filter((g) => !problems.has(key(g)))];

const sameSet = (a: readonly Hex[], b: readonly Hex[]): boolean => a.length === b.length && a.every((x) => b.some((y) => sameAccount(x, y)));

/** The pass an admission started: it freed the guest's seat again, taking whom the pass order names first and never the guest just admitted. */
function passAfter(label: string, pass: PassSeen | undefined, order: readonly Hex[], problems: ReadonlySet<string>, admitted: Hex): Probe {
  if (pass === undefined) return { ok: false, line: `${label}: NO PASS WAS SEEN` };
  const expected = passOrder(order, problems).slice(0, pass.removed.length);
  const lost = pass.removed.some((m) => sameAccount(m, admitted));
  return {
    ok: pass.reached && pass.removed.length > 0 && sameSet(pass.removed, expected) && !lost,
    line: `${label}; with no request from the suite, the background pass ${passLine(pass)}; the pass order names ${expected.join(", ") || "nobody"}; the guest just admitted ${lost ? "WAS REMOVED" : "stays"}`,
  };
}

const KEY_CHANGED_NOTE: Probe = {
  ok: true,
  line: "not covered here: a guest whose key changed since its epoch was sealed is taken first by the bot, which opens the envelopes; this suite sees missing and shared keys only, so such a guest would show here as out of order",
};

/** The board_full branch, live: the board is at its cap, so the judge's first join must be refused and moves nothing. */
async function atCap(ctx: Ctx, boardId: bigint, start: Board, byAge: readonly Hex[], problems: ReadonlySet<string>): Promise<Result> {
  const judge = await freshGuest(ctx, boardId, "judge1");
  const r = await admit(ctx, judge);
  const probes: Probe[] = [{ ok: true, line: `path: full board. Board ${boardId} held ${start.members.length} members, its cap, so this run tests the board_full branch live` }];
  const f = r.full;
  if (f === undefined) return verdict([...probes, { ok: false, line: `a fresh judge ${judge.evm} joins the full board: ${r.steps}` }]);
  const firstPass = passOrder(byAge, problems).slice(0, f.pass.removed.length);
  const still = f.after.nonce === f.before.nonce && membersOf(f.after) === membersOf(f.before);
  probes.push(
    { ok: f.retryAfter === "30", line: `a fresh judge ${judge.evm} joins: 503 board_full, retry-after ${f.retryAfter ?? "none"}` },
    { ok: still, line: `board ${boardId} just before that join: ${f.before.members.length} members, nonce ${f.before.nonce}; read just after its answer: ${f.after.members.length} members, nonce ${f.after.nonce}, ${still ? "the same members" : "MEMBERS CHANGED"}` },
    { ok: f.pass.reached, line: `with no request from the suite, the background pass ${passLine(f.pass)}` },
    { ok: f.pass.removed.length > 0 && sameSet(f.pass.removed, firstPass), line: `the pass order (key problems the suite can see first, then the oldest admission) names ${firstPass.join(", ") || "nobody"}` },
    { ok: !f.pass.removed.some((m) => sameAccount(m, judge.evm)), line: "the judge is not among the guests removed" },
    {
      ok: r.landed && f.sameChallenge,
      line: `then the judge sends the same join again: ${r.landed ? `202 ${r.txHash}, landed, ${f.sameChallenge ? "on the challenge board_full left in place" : "BUT ONLY ON A FRESH CHALLENGE: THE FIRST WAS GONE"}` : `NOT ADMITTED: ${r.steps}`}`,
    },
  );
  if (r.landed) {
    const order = [...byAge.filter((g) => !f.pass.removed.some((m) => sameAccount(m, g))), judge.evm];
    probes.push(passAfter("the judge's admission", r.pass, order, problems, judge.evm));
  }
  const end = await boardAt(ctx.client, boardId);
  probes.push({ ok: end.members.some((m) => sameAccount(m, judge.evm)), line: `the judge is a member; the board holds ${end.members.length}` }, KEY_CHANGED_NOTE);
  return verdict(probes);
}

/**
 * Below the cap the suite cannot fill the board: every admission that leaves more than
 * SEATS_AFTER_PASS members starts a pass that brings it back. So it makes the joins that would fill
 * it, one at a time, and shows each lands and each pass frees the seat again.
 */
async function belowCap(ctx: Ctx, boardId: bigint, start: Board, joins: number, byAge: readonly Hex[], problems: ReadonlySet<string>): Promise<Result> {
  const guests = [...(await fillGuests(ctx, boardId, joins - 1)), await freshGuest(ctx, boardId, "judge1")];
  const probes: Probe[] = [
    {
      ok: true,
      line: `path: below the cap. Board ${boardId} held ${start.members.length} members, under its cap of ${DEMO_GUEST_CAP}, so this run makes the ${joins} joins that would fill it, one at a time, the last a fresh judge; board_full is not run live on this path (C41-board-full lists its unit tests)`,
    },
  ];
  let order = [...byAge];
  for (const [i, guest] of guests.entries()) {
    const label = `join ${i + 1} of ${joins}, ${guest.evm}`;
    const r = await admit(ctx, guest);
    if (r.full !== undefined || !r.landed) return verdict([...probes, { ok: false, line: `${label}: ${r.steps}` }]);
    order = [...order, guest.evm];
    if (r.pass === undefined) {
      probes.push({ ok: true, line: `${label}: 202 ${r.txHash}, landed, leaving ${SEATS_AFTER_PASS} members or fewer, which starts no pass` });
      continue;
    }
    const removed = r.pass.removed;
    probes.push(passAfter(`${label}: 202 ${r.txHash}, landed`, r.pass, order, problems, guest.evm));
    order = order.filter((g) => !removed.some((m) => sameAccount(m, g)));
  }
  const end = await boardAt(ctx.client, boardId);
  probes.push({ ok: end.members.length <= SEATS_AFTER_PASS, line: `after the last join the board holds ${end.members.length} members, and no join met board_full` }, KEY_CHANGED_NOTE);
  return verdict(probes);
}

const full: Attack = {
  id: "C41-full-board",
  claim: `A judge never costs a guest a seat and waits seconds, not for a removal of their own: at a full demo board of ${DEMO_GUEST_CAP}, a fresh judge's join answers 503 board_full and moves nothing, the dev server's background pass alone brings the board to ${SEATS_AFTER_PASS} within ${PASS_WITHIN_MS / 60_000} minutes, removing the oldest guests (key problems first) and never the judge, and the judge's same join, on the challenge board_full left unused, then admits 202. Below the cap, the joins that would fill it land one at a time, none meets board_full, and each pass brings the board back to ${SEATS_AFTER_PASS}, removing the oldest and never the guest just admitted.`,
  costUqor: FILL_COST_EACH,
  serverUqor: COST.join + BigInt(DEMO_GUEST_CAP + 1 - SEATS_AFTER_PASS) * COST.remove,
  costNote: `runs before any other attack joins the demo board. The wallet pays for the judge; below the cap, up to ${DEMO_GUEST_CAP - 4} fill guests more at 0.23 QOR each, C7-exceed-64's identities first. Our relayer pays, at a full board, the judge's admission and ${DEMO_GUEST_CAP + 1 - SEATS_AFTER_PASS} pass removals (shown); below the cap, one admission per join and one removal for each join past ${SEATS_AFTER_PASS}. Each reserves up to ${formatQor(WORST_JOIN_UQOR)} QOR (an admission) or ${formatQor(WORST_REMOVE_UQOR)} QOR (a removal) against the demo bot's own ${formatQor(DEMO_DAILY_CEILING_UQOR)} QOR daily share; runs only if both hold it`,
  async run(ctx) {
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    if (ctx.env.demoSeeded.length === 0) return notRun("DEMO_SEEDED is not set in security/.env; telling guests from seeded directors needs it");
    const start = await boardAt(ctx.client, boardId);
    const capped = start.members.length >= DEMO_GUEST_CAP;
    const joins = capped ? 1 : DEMO_GUEST_CAP - start.members.length;
    const removals = Math.max(0, start.members.length + joins - SEATS_AFTER_PASS);
    const reserve = BigInt(joins) * WORST_JOIN_UQOR + BigInt(removals) * WORST_REMOVE_UQOR;
    if (reserve > DEMO_DAILY_CEILING_UQOR) return notRun(`${joins} joins and ${removals} removals would reserve up to ${formatQor(reserve)} QOR of relayer spend, past the demo bot's own ${formatQor(DEMO_DAILY_CEILING_UQOR)} QOR daily share`);
    const cost = await fillCost(ctx, boardId, joins - 1);
    const { ok, balance } = await ctx.affordable(cost);
    if (!ok) return notRun(`would cost ${formatQor(cost)} QOR; the wallet holds ${formatQor(balance)} QOR`);
    const byAge = await guestsByAge(ctx, boardId);
    const problems = await keyProblems(start, byAge);
    return capped ? atCap(ctx, boardId, start, byAge, problems) : belowCap(ctx, boardId, start, joins, byAge, problems);
  },
};

/** Guests C42 admits itself when no guest this run admitted is on the board besides its oldest. */
const C42_OWN_GUESTS = 1;

/** The most recently admitted of `ours` still on the board that is not its oldest guest, so only its key state can explain a pass taking it first. */
async function keyTarget(ctx: Ctx, boardId: bigint, ours: readonly Person[]): Promise<{ target: Person; byAge: Hex[] } | undefined> {
  const byAge = await guestsByAge(ctx, boardId);
  const oldest = byAge[0];
  if (oldest === undefined) return undefined;
  const target = [...ours].reverse().find((g) => byAge.some((m) => sameAccount(m, g.evm)) && !sameAccount(g.evm, oldest));
  return target === undefined ? undefined : { target, byAge };
}

const badKey: Attack = {
  id: "C42-bad-key-guest",
  claim: `No member's key state can block another's removal: with the demo board at ${SEATS_AFTER_PASS} members, a guest that is not the oldest withdraws its ML-KEM key, a fresh judge's admission takes the board to ${SEATS_AFTER_PASS + 1}, and the background pass that admission starts removes the guest with no key, not the oldest one.`,
  costUqor: BigInt(C42_OWN_GUESTS + 1) * FILL_COST_EACH + COST.kemRemove,
  serverUqor: BigInt(C42_OWN_GUESTS + 1) * (COST.join + COST.remove),
  costNote: `a second judge, plus ${C42_OWN_GUESTS} fresh guest of its own when no guest this run admitted is on the board besides its oldest (the worst case shown); each admission past ${SEATS_AFTER_PASS} members is one addMember and one pass removal by our relayer; the withdrawal is paid from the guest's own leftover funds; runs only on a board of ${SEATS_AFTER_PASS} to ${DEMO_GUEST_CAP - 1} members`,
  async run(ctx) {
    const boardId = demoBoard(ctx);
    if (typeof boardId !== "bigint") return boardId;
    if (ctx.env.demoSeeded.length === 0) return notRun("DEMO_SEEDED is not set in security/.env; telling guests from seeded directors needs it");
    const start = await boardAt(ctx.client, boardId);
    if (start.members.length < SEATS_AFTER_PASS || start.members.length >= DEMO_GUEST_CAP) {
      return notRun(`the board holds ${start.members.length} members; this attack needs ${SEATS_AFTER_PASS} to ${DEMO_GUEST_CAP - 1}, so the judge's admission starts a pass and meets no full board (C41-full-board leaves it at ${SEATS_AFTER_PASS})`);
    }
    let found = await keyTarget(ctx, boardId, ourGuests(ctx));
    const setup: Probe[] = [];
    if (found === undefined) {
      const cost = BigInt(C42_OWN_GUESTS + 1) * FILL_COST_EACH;
      const { ok, balance } = await ctx.affordable(cost);
      if (!ok) return notRun(`no guest this run admitted is on the board besides its oldest, and admitting ${C42_OWN_GUESTS} of its own plus the judge would cost ${formatQor(cost)} QOR; the wallet holds ${formatQor(balance)} QOR`);
      for (let i = 1; i <= C42_OWN_GUESTS; i++) {
        const guest = await freshGuest(ctx, boardId, `keyguest${i}`);
        const r = await admit(ctx, guest);
        if (!r.landed) return verdict([{ ok: false, line: `setup: own guest ${i} of ${C42_OWN_GUESTS}, ${guest.evm}: ${r.steps}` }]);
        setup.push({ ok: true, line: `setup: own guest ${i} ${guest.evm}: ${r.steps}` });
      }
      found = await keyTarget(ctx, boardId, ourGuests(ctx));
      if (found === undefined) return notRun(`after admitting ${C42_OWN_GUESTS} guest of its own, no guest this run admitted is on the board besides its oldest`);
    } else {
      const { ok, balance } = await ctx.affordable(FILL_COST_EACH);
      if (!ok) return notRun(`would cost ${formatQor(FILL_COST_EACH)} QOR; the wallet holds ${formatQor(balance)} QOR`);
    }
    const { target, byAge } = found;
    const oldest = byAge[0]!;
    const already = await keyProblems(await boardAt(ctx.client, boardId), byAge);
    if (already.size > 0) return notRun(`guest ${[...already].join(", ")} already shows a key problem, so a pass would take the oldest such guest first, whoever withdraws a key now`);
    const withdrawn = await removeKem(target);
    const judge = await freshGuest(ctx, boardId, "judge2");
    const before = await boardAt(ctx.client, boardId);
    const r = await admit(ctx, judge);
    const after = await boardAt(ctx.client, boardId);
    const removed = r.pass?.removed ?? [];
    const has = (who: Hex): boolean => after.members.some((m) => sameAccount(m, who));
    return verdict([
      ...setup,
      { ok: true, line: `${target.evm}, not the oldest guest, withdrew its ML-KEM key in ${withdrawn.hash}; qor_getKEMKey then found none` },
      { ok: r.landed && r.full === undefined, line: `a fresh judge ${judge.evm} joins at ${before.members.length} members: ${r.landed && r.full === undefined ? `202 ${r.txHash}, landed` : r.steps}` },
      { ok: r.pass?.reached === true && removed.length === 1 && sameAccount(removed[0]!, target.evm), line: `with no request from the suite, the background pass the judge's admission started ${r.pass === undefined ? "WAS NOT SEEN" : passLine(r.pass)}` },
      { ok: !has(target.evm), line: `${target.evm} (no key) ${has(target.evm) ? "IS STILL A MEMBER" : "was removed"}` },
      { ok: has(oldest), line: `the oldest guest ${oldest} ${has(oldest) ? "stays" : "WAS REMOVED"}` },
      { ok: has(judge.evm), line: `the judge ${has(judge.evm) ? "is a member" : "IS NOT A MEMBER"}; the board holds ${after.members.length}` },
    ]);
  },
};

export const attacks: readonly Attack[] = [otherBytes, challengeSurvives, replay, once, perIp, sealed, noKem, noKemGuest, sharedKem, drill, badKey];
/** Runs before any other attack joins the demo board, so a board an older server left full meets C41 first. */
export const seatAttacks: readonly Attack[] = [full];
