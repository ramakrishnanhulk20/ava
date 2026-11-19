import {
  BOARD_TAG,
  Mode,
  accountBytes,
  accountBytesStrict,
  actionMessage,
  decryptDocument,
  encryptDocument,
  newEpochKey,
  openEpochKey,
  paramsAdd,
  paramsCreate,
  paramsPost,
  paramsRemove,
  paramsRotate,
  paramsTransfer,
  sameAccount,
  sameHash,
  sha256,
  signAction,
  verifyAction,
} from "@ava/core";
import { fetchKemKey as fetchKemKeyRest, isRegisteredPqcKey } from "@qorechain/sdk";
import { bytesToHex, decodeFunctionData, hexToBytes, type Hex } from "viem";
import { GAS_CEILING } from "../../packages/server/src/config.ts";
import { COST, FILL_COST_EACH, notRun, verdict, type Attack, type Probe, type Result } from "../lib/attack.ts";
import { ethCall, formatQor, pqcStatus, readKeyStatus, refusalOf, registryEvents } from "../lib/chain.ts";
import type { Ctx } from "../lib/context.ts";
import { PROBE, REGISTRY, REST } from "../lib/guard.ts";
import { FILL_RANGE, ROLES, type Person } from "../lib/identities.ts";
import { isOurProvenKey, kemOf, standingOf } from "../lib/people.ts";
import { Action, ZERO_SIGNATURE, abi, boardAt, calldata, createNonceOf, flipByte, grantsOf, random32, sealTo, sign } from "../lib/registry.ts";

const ONE_UQOR_WEI = 10n ** 12n;
const ENVELOPE_CAP = 110_000;
const CIPHER_CAP = 26_214_400n;
const RESERVED_PREFIXES = [
  "qorechain-pqc-hybrid-v2",
  "qorechain-pqc-pop-v1|",
  "qorechain-pqc-rotate-v1|",
  "qorechain:pqc:recovery:v1",
  "qorechain-siwq-v1|",
  "qorechain-msg-v1|",
  "qorechain-svm-auth-v2",
];

const shown = (names: readonly string[]): string => names.map((n) => (n === "" ? "a revert with no data" : n)).join(" or ");

/** eth_call of one exact transaction; refused only with one of `expected` ("" is a revert carrying no data). */
async function refused(ctx: Ctx, label: string, data: Hex, expected: readonly string[], opts: { value?: bigint; from?: Hex; to?: Hex } = {}): Promise<Probe> {
  const outcome = await ethCall(ctx.client, { from: opts.from ?? ctx.wallet.evm, to: opts.to ?? REGISTRY, data, ...(opts.value === undefined ? {} : { value: opts.value }) });
  const r = refusalOf(outcome);
  return { ok: !outcome.ok && expected.includes(r.name), line: `${label}: ${r.text} (wanted ${shown(expected)})` };
}

/** eth_call that must pass, so a refusal next to it is the attack's doing and not a broken setup. */
async function passes(ctx: Ctx, label: string, data: Hex): Promise<Probe> {
  const outcome = await ethCall(ctx.client, { from: ctx.wallet.evm, to: REGISTRY, data });
  return { ok: outcome.ok, line: `control ${label}: ${outcome.ok ? "passes" : refusalOf(outcome).text}` };
}

const fact = (ok: boolean, line: string): Probe => ({ ok, line });

/** The name of whatever an attempt threw (QoreSeal errors by code), or undefined when it went through. */
async function thrown(attempt: () => unknown): Promise<string | undefined> {
  try {
    await attempt();
    return undefined;
  } catch (err) {
    if (err instanceof Error && err.name === "QoreSealError") return String((err as { code?: unknown }).code);
    return err instanceof Error ? err.name : String(err);
  }
}

const sameBytes = (a: Uint8Array | undefined, b: Uint8Array | undefined): boolean => a !== undefined && b !== undefined && Buffer.from(a).equals(Buffer.from(b));

async function signedPost(ctx: Ctx, board: bigint, opts: { deadline?: bigint } = {}): Promise<{ args: Parameters<typeof calldata.postDocument>[0]; paramsHash: Hex; nonce: bigint }> {
  const b = await boardAt(ctx.client, board);
  const docRef = random32();
  const cipherHash = random32();
  const cipherSize = 4_096n;
  const deadline = opts.deadline ?? (await ctx.deadline());
  const paramsHash = paramsPost({ docRef, cipherHash, cipherSize, epoch: b.epoch });
  const signature = sign(ctx.wallet, { action: Action.POST, boardId: board, paramsHash, nonce: b.nonce, deadline });
  return { args: { boardId: board, docRef, cipherHash, cipherSize, epoch: b.epoch, deadline, signature }, paramsHash, nonce: b.nonce };
}

/** A non-chair member of the board, read from the chain. */
async function memberOf(ctx: Ctx, board: bigint): Promise<Hex> {
  const b = await boardAt(ctx.client, board);
  const m = b.members.find((x) => !sameAccount(x, b.chair));
  if (m === undefined) throw new Error(`Board ${board} has no member besides its chair; the setup did not finish.`);
  return m;
}


const c3: Attack = {
  id: "C3-tag",
  claim: "No app signature can be anything else: the deployed registry builds every message under a tag whose first byte is 0x20, never 'q', and the shared signer refuses bytes that start with any QoreChain reserved prefix.",
  costUqor: 0n,
  async run(ctx) {
    const tag = await ctx.client.readContract({ address: REGISTRY, abi, functionName: "DOMAIN_TAG" });
    const deadline = await ctx.deadline();
    const message = await ctx.client.readContract({ address: REGISTRY, abi, functionName: "actionMessage", args: [Action.ADD, 1n, random32(), 5n, deadline] });
    const probes: Probe[] = [
      fact(sameHash(tag, BOARD_TAG) && hexToBytes(tag)[0] === 0x20, `DOMAIN_TAG() is ${tag}, equal to @ava/core's BOARD_TAG, first byte 0x${hexToBytes(tag)[0]!.toString(16)}`),
      fact(message.length === 2 + 512 && message.slice(0, 66).toLowerCase() === tag.toLowerCase(), `actionMessage() on chain is ${(message.length - 2) / 2} bytes and starts with the tag`),
    ];
    for (const prefix of RESERVED_PREFIXES) {
      for (const size of [256, 224]) {
        const bytes = new Uint8Array(size);
        bytes.set(new TextEncoder().encode(prefix));
        const name = await thrown(() => signAction(ctx.wallet.pqc.secretKey, bytes));
        probes.push(fact(name === "ActionError", `signAction over ${size} bytes starting "${prefix}": ${name ?? "SIGNED"}`));
      }
    }
    return verdict(probes);
  },
};

const c4: Attack = {
  id: "C4-same-bytes",
  claim: "The browser and the contract sign and verify the same bytes: the deployed registry's actionMessage and every params hash equal @ava/core's, byte for byte, for the same inputs.",
  costUqor: 0n,
  async run(ctx) {
    const deadline = await ctx.deadline();
    const ph = random32();
    const [h, ref, member] = [random32(), random32(), ctx.wallet.evm];
    const onChain = await ctx.client.readContract({ address: REGISTRY, abi, functionName: "actionMessage", args: [Action.POST, 7n, ph, 11n, deadline] });
    const local = bytesToHex(actionMessage({ registry: REGISTRY, action: Action.POST, boardId: 7n, paramsHash: ph, nonce: 11n, deadline }));
    const pairs: [string, Hex, Hex][] = [
      ["actionMessage", onChain, local],
      ["paramsCreate", await ctx.client.readContract({ address: REGISTRY, abi, functionName: "paramsCreate", args: [member, ref, h, 1234] }), paramsCreate({ chair: member, boardRef: ref, envelopeHash: h, envelopeSize: 1234 })],
      ["paramsAdd", await ctx.client.readContract({ address: REGISTRY, abi, functionName: "paramsAdd", args: [member, Mode.SEAL_CURRENT, h, 1234, 9n] }), paramsAdd({ member, mode: Mode.SEAL_CURRENT, envelopeHash: h, envelopeSize: 1234, epochAfter: 9n })],
      ["paramsRemove", await ctx.client.readContract({ address: REGISTRY, abi, functionName: "paramsRemove", args: [member, h, 1234, 9n] }), paramsRemove({ member, envelopeHash: h, envelopeSize: 1234, epochAfter: 9n })],
      ["paramsRotate", await ctx.client.readContract({ address: REGISTRY, abi, functionName: "paramsRotate", args: [h, 1234, 9n] }), paramsRotate({ envelopeHash: h, envelopeSize: 1234, epochAfter: 9n })],
      ["paramsPost", await ctx.client.readContract({ address: REGISTRY, abi, functionName: "paramsPost", args: [ref, h, 4096n, 9n] }), paramsPost({ docRef: ref, cipherHash: h, cipherSize: 4096n, epoch: 9n })],
      ["paramsTransfer", await ctx.client.readContract({ address: REGISTRY, abi, functionName: "paramsTransfer", args: [member] }), paramsTransfer({ newChair: member })],
    ];
    return verdict(pairs.map(([name, a, b]) => fact(Buffer.from(hexToBytes(a)).equals(Buffer.from(hexToBytes(b))), `${name}: chain and @ava/core ${Buffer.from(hexToBytes(a)).equals(Buffer.from(hexToBytes(b))) ? "agree" : "DIFFER"} (${(a.length - 2) / 2} bytes)`)));
  },
};

const c16: Attack = {
  id: "C16-one-account",
  claim: "One account, one form: Dana's qor1 and 0x forms are one 20-byte account, pqcKeyStatus (0x) and the REST key record (qor1) hold her one ML-DSA key, both KEM routes give her one ML-KEM key, and the request decoder refuses her address in lowercase.",
  costUqor: 0n,
  needs: ["dana"],
  async run(ctx) {
    const dana = await ctx.need("dana");
    const [precompile, rest, kemEvm, kemRest] = await Promise.all([
      readKeyStatus(ctx.client, dana.evm),
      pqcStatus(dana.qor1),
      kemOf(dana.evm),
      fetchKemKeyRest({ rest: REST, address: dana.qor1 }),
    ]);
    const lower = dana.evm.toLowerCase();
    const strict = await thrown(() => accountBytesStrict(lower));
    return verdict([
      fact(Buffer.from(accountBytes(dana.qor1)).equals(Buffer.from(accountBytes(dana.evm))), `${dana.qor1} and ${dana.evm} decode to the same 20 bytes`),
      fact(sameBytes(precompile.pubkey, dana.pqc.publicKey) && precompile.possessionProven && precompile.algorithmId === 1, "pqcKeyStatus(0x) returns her 2,592-byte key, algorithm 1, possession proven"),
      fact(isRegisteredPqcKey(rest, dana.pqc.publicKey) === true && rest.possessionProven === true, "REST /qorechain/pqc/v1/account(qor1) holds the same key, possession proven"),
      fact(sameBytes(kemEvm, dana.seal.mlkemPublicKey) && kemRest.found && sameBytes(kemRest.key?.publicKey, dana.seal.mlkemPublicKey), "qor_getKEMKey(0x) and REST KEM (qor1) return the same 1,568-byte ML-KEM key"),
      fact(strict === "AddressError" && Buffer.from(accountBytes(lower)).equals(Buffer.from(accountBytes(dana.qor1))), `accountBytesStrict("${lower.slice(0, 10)}...") refuses: ${strict ?? "ACCEPTED"}; the lenient chain-side decoder reads it as the same account`),
    ]);
  },
};

const c1NonChair: Attack = {
  id: "C1-non-chair",
  claim: "Only the chair's key can change a board: Dana's valid ML-DSA-87 signature over an addMember for board B, which the wallet chairs, is refused, while the chair's own signature over the same bytes passes.",
  costUqor: 0n,
  needs: ["boards", "dana"],
  async run(ctx) {
    const { b: board } = await ctx.boards();
    const dana = await ctx.need("dana");
    const b = await boardAt(ctx.client, board);
    const epochAfter = b.epoch + 1n;
    const envelope = await sealTo([...b.members, dana.evm], b.boardRef, epochAfter, newEpochKey());
    const envelopeHash = ctx.blobs.put(envelope);
    const deadline = await ctx.deadline();
    const paramsHash = paramsAdd({ member: dana.evm, mode: Mode.ROTATE, envelopeHash, envelopeSize: envelope.length, epochAfter });
    const message = actionMessage({ registry: REGISTRY, action: Action.ADD, boardId: board, paramsHash, nonce: b.nonce, deadline });
    const danaSig = bytesToHex(signAction(dana.pqc.secretKey, message));
    const args = { boardId: board, member: dana.evm, mode: Mode.ROTATE, envelopeHash, envelopeSize: envelope.length, epochAfter, deadline };
    return verdict([
      fact(verifyAction(dana.pqc.publicKey, message, hexToBytes(danaSig)), "setup: Dana's signature verifies under her own registered key"),
      await passes(ctx, "the chair's own signature over the same message", calldata.addMember({ ...args, signature: sign(ctx.wallet, { action: Action.ADD, boardId: board, paramsHash, nonce: b.nonce, deadline }) })),
      await refused(ctx, `Dana signs as chair of board ${board}`, calldata.addMember({ ...args, signature: danaSig }), ["BadSignature"]),
    ]);
  },
};

const c1NoSignature: Attack = {
  id: "C1-no-signature",
  claim: "msg.sender grants nothing: each of the six board-changing functions, sent by the chair's own account with an empty signature and every other check passing, is refused.",
  costUqor: 0n,
  needs: ["boards", "dana"],
  async run(ctx) {
    const { a, b } = await ctx.boards();
    const dana = await ctx.need("dana");
    const [sa, sb] = await Promise.all([boardAt(ctx.client, a), boardAt(ctx.client, b)]);
    const member = await memberOf(ctx, a);
    const deadline = await ctx.deadline();
    const h = random32();
    const none: Hex = "0x";
    const want = ["BadSignature"];
    return verdict([
      await refused(ctx, "createBoard", calldata.createBoard({ chair: ctx.wallet.evm, boardRef: random32(), envelopeHash: h, envelopeSize: 1000, deadline, signature: none }), want),
      await refused(ctx, "addMember", calldata.addMember({ boardId: b, member: dana.evm, mode: Mode.ROTATE, envelopeHash: h, envelopeSize: 1000, epochAfter: sb.epoch + 1n, deadline, signature: none }), want),
      await refused(ctx, "removeMember", calldata.removeMember({ boardId: a, member, envelopeHash: h, envelopeSize: 1000, epochAfter: sa.epoch + 1n, deadline, signature: none }), want),
      await refused(ctx, "rotateEpoch", calldata.rotateEpoch({ boardId: a, envelopeHash: h, envelopeSize: 1000, epochAfter: sa.epoch + 1n, deadline, signature: none }), want),
      await refused(ctx, "postDocument", calldata.postDocument({ boardId: a, docRef: random32(), cipherHash: h, cipherSize: 1000n, epoch: sa.epoch, deadline, signature: none }), want),
      await refused(ctx, "transferChair", calldata.transferChair({ boardId: a, newChair: member, deadline, signature: none }), want),
    ]);
  },
};

const c1Unproven: Attack = {
  id: "C1-unproven-key",
  claim: "A key without a proof of possession authorises nothing: a test identity registers its ML-DSA-87 key with no proof (the SDK allows it; a chain that refuses it holds the line one layer down), then neither creates a board with its own valid signature nor can be added as a member.",
  costUqor: ROLES.nopop.profile.fundUqor + COST.sendAlone,
  costNote: "nothing when an earlier run already registered the identity",
  needs: ["boards"],
  async run(ctx) {
    const { b: board } = await ctx.boards();
    const nopop = await ctx.people.role("nopop");
    try {
      await ctx.people.ensureAll([{ person: nopop, profile: ROLES.nopop.profile }]);
    } catch (err) {
      const text = err instanceof Error ? err.message : String(err);
      if (/Refused before inclusion|failed on chain/.test(text)) return { held: true, evidence: `the chain refused an ML-DSA-87 registration without a proof of possession: ${text.slice(0, 200)}` };
      throw err;
    }
    const st = await readKeyStatus(ctx.client, nopop.evm);
    if (!st.registered || st.possessionProven) return notRun(`pqcKeyStatus(${nopop.evm}) says registered ${st.registered}, possessionProven ${st.possessionProven}; the unproven key this attack needs does not exist`);
    const deadline = await ctx.deadline();
    const ref = random32();
    const h = random32();
    const nonce = await createNonceOf(ctx.client, nopop.evm);
    const own = sign(nopop, { action: Action.CREATE, boardId: 0n, paramsHash: paramsCreate({ chair: nopop.evm, boardRef: ref, envelopeHash: h, envelopeSize: 1000 }), nonce, deadline });
    const b = await boardAt(ctx.client, board);
    const addParams = { member: nopop.evm, mode: Mode.ROTATE, envelopeHash: h, envelopeSize: 1000, epochAfter: b.epoch + 1n };
    const chairSig = sign(ctx.wallet, { action: Action.ADD, boardId: board, paramsHash: paramsAdd(addParams), nonce: b.nonce, deadline });
    return verdict([
      fact(true, `pqcKeyStatus(${nopop.evm}): registered true, algorithm ${st.algorithmId}, ${st.pubkey.length} bytes, possessionProven false`),
      await refused(ctx, "createBoard with that identity as chair, signed by its own key", calldata.createBoard({ chair: nopop.evm, boardRef: ref, envelopeHash: h, envelopeSize: 1000, deadline, signature: own }), ["PossessionNotProven"]),
      await refused(ctx, `the chair adds it to board ${board}`, calldata.addMember({ boardId: board, ...addParams, deadline, signature: chairSig }), ["PossessionNotProven"]),
    ]);
  },
};

const c2CrossBoard: Attack = {
  id: "C2-cross-board",
  claim: "A signature authorises one action in one place: the chair's landed addMember signature for board A, submitted for board B at the same nonce and epoch so only the board id differs, is refused.",
  costUqor: 0n,
  needs: ["boards"],
  async run(ctx) {
    const tb = await ctx.boards();
    const sb = await boardAt(ctx.client, tb.b);
    if (sb.epoch !== 0n || sb.nonce !== 0n) throw new Error(`Board B is at epoch ${sb.epoch}, nonce ${sb.nonce}; this attack needs it untouched.`);
    return verdict([await refused(ctx, `board A's landed addMember (${tb.addDana.hash}) aimed at board ${tb.b}`, calldata.addMember({ ...tb.addDana.args, boardId: tb.b }), ["BadSignature"])]);
  },
};

const c2CrossAction: Attack = {
  id: "C2-cross-action",
  claim: "A signature authorises one action: the chair's signed rotateEpoch, submitted as a removeMember carrying the same envelope, size and epoch, is refused, while the rotation itself passes.",
  costUqor: 0n,
  needs: ["boards"],
  async run(ctx) {
    const { a } = await ctx.boards();
    const s = await boardAt(ctx.client, a);
    const member = await memberOf(ctx, a);
    const deadline = await ctx.deadline();
    const h = random32();
    const p = { envelopeHash: h, envelopeSize: 1000, epochAfter: s.epoch + 1n };
    const signature = sign(ctx.wallet, { action: Action.ROTATE, boardId: a, paramsHash: paramsRotate(p), nonce: s.nonce, deadline });
    return verdict([
      await passes(ctx, "the signed rotateEpoch", calldata.rotateEpoch({ boardId: a, ...p, deadline, signature })),
      await refused(ctx, "the same signature as removeMember", calldata.removeMember({ boardId: a, member, ...p, deadline, signature }), ["BadSignature"]),
    ]);
  },
};

const c2Params: Attack = {
  id: "C2-params",
  claim: "The signature covers every parameter: a chair-signed postDocument passes, and changing its docRef, cipher hash, size, deadline or one byte of the signature is refused each time.",
  costUqor: 0n,
  needs: ["boards"],
  async run(ctx) {
    const { a } = await ctx.boards();
    const { args } = await signedPost(ctx, a);
    return verdict([
      await passes(ctx, "the signed postDocument", calldata.postDocument(args)),
      await refused(ctx, "another docRef", calldata.postDocument({ ...args, docRef: random32() }), ["BadSignature"]),
      await refused(ctx, "another cipher hash", calldata.postDocument({ ...args, cipherHash: random32() }), ["BadSignature"]),
      await refused(ctx, "size plus one", calldata.postDocument({ ...args, cipherSize: args.cipherSize + 1n }), ["BadSignature"]),
      await refused(ctx, "deadline plus one second", calldata.postDocument({ ...args, deadline: args.deadline + 1n }), ["BadSignature"]),
      await refused(ctx, "signature byte 100 flipped", calldata.postDocument({ ...args, signature: flipByte(args.signature, 100) }), ["BadSignature"]),
    ]);
  },
};

const c2Expired: Attack = {
  id: "C2-expired",
  claim: "A signature does not outlive its deadline: a postDocument the chair signed with a deadline 60 seconds before the latest block is refused.",
  costUqor: 0n,
  needs: ["boards"],
  async run(ctx) {
    const { a } = await ctx.boards();
    const block = await ctx.client.getBlock({ blockTag: "latest" });
    const { args } = await signedPost(ctx, a, { deadline: block.timestamp - 60n });
    return verdict([await refused(ctx, `deadline ${args.deadline}, latest block ${block.timestamp}`, calldata.postDocument(args), ["DeadlineExpired"])]);
  },
};

const c2Far: Attack = {
  id: "C2-far-deadline",
  claim: "No signature is valid for more than an hour: a postDocument the chair signed with a deadline 3,720 seconds after the latest block is refused.",
  costUqor: 0n,
  needs: ["boards"],
  async run(ctx) {
    const { a } = await ctx.boards();
    const block = await ctx.client.getBlock({ blockTag: "latest" });
    const { args } = await signedPost(ctx, a, { deadline: block.timestamp + 3_720n });
    return verdict([await refused(ctx, `deadline ${args.deadline}, latest block ${block.timestamp}`, calldata.postDocument(args), ["DeadlineTooFar"])]);
  },
};

const c7RemoveChair: Attack = {
  id: "C7-remove-chair",
  claim: "The chair is always a member: a removeMember of the chair, signed by the chair, is refused.",
  costUqor: 0n,
  needs: ["boards"],
  async run(ctx) {
    const { a } = await ctx.boards();
    const s = await boardAt(ctx.client, a);
    const deadline = await ctx.deadline();
    const p = { member: ctx.wallet.evm, envelopeHash: random32(), envelopeSize: 1000, epochAfter: s.epoch + 1n };
    const signature = sign(ctx.wallet, { action: Action.REMOVE, boardId: a, paramsHash: paramsRemove(p), nonce: s.nonce, deadline });
    return verdict([await refused(ctx, "the chair removes itself", calldata.removeMember({ boardId: a, ...p, deadline, signature }), ["ChairCannotLeave"])]);
  },
};

const c7AddExisting: Attack = {
  id: "C7-add-existing",
  claim: "Members are unique: a chair-signed addMember of Dana, already a member of board A, is refused.",
  costUqor: 0n,
  needs: ["boards", "dana"],
  async run(ctx) {
    const { a } = await ctx.boards();
    const dana = await ctx.need("dana");
    const s = await boardAt(ctx.client, a);
    const deadline = await ctx.deadline();
    const p = { member: dana.evm, mode: Mode.SEAL_CURRENT, envelopeHash: random32(), envelopeSize: 1000, epochAfter: s.epoch };
    const signature = sign(ctx.wallet, { action: Action.ADD, boardId: a, paramsHash: paramsAdd(p), nonce: s.nonce, deadline });
    return verdict([await refused(ctx, "Dana added a second time", calldata.addMember({ boardId: a, ...p, deadline, signature }), ["AlreadyMember"])]);
  },
};

const c7TransferOutside: Attack = {
  id: "C7-transfer-non-member",
  claim: "The chair can only pass to a current member: a chair-signed transferChair to an address that is not on the board is refused.",
  costUqor: 0n,
  needs: ["boards"],
  async run(ctx) {
    const { a } = await ctx.boards();
    const stranger = await ctx.people.role("stranger");
    const s = await boardAt(ctx.client, a);
    const deadline = await ctx.deadline();
    const signature = sign(ctx.wallet, { action: Action.TRANSFER, boardId: a, paramsHash: paramsTransfer({ newChair: stranger.evm }), nonce: s.nonce, deadline });
    return verdict([await refused(ctx, `transferChair to ${stranger.evm}`, calldata.transferChair({ boardId: a, newChair: stranger.evm, deadline, signature }), ["NotMember"])]);
  },
};

const c8: Attack = {
  id: "C8-oversize",
  claim: "Storage is bounded: an envelope size of 110,001 or 0 bytes, a cipher size of 25 MiB plus one or 0, and a 4,628-byte signature are each refused before anything is stored.",
  costUqor: 0n,
  needs: ["boards", "dana"],
  async run(ctx) {
    const { a, b } = await ctx.boards();
    const dana = await ctx.need("dana");
    const [sa, sb] = await Promise.all([boardAt(ctx.client, a), boardAt(ctx.client, b)]);
    const member = await memberOf(ctx, a);
    const deadline = await ctx.deadline();
    const h = random32();
    const big = ENVELOPE_CAP + 1;
    const env = ["BadEnvelopeSize"];
    const longSig: Hex = `${ZERO_SIGNATURE}00`;
    return verdict([
      await refused(ctx, `createBoard, envelope ${big} bytes`, calldata.createBoard({ chair: ctx.wallet.evm, boardRef: random32(), envelopeHash: h, envelopeSize: big, deadline, signature: ZERO_SIGNATURE }), env),
      await refused(ctx, "createBoard, envelope 0 bytes", calldata.createBoard({ chair: ctx.wallet.evm, boardRef: random32(), envelopeHash: h, envelopeSize: 0, deadline, signature: ZERO_SIGNATURE }), env),
      await refused(ctx, `addMember, envelope ${big} bytes`, calldata.addMember({ boardId: b, member: dana.evm, mode: Mode.ROTATE, envelopeHash: h, envelopeSize: big, epochAfter: sb.epoch + 1n, deadline, signature: ZERO_SIGNATURE }), env),
      await refused(ctx, "addMember, envelope 4,294,967,295 bytes", calldata.addMember({ boardId: b, member: dana.evm, mode: Mode.ROTATE, envelopeHash: h, envelopeSize: 4_294_967_295, epochAfter: sb.epoch + 1n, deadline, signature: ZERO_SIGNATURE }), env),
      await refused(ctx, `removeMember, envelope ${big} bytes`, calldata.removeMember({ boardId: a, member, envelopeHash: h, envelopeSize: big, epochAfter: sa.epoch + 1n, deadline, signature: ZERO_SIGNATURE }), env),
      await refused(ctx, `rotateEpoch, envelope ${big} bytes`, calldata.rotateEpoch({ boardId: a, envelopeHash: h, envelopeSize: big, epochAfter: sa.epoch + 1n, deadline, signature: ZERO_SIGNATURE }), env),
      await refused(ctx, `postDocument, cipher ${CIPHER_CAP + 1n} bytes`, calldata.postDocument({ boardId: a, docRef: random32(), cipherHash: h, cipherSize: CIPHER_CAP + 1n, epoch: sa.epoch, deadline, signature: ZERO_SIGNATURE }), ["BadCipherSize"]),
      await refused(ctx, "postDocument, cipher 0 bytes", calldata.postDocument({ boardId: a, docRef: random32(), cipherHash: h, cipherSize: 0n, epoch: sa.epoch, deadline, signature: ZERO_SIGNATURE }), ["BadCipherSize"]),
      await refused(ctx, "postDocument, a 4,628-byte signature", calldata.postDocument({ boardId: a, docRef: random32(), cipherHash: h, cipherSize: 1000n, epoch: sa.epoch, deadline, signature: longSig }), ["BadSignature"]),
    ]);
  },
};

const c10: Attack = {
  id: "C10-value",
  claim: "There is nothing to drain: every registry write carrying 1 uqor, a plain transfer to either contract, and a call to a function neither has, all revert.",
  costUqor: 0n,
  needs: ["boards", "dana"],
  async run(ctx) {
    const { a, b } = await ctx.boards();
    const dana = await ctx.need("dana");
    const [sa, sb] = await Promise.all([boardAt(ctx.client, a), boardAt(ctx.client, b)]);
    const member = await memberOf(ctx, a);
    const deadline = await ctx.deadline();
    const h = random32();
    const v = { value: ONE_UQOR_WEI };
    const none = [""];
    return verdict([
      await refused(ctx, "createBoard with 1 uqor", calldata.createBoard({ chair: ctx.wallet.evm, boardRef: random32(), envelopeHash: h, envelopeSize: 1000, deadline, signature: ZERO_SIGNATURE }), none, v),
      await refused(ctx, "addMember with 1 uqor", calldata.addMember({ boardId: b, member: dana.evm, mode: Mode.ROTATE, envelopeHash: h, envelopeSize: 1000, epochAfter: sb.epoch + 1n, deadline, signature: ZERO_SIGNATURE }), none, v),
      await refused(ctx, "removeMember with 1 uqor", calldata.removeMember({ boardId: a, member, envelopeHash: h, envelopeSize: 1000, epochAfter: sa.epoch + 1n, deadline, signature: ZERO_SIGNATURE }), none, v),
      await refused(ctx, "rotateEpoch with 1 uqor", calldata.rotateEpoch({ boardId: a, envelopeHash: h, envelopeSize: 1000, epochAfter: sa.epoch + 1n, deadline, signature: ZERO_SIGNATURE }), none, v),
      await refused(ctx, "postDocument with 1 uqor", calldata.postDocument({ boardId: a, docRef: random32(), cipherHash: h, cipherSize: 1000n, epoch: sa.epoch, deadline, signature: ZERO_SIGNATURE }), none, v),
      await refused(ctx, "transferChair with 1 uqor", calldata.transferChair({ boardId: a, newChair: member, deadline, signature: ZERO_SIGNATURE }), none, v),
      await refused(ctx, "plain 1 uqor transfer to the registry", "0x", none, v),
      await refused(ctx, "unknown selector 0xdeadbeef to the registry", "0xdeadbeef", none),
      await refused(ctx, "plain 1 uqor transfer to the PqcProbe", "0x", none, { ...v, to: PROBE }),
      await refused(ctx, "unknown selector 0xdeadbeef to the PqcProbe", "0xdeadbeef", none, { to: PROBE }),
    ]);
  },
};

const c12: Attack = {
  id: "C12-tamper",
  claim: "Nothing is used until its hash matches the chain: board A's real epoch 0 envelope opens with the chair's keys, and the same bytes with one byte changed are refused before any key touches them.",
  costUqor: 0n,
  needs: ["boards"],
  async run(ctx) {
    const tb = await ctx.boards();
    const s = await boardAt(ctx.client, tb.a);
    const grant = (await grantsOf(ctx.client, tb.a, 0n))[0];
    if (grant === undefined) throw new Error("Board A has no epoch 0 grant.");
    const bytes = ctx.blobs.get(grant.envelopeHash);
    const open = (envelope: Uint8Array) =>
      openEpochKey({ registry: REGISTRY, boardRef: s.boardRef, epoch: 0n, envelope, expectedHash: grant.envelopeHash, expectedSize: grant.envelopeSize, sealKeys: ctx.wallet.seal });
    const key = open(bytes);
    const tampered = Uint8Array.from(bytes);
    tampered[100] = tampered[100]! ^ 0x01;
    const name = await thrown(() => open(tampered));
    return verdict([
      fact(sameBytes(key, tb.keys.get(`${tb.a}:0`)), "control: the recorded envelope opens to the epoch 0 key"),
      fact(name === "HashMismatch", `byte 100 flipped: ${name ?? "OPENED"}`),
    ]);
  },
};

const c13: Attack = {
  id: "C13-move",
  claim: "Every ciphertext is bound to its place: board A's envelope opened as board B's or as another epoch, and a document encrypted for A decrypted as B's, as another document or as another epoch, all fail.",
  costUqor: 0n,
  needs: ["boards"],
  async run(ctx) {
    const tb = await ctx.boards();
    const [sa, sb] = await Promise.all([boardAt(ctx.client, tb.a), boardAt(ctx.client, tb.b)]);
    const grant = (await grantsOf(ctx.client, tb.a, 0n))[0];
    const k0 = tb.keys.get(`${tb.a}:0`);
    if (grant === undefined || k0 === undefined) throw new Error("Board A's epoch 0 record is missing.");
    const envelope = ctx.blobs.get(grant.envelopeHash);
    const openAs = (boardRef: Hex, epoch: bigint) =>
      thrown(() => openEpochKey({ registry: REGISTRY, boardRef, epoch, envelope, expectedHash: grant.envelopeHash, expectedSize: grant.envelopeSize, sealKeys: ctx.wallet.seal }));
    const plaintext = globalThis.crypto.getRandomValues(new Uint8Array(300));
    const docRef = random32();
    const cipher = await encryptDocument({ epochKey: k0, registry: REGISTRY, boardRef: sa.boardRef, epoch: 0n, docRef, plaintext });
    const expected = { expectedHash: bytesToHex(sha256(cipher)), expectedSize: cipher.length };
    const decryptAs = (boardRef: Hex, epoch: bigint, ref: Hex) => thrown(() => decryptDocument({ epochKey: k0, registry: REGISTRY, boardRef, epoch, docRef: ref, ciphertext: cipher, ...expected }));
    const back = await decryptDocument({ epochKey: k0, registry: REGISTRY, boardRef: sa.boardRef, epoch: 0n, docRef, ciphertext: cipher, ...expected });
    const asB = await openAs(sb.boardRef, 0n);
    const asE1 = await openAs(sa.boardRef, 1n);
    const dB = await decryptAs(sb.boardRef, 0n, docRef);
    const dRef = await decryptAs(sa.boardRef, 0n, random32());
    const dEpoch = await decryptAs(sa.boardRef, 1n, docRef);
    return verdict([
      fact(sameBytes(back, plaintext), "control: the document decrypts in its own place"),
      fact(asB === "DECRYPTION_FAILED", `A's envelope opened as board B's: ${asB ?? "OPENED"}`),
      fact(asE1 === "DECRYPTION_FAILED", `A's epoch 0 envelope opened as epoch 1: ${asE1 ?? "OPENED"}`),
      fact(dB === "DocumentError", `A's document decrypted as B's: ${dB ?? "DECRYPTED"}`),
      fact(dRef === "DocumentError", `as another docRef: ${dRef ?? "DECRYPTED"}`),
      fact(dEpoch === "DocumentError", `as epoch 1: ${dEpoch ?? "DECRYPTED"}`),
    ]);
  },
};

const c5: Attack = {
  id: "C5-old-epoch",
  claim: "A document always lands under the current epoch: a postDocument the chair signs for the current epoch, held back while Eli's removal lands, is refused afterwards.",
  costUqor: COST.remove,
  needs: ["boards", "eli"],
  async run(ctx): Promise<Result> {
    const tb = await ctx.boards();
    const eli = await ctx.need("eli");
    const s = await boardAt(ctx.client, tb.a);
    if (!s.members.some((m) => sameAccount(m, eli.evm))) throw new Error("Eli is not on board A; the setup did not finish.");
    const { args: stale } = await signedPost(ctx, tb.a);
    const before = await passes(ctx, `a postDocument signed for epoch ${s.epoch} at nonce ${s.nonce}`, calldata.postDocument(stale));
    const remaining = s.members.filter((m) => !sameAccount(m, eli.evm));
    const epochAfter = s.epoch + 1n;
    const key = newEpochKey();
    const envelope = await sealTo(remaining, s.boardRef, epochAfter, key);
    const envelopeHash = ctx.blobs.put(envelope);
    const deadline = await ctx.deadline();
    const p = { member: eli.evm, envelopeHash, envelopeSize: envelope.length, epochAfter };
    const signature = sign(ctx.wallet, { action: Action.REMOVE, boardId: tb.a, paramsHash: paramsRemove(p), nonce: s.nonce, deadline });
    const sent = await ctx.lane.write(calldata.removeMember({ boardId: tb.a, ...p, deadline, signature }));
    tb.keys.set(`${tb.a}:${epochAfter}`, key);
    ctx.state.removal = { hash: sent.hash };
    const after = await boardAt(ctx.client, tb.a);
    return verdict([
      before,
      fact(after.epoch === epochAfter, `Eli's removal landed in ${sent.hash} (${sent.receipt.gasUsed} gas); board A moved from epoch ${s.epoch} to ${after.epoch}`),
      await refused(ctx, "the held-back postDocument now", calldata.postDocument(stale), ["WrongEpoch"]),
    ]);
  },
};

const c2Replay: Attack = {
  id: "C2-replay",
  claim: "One signature, one action, once: the landed createBoard and the landed removal replayed byte for byte are refused, and the removal's signature re-aimed at the board as it is now, so every check before the signature passes, is refused too.",
  costUqor: 0n,
  needs: ["boards"],
  async run(ctx) {
    const tb = await ctx.boards();
    const removal = ctx.state.removal;
    if (removal === undefined) return notRun("C5-old-epoch landed no removal to replay");
    const createTx = await ctx.client.getTransaction({ hash: tb.aCreateHash });
    const removeTx = await ctx.client.getTransaction({ hash: removal.hash });
    const decoded = decodeFunctionData({ abi, data: removeTx.input });
    if (decoded.functionName !== "removeMember") throw new Error(`${removal.hash} is not a removeMember.`);
    const [, , envelopeHash, envelopeSize, , deadline, signature] = decoded.args;
    const now = await boardAt(ctx.client, tb.a);
    const member = await memberOf(ctx, tb.a);
    return verdict([
      await refused(ctx, `createBoard ${tb.aCreateHash} replayed`, createTx.input, ["BoardRefUsed", "BadSignature"]),
      await refused(ctx, `removeMember ${removal.hash} replayed`, removeTx.input, ["NotMember", "WrongEpoch", "BadSignature"]),
      await refused(
        ctx,
        `its signature aimed at removing ${member} at epoch ${now.epoch + 1n}, board nonce ${now.nonce}`,
        calldata.removeMember({ boardId: tb.a, member, envelopeHash, envelopeSize, epochAfter: now.epoch + 1n, deadline, signature }),
        ["BadSignature"],
      ),
    ]);
  },
};

/** Seal-current add of `person` to board A under its current epoch key. */
async function sealCurrentAdd(ctx: Ctx, person: Person): Promise<{ hash: Hex; envelopeHash: Hex; envelopeSize: number; epoch: bigint; nonce: bigint; events: ReturnType<typeof registryEvents> }> {
  const tb = await ctx.boards();
  const s = await boardAt(ctx.client, tb.a);
  const key = tb.keys.get(`${tb.a}:${s.epoch}`);
  if (key === undefined) throw new Error(`No key kept for board A epoch ${s.epoch}.`);
  const envelope = await sealTo([person.evm], s.boardRef, s.epoch, key);
  const envelopeHash = ctx.blobs.put(envelope);
  const deadline = await ctx.deadline();
  const p = { member: person.evm, mode: Mode.SEAL_CURRENT, envelopeHash, envelopeSize: envelope.length, epochAfter: s.epoch };
  const signature = sign(ctx.wallet, { action: Action.ADD, boardId: tb.a, paramsHash: paramsAdd(p), nonce: s.nonce, deadline });
  const sent = await ctx.lane.write(calldata.addMember({ boardId: tb.a, ...p, deadline, signature }));
  return { hash: sent.hash, envelopeHash, envelopeSize: envelope.length, epoch: s.epoch, nonce: s.nonce, events: registryEvents(sent.receipt) };
}

const sameGrant = (x: { envelopeHash: Hex; envelopeSize: number; mode: number; member: Hex }, y: typeof x): boolean =>
  sameHash(x.envelopeHash, y.envelopeHash) && x.envelopeSize === y.envelopeSize && x.mode === y.mode && sameAccount(x.member, y.member);

const c6: Attack = {
  id: "C6-append",
  claim: "History is append-only: a second MODE_SEAL_CURRENT grant in one epoch is appended after the first, which stays exactly as it was, and its events carry member, epoch, envelope hash, mode and nonce.",
  costUqor: 2n * COST.addSeal,
  needs: ["boards", "fay", "eli"],
  async run(ctx) {
    const tb = await ctx.boards();
    const fay = await ctx.need("fay");
    const eli = await ctx.need("eli");
    const first = await sealCurrentAdd(ctx, fay);
    const mid = await grantsOf(ctx.client, tb.a, first.epoch);
    const second = await sealCurrentAdd(ctx, eli);
    const after = await grantsOf(ctx.client, tb.a, first.epoch);
    const last = after.at(-1);
    const added = second.events.find((e) => e.eventName === "MemberAdded")?.args;
    const granted = second.events.find((e) => e.eventName === "EnvelopeGranted")?.args;
    const eventsOk =
      added !== undefined &&
      granted !== undefined &&
      sameAccount(String(added.member), eli.evm) &&
      added.epoch === first.epoch &&
      Number(added.mode) === Mode.SEAL_CURRENT &&
      added.nonce === second.nonce &&
      sameHash(String(granted.envelopeHash) as Hex, second.envelopeHash) &&
      Number(granted.envelopeSize) === second.envelopeSize &&
      sameAccount(String(granted.member), eli.evm) &&
      granted.nonce === second.nonce;
    return verdict([
      fact(true, `Fay added by MODE_SEAL_CURRENT in ${first.hash}, Eli in ${second.hash}, both under epoch ${first.epoch}`),
      fact(after.length === mid.length + 1 && mid.every((g, i) => sameGrant(g, after[i]!)), `getGrants(A, ${first.epoch}) went from ${mid.length} to ${after.length} entries, every earlier entry unchanged`),
      fact(last !== undefined && sameHash(last.envelopeHash, second.envelopeHash) && last.mode === Mode.SEAL_CURRENT && sameAccount(last.member, eli.evm), "the new entry is Eli's grant, appended last"),
      fact(eventsOk, "MemberAdded and EnvelopeGranted name Eli, the epoch, the envelope hash and size, the mode and the nonce"),
    ]);
  },
};

const c17: Attack = {
  id: "C17-concurrent",
  claim: "A rotation is sealed to exactly the members the registry holds once it lands: two removals of different members signed from the same view and sent back to back, the second reverts on chain, and the removed member cannot open the new epoch's envelope.",
  costUqor: COST.remove + COST.reverted,
  needs: ["boards", "fay"],
  async run(ctx) {
    const tb = await ctx.boards();
    const s = await boardAt(ctx.client, tb.a);
    const others = s.members.filter((m) => !sameAccount(m, s.chair));
    const [x, y] = others;
    if (x === undefined || y === undefined) throw new Error("Board A needs two members besides its chair; the setup did not finish.");
    const people = await Promise.all([ROLES.dana, ROLES.eli, ROLES.fay].map((r, i) => ctx.people.derive(r.index, ["dana", "eli", "fay"][i]!)));
    const personFor = (a: Hex): Person => {
      const p = people.find((q) => sameAccount(q.evm, a));
      if (p === undefined) throw new Error(`${a} is not one of this suite's identities.`);
      return p;
    };
    const epochAfter = s.epoch + 1n;
    const deadline = await ctx.deadline();
    const build = async (member: Hex) => {
      const envelope = await sealTo(s.members.filter((m) => !sameAccount(m, member)), s.boardRef, epochAfter, newEpochKey());
      const envelopeHash = ctx.blobs.put(envelope);
      const p = { member, envelopeHash, envelopeSize: envelope.length, epochAfter };
      const signature = sign(ctx.wallet, { action: Action.REMOVE, boardId: tb.a, paramsHash: paramsRemove(p), nonce: s.nonce, deadline });
      return { data: calldata.removeMember({ boardId: tb.a, ...p, deadline, signature }), envelopeHash, envelopeSize: envelope.length };
    };
    const rx = await build(x);
    const ry = await build(y);
    const controls = [await passes(ctx, `removing ${x} alone`, rx.data), await passes(ctx, `removing ${y} alone`, ry.data)];
    const [sx, sy] = await ctx.lane.writePair(rx.data, ry.data, GAS_CEILING.remove);
    const after = await boardAt(ctx.client, tb.a);
    const grants = await grantsOf(ctx.client, tb.a, epochAfter);
    const open = (r: { envelopeHash: Hex; envelopeSize: number }, who: Person) =>
      thrown(() =>
        openEpochKey({ registry: REGISTRY, boardRef: s.boardRef, epoch: epochAfter, envelope: ctx.blobs.get(r.envelopeHash), expectedHash: r.envelopeHash, expectedSize: r.envelopeSize, sealKeys: who.seal }),
      );
    const removedOpens = await open(rx, personFor(x));
    const stayerOpens = await open(rx, personFor(y));
    // The stale removal's envelope was sealed from the old member list, so it still names x.
    const staleNamesRemoved = await open(ry, personFor(x));
    return verdict([
      ...controls,
      fact(sx.receipt.status === "success", `first removal ${sx.hash}: ${sx.receipt.status}`),
      fact(sy.receipt.status === "reverted", `second removal ${sy.hash}, same nonce ${s.nonce}: ${sy.receipt.status} on chain`),
      await refused(ctx, "the second removal's calldata now", ry.data, ["WrongEpoch", "BadSignature"]),
      fact(after.epoch === epochAfter && !after.members.some((m) => sameAccount(m, x)) && after.members.some((m) => sameAccount(m, y)), `board A is at epoch ${after.epoch}, ${x} gone, ${y} still a member`),
      fact(grants.length === 1 && sameHash(grants[0]!.envelopeHash, rx.envelopeHash), `getGrants(A, ${epochAfter}) holds only the first removal's envelope`),
      fact(removedOpens === "NOT_A_RECIPIENT", `the removed member opens the new epoch's envelope: ${removedOpens ?? "OPENED"}`),
      fact(stayerOpens === undefined, `control: the member who stays opens it: ${stayerOpens ?? "opened"}`),
      fact(staleNamesRemoved === undefined, `what was averted: the reverted removal's envelope still opens for the removed member (${staleNamesRemoved ?? "opened"}), and it never reached the chain`),
    ]);
  },
};

const FILL_WRITES = BigInt(FILL_RANGE.count);
const C7_WRITES_COST = COST.create + FILL_WRITES * COST.addSeal + 2n * COST.windowOpen;
const C7_FULL_COST = FILL_WRITES * FILL_COST_EACH + C7_WRITES_COST;

const c7Full: Attack = {
  id: "C7-exceed-64",
  claim: "A board never holds more than 64 members: a board filled to 64 by 63 real, possession-proven identities refuses a 65th.",
  costUqor: C7_FULL_COST,
  costNote: "63 identities at 0.23 QOR each, shared with C41, plus 64 writes; runs only if the wallet holds it, else reports not run",
  needs: ["dana"],
  async run(ctx) {
    // The fill identities are registered in index order, so when the last one holds both keys an
    // earlier run made them all and only the writes cost anything now.
    const last = (await ctx.people.fill(FILL_RANGE.count)).at(-1)!;
    const lastStanding = await standingOf(last);
    const made = isOurProvenKey(lastStanding.pqc, last) && lastStanding.kem !== undefined;
    const cost = made ? C7_WRITES_COST : C7_FULL_COST;
    const { ok, balance } = await ctx.affordable(cost);
    if (!ok) return notRun(`would cost ${formatQor(cost)} QOR; the wallet holds ${formatQor(balance)} QOR`);
    const dana = await ctx.need("dana");
    const fill = await ctx.people.ensureFill(FILL_RANGE.count);
    const { id: x } = await ctx.createBoard("X");
    const h = random32();
    for (const [i, person] of fill.entries()) {
      // Two windows of up to 40 for the 63 writes, the count the cost estimate assumes.
      if (i % 40 === 0) await ctx.lane.ensureWindow(Math.min(40, fill.length - i));
      const s = await boardAt(ctx.client, x);
      const deadline = await ctx.deadline();
      const p = { member: person.evm, mode: Mode.SEAL_CURRENT, envelopeHash: h, envelopeSize: 1000, epochAfter: s.epoch };
      const signature = sign(ctx.wallet, { action: Action.ADD, boardId: x, paramsHash: paramsAdd(p), nonce: s.nonce, deadline });
      await ctx.lane.write(calldata.addMember({ boardId: x, ...p, deadline, signature }));
      if ((i + 1) % 10 === 0) ctx.log(`  board X: ${i + 2} members`);
    }
    const s = await boardAt(ctx.client, x);
    const cap = await ctx.client.readContract({ address: REGISTRY, abi, functionName: "MAX_MEMBERS" });
    const deadline = await ctx.deadline();
    const p = { member: dana.evm, mode: Mode.SEAL_CURRENT, envelopeHash: h, envelopeSize: 1000, epochAfter: s.epoch };
    const signature = sign(ctx.wallet, { action: Action.ADD, boardId: x, paramsHash: paramsAdd(p), nonce: s.nonce, deadline });
    return verdict([
      fact(s.members.length === 64 && cap === 64n, `board ${x} holds ${s.members.length} members; MAX_MEMBERS() is ${cap}`),
      await refused(ctx, "a 65th member, chair-signed", calldata.addMember({ boardId: x, ...p, deadline, signature }), ["BoardFull"]),
    ]);
  },
};

/** In the order they run: reads first, then eth_call probes, then the writes whose effect is the point. */
export const attacks: readonly Attack[] = [
  c3,
  c4,
  c16,
  c1NonChair,
  c1NoSignature,
  c1Unproven,
  c2CrossBoard,
  c2CrossAction,
  c2Params,
  c2Expired,
  c2Far,
  c7RemoveChair,
  c7AddExisting,
  c7TransferOutside,
  c8,
  c10,
  c12,
  c13,
  c5,
  c2Replay,
  c6,
  c17,
  c7Full,
];
