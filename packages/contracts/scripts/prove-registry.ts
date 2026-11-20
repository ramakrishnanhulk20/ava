import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  Action,
  CHAIN_ID as CORE_CHAIN_ID,
  EVM_CHAIN_ID as CORE_EVM_CHAIN_ID,
  MAX_DEADLINE_AHEAD,
  Mode,
  actionMessage,
  deadlineFrom,
  decryptDocument,
  encryptDocument,
  newBoardRef,
  newDocRef,
  newEpochKey,
  openEpochKey,
  paramsAdd,
  paramsCreate,
  paramsPost,
  paramsRemove,
  sameAccount,
  sameHash,
  sealEpochKey,
  sha256,
  signAction,
  verifyAction,
  type FreshEpochKey,
  type OpenedEpochKey,
} from "@ava/core";
import { classifyEvmWindowRejection } from "@qorechain/evm";
import { parseEnvelope, recipientHint } from "@qorechain/qoreseal";
import { fetchEvmWindow, withRetry } from "@qorechain/sdk";
import { BaseError, bytesToHex, decodeFunctionData, encodeFunctionData, hexToBytes, keccak256, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { deriveDeployer, type Deployer } from "./account.js";
import { assertTestnet, evmClient } from "./chain.js";
import { CHAIN_ID, EVM_CHAIN_ID, REST, requireMnemonic } from "./env.js";
import { BudgetError, DEPLOYER_FLOOR_UQOR, balanceOf, fees, formatQor, withHeadroom } from "./lib/evm.js";
import { ensureIdentity, kemRecipientOf, precompileKeyStatus, restShowsProvenKey } from "./lib/identities.js";
import {
  boardAt,
  callFromDeployer,
  createNonceAt,
  describeRefusal,
  documentOf,
  grantsOf,
  loadRegistryArtifact,
  recordedRegistry,
  relayWrite,
  sameMembers,
  type Grant,
  type Registry,
  type RegistryArtifact,
  type RegistryRecord,
  type WriteResult,
} from "./lib/registry.js";

const REPORT_DIR = new URL("../deployments/", import.meta.url);
// Two real files of this repository stand in for board papers.
const DOC1_URL = new URL("../../../docs/spec/actions.md", import.meta.url);
const DOC2_URL = new URL("../../../docs/security/threat-model.md", import.meta.url);
const DEADLINE_SECONDS = 600;
// 3a, 3b, Dana, Eli, document 1, the removal, document 2.
const WRITES_PER_RUN = 7;

class CheckFailed extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CheckFailed";
  }
}

interface StepOutcome {
  n: string;
  title: string;
  ok: boolean;
  reason?: string;
}

interface People {
  chair: Deployer;
  dana: Deployer;
  eli: Deployer;
}

function need<T>(value: T | undefined, what: string): T {
  if (value === undefined) throw new Error(`${what} is missing: an earlier step did not finish.`);
  return value;
}

const sameBytes = (a: Uint8Array, b: Uint8Array): boolean => Buffer.from(a).equals(Buffer.from(b));

interface Board {
  id: bigint;
  boardRef: Hex;
  create: WriteResult;
}

interface Write {
  label: string;
  result: WriteResult;
}

/** Everything one run knows. Fields fill in as the steps land; a later step asks for them with need(). */
class Proof {
  readonly lines: string[] = [];
  readonly outcomes: StepOutcome[] = [];
  readonly writes: Write[] = [];
  // Stands in for the public blob store: bytes are found only by the SHA-256 the chain records.
  private readonly blobs = new Map<string, Uint8Array>();
  people?: People;
  board1?: Board;
  board2?: Board;
  addDana?: { write: WriteResult; args: readonly unknown[] };
  doc1?: Posted;
  doc2?: Posted;
  stalePost?: readonly unknown[];
  remove?: WriteResult;
  fundingUqor = 0n;

  constructor(
    readonly reg: Registry,
    readonly record: RegistryRecord,
    readonly artifact: RegistryArtifact,
  ) {}

  log = (line: string): void => {
    console.log(line);
    this.lines.push(line);
  };

  check(ok: boolean, what: string): void {
    if (!ok) throw new CheckFailed(`check failed: ${what}`);
    this.log(`  check:    ${what}: yes`);
  }

  put(bytes: Uint8Array): Hex {
    const hash = bytesToHex(sha256(bytes));
    this.blobs.set(hash, Uint8Array.from(bytes));
    return hash;
  }

  blob(onChainHash: Hex): Uint8Array {
    return Uint8Array.from(need(this.blobs.get(onChainHash.toLowerCase()), `the blob for ${onChainHash}`));
  }

  /** The exact 256 bytes from @ava/core, signed with the person's registered ML-DSA-87 key. */
  sign(person: Deployer, a: { action: Action; boardId: bigint; paramsHash: Hex; nonce: bigint; deadline: bigint }): Hex {
    return bytesToHex(signAction(person.pqc.secretKey, actionMessage({ registry: this.reg.address, ...a })));
  }

  /** Seals an epoch key to each address as the pair qor_getKEMKey returns for that address (C15). */
  async sealTo(addresses: readonly Hex[], boardRef: Hex, epoch: bigint, epochKey: FreshEpochKey | OpenedEpochKey): Promise<Uint8Array> {
    const recipients = [];
    for (const address of addresses) recipients.push(await kemRecipientOf(address));
    return sealEpochKey({ registry: this.reg.address, boardRef, epoch, epochKey, recipients });
  }

  async relay(label: string, functionName: string, args: readonly unknown[]): Promise<WriteResult> {
    const result = await relayWrite(this.reg, functionName, args, this.log);
    this.writes.push({ label, result });
    return result;
  }
}

const isZeroAddress = (a: string): boolean => /^0x0{40}$/i.test(a);
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const ONE_UQOR_WEI = 10n ** 12n;

async function chainAndRegistry(p: Proof): Promise<void> {
  const chainId = await assertTestnet();
  p.check(chainId === CHAIN_ID && CHAIN_ID === CORE_CHAIN_ID, `the consensus RPC serves ${chainId}, the chain @ava/core seals for`);
  const evmChainId = await p.reg.client.getChainId();
  p.check(evmChainId === EVM_CHAIN_ID && EVM_CHAIN_ID === CORE_EVM_CHAIN_ID, `eth_chainId is ${evmChainId}, the chain id @ava/core signs into every message`);
  const code = await p.reg.client.getCode({ address: p.reg.address });
  const hash = code === undefined ? "no code" : keccak256(code);
  p.log(`  registry: ${p.reg.address}, deployed in ${p.record.deployTx} at block ${p.record.blockNumber}`);
  p.check(hash === p.record.runtimeCodeHash, `the registry's runtime code hashes to ${hash}, the hash recorded at deploy`);
  p.check(keccak256(p.artifact.deployedBytecode) === p.record.runtimeCodeHash, "the current build's runtime code hashes the same, so this script speaks the deployed ABI");
}

async function identities(p: Proof): Promise<void> {
  const setups = [];
  for (const role of ["chair", "dana", "eli"] as const) setups.push(await ensureIdentity(role, p.reg.deployer, p.log));
  for (const s of setups) p.fundingUqor += s.fundingSpentUqor;
  const accounts = [p.reg.deployer, ...setups.map((s) => s.account)];
  p.check(accounts.every((a, i) => accounts.every((b, j) => i === j || !sameAccount(a.qor1, b.qor1))), "the deployer, the chair, Dana and Eli are four different accounts");
  for (const { role, account: a } of setups) {
    p.log(`  ${role}: ${a.qor1} / ${a.evm} (one 20-byte account on both lanes, coin type 60)`);
    p.check(await restShowsProvenKey(a), `${role}: PQ key found over REST, this phrase's ML-DSA-87 key, possession_proven true`);
    const st = await precompileKeyStatus(p.reg.client, a.evm);
    p.check(
      st.registered && st.algorithmId === 1 && st.possessionProven && st.pubkey.length === 2592 && sameBytes(st.pubkey, a.pqc.publicKey),
      `${role}: pqcKeyStatus(${a.evm}), the precompile the registry reads, says registered, algorithm 1, possessionProven, 2,592-byte key equal to this phrase's`,
    );
    const kem = await kemRecipientOf(a.evm);
    p.check(
      sameAccount(kem.address, a.evm) && sameBytes(kem.kemPublicKey, a.seal.mlkemPublicKey),
      `${role}: KEM key found via qor_getKEMKey(${a.evm}): algorithm 2, 1,568 bytes, account matched as 20 bytes, this phrase's key`,
    );
  }
  const [chair, dana, eli] = setups.map((s) => s.account) as [Deployer, Deployer, Deployer];
  p.people = { chair, dana, eli };
}

async function createOneBoard(p: Proof, part: string): Promise<Board> {
  const { chair } = need(p.people, "the identities");
  const boardRef = bytesToHex(newBoardRef());
  const envelope = await p.sealTo([chair.evm], boardRef, 0n, newEpochKey());
  const envelopeHash = p.put(envelope);
  const at = await createNonceAt(p.reg, chair.evm);
  const deadline = deadlineFrom(at.timestamp, DEADLINE_SECONDS);
  const paramsHash = paramsCreate({ chair: chair.evm, boardRef, envelopeHash, envelopeSize: envelope.length });
  const signature = p.sign(chair, { action: Action.CREATE, boardId: 0n, paramsHash, nonce: at.nonce, deadline });
  p.log(`  ${part} board: boardRef ${boardRef} from newBoardRef; a fresh epoch 0 key sealed to the chair only (${envelope.length}-byte envelope, sha256 ${envelopeHash})`);
  p.log(`  signed:   CREATE by the chair's ML-DSA-87 key over createNonce ${at.nonce} read at block ${at.blockNumber}, deadline that block's time + ${DEADLINE_SECONDS} s`);

  const create = await p.relay(`createBoard (${part})`, "createBoard", [chair.evm, boardRef, envelopeHash, envelope.length, deadline, signature]);
  const id = create.events.find((e) => e.eventName === "BoardCreated")?.args.boardId;
  if (typeof id !== "bigint") throw new CheckFailed("check failed: the createBoard receipt carries a BoardCreated event");
  const b = await boardAt(p.reg, id);
  const after = await createNonceAt(p.reg, chair.evm);
  const grants = await grantsOf(p.reg, id, 0n);
  p.log(`  getBoard(${id}): chair ${b.chair}, boardRef ${b.boardRef}, epoch ${b.epoch}, nonce ${b.nonce}, members ${b.memberCount}, documents ${b.documentCount}`);
  p.check(
    sameAccount(b.chair, chair.evm) && sameHash(b.boardRef, boardRef) && b.epoch === 0n && b.nonce === 0n && b.memberCount === 1 && b.documentCount === 0 && sameMembers(b.members, [chair.evm]),
    `board ${id} holds the chair, this boardRef, epoch 0 and board nonce 0 (the next action signs nonce 0), with the chair its only member`,
  );
  p.check(after.nonce === at.nonce + 1n, `the chair's createNonce moved from ${at.nonce} to ${after.nonce}`);
  p.check(
    grants.length === 1 && sameHash(grants[0]!.envelopeHash, envelopeHash) && grants[0]!.envelopeSize === envelope.length && grants[0]!.mode === Mode.ROTATE && isZeroAddress(grants[0]!.member),
    `getGrants(${id}, 0) is one MODE_ROTATE grant with this envelope's sha256 and size`,
  );
  return { id, boardRef, create };
}

async function createBoards(p: Proof): Promise<void> {
  p.board1 = await createOneBoard(p, "3a");
  p.board2 = await createOneBoard(p, "3b");
  p.log(`  board ${p.board2.id} exists only so attack 7e has a second board of the same chair`);
}

/**
 * A person opens the envelope that names them for one epoch: the MODE_SEAL_CURRENT grant sealed
 * to them, or else the epoch's MODE_ROTATE grant. openEpochKey refuses the bytes unless their size
 * and SHA-256 are the ones the registry recorded (C12).
 */
async function openFor(p: Proof, person: Deployer, boardId: bigint, boardRef: Hex, epoch: bigint): Promise<{ key: OpenedEpochKey; index: number; grant: Grant }> {
  const grants = await grantsOf(p.reg, boardId, epoch);
  let index = grants.findIndex((g) => g.mode === Mode.SEAL_CURRENT && sameAccount(g.member, person.evm));
  if (index < 0) index = grants.findIndex((g) => g.mode === Mode.ROTATE);
  const grant = need(grants[index], `a grant for epoch ${epoch} of board ${boardId}`);
  const key = openEpochKey({
    registry: p.reg.address,
    boardRef,
    epoch,
    envelope: p.blob(grant.envelopeHash),
    expectedHash: grant.envelopeHash,
    expectedSize: grant.envelopeSize,
    sealKeys: person.seal,
  });
  return { key, index, grant };
}

const eventNames = (w: WriteResult): string => w.events.map((e) => e.eventName).join(", ");

async function addMembers(p: Proof): Promise<void> {
  const { chair, dana, eli } = need(p.people, "the identities");
  const board = need(p.board1, "board 1");

  const b0 = await boardAt(p.reg, board.id);
  const epoch1 = b0.epoch + 1n;
  const danaEnvelope = await p.sealTo([...b0.members, dana.evm], b0.boardRef, epoch1, newEpochKey());
  const danaHash = p.put(danaEnvelope);
  const danaDeadline = deadlineFrom(b0.timestamp, DEADLINE_SECONDS);
  const danaParams = paramsAdd({ member: dana.evm, mode: Mode.ROTATE, envelopeHash: danaHash, envelopeSize: danaEnvelope.length, epochAfter: epoch1 });
  const danaSig = p.sign(chair, { action: Action.ADD, boardId: board.id, paramsHash: danaParams, nonce: b0.nonce, deadline: danaDeadline });
  p.log(`  4a Dana, MODE_ROTATE. Read at block ${b0.blockNumber}: epoch ${b0.epoch}, nonce ${b0.nonce}, members ${b0.members.join(", ")}`);
  p.log(`  sealed:   a fresh epoch ${epoch1} key to the chair and Dana (${danaEnvelope.length}-byte envelope, 2 recipients); Dana is named by her 0x form ${dana.evm}`);
  const danaArgs = [board.id, dana.evm, Mode.ROTATE, danaHash, danaEnvelope.length, epoch1, danaDeadline, danaSig] as const;
  const addDana = await p.relay("addMember MODE_ROTATE", "addMember", danaArgs);
  p.addDana = { write: addDana, args: danaArgs };
  const b1 = await boardAt(p.reg, board.id);
  p.check(eventNames(addDana) === "MemberAdded, EpochRotated, EnvelopeGranted", "the receipt carries MemberAdded, EpochRotated, EnvelopeGranted");
  p.check(b1.epoch === epoch1 && b1.nonce === b0.nonce + 1n && sameMembers(b1.members, [chair.evm, dana.evm]), `board ${board.id} is at epoch ${b1.epoch} and nonce ${b1.nonce}, members the chair and Dana`);

  const b2 = await boardAt(p.reg, board.id);
  const current = await openFor(p, chair, board.id, b2.boardRef, b2.epoch);
  const eliEnvelope = await p.sealTo([eli.evm], b2.boardRef, b2.epoch, current.key);
  const eliHash = p.put(eliEnvelope);
  const eliDeadline = deadlineFrom(b2.timestamp, DEADLINE_SECONDS);
  const eliParams = paramsAdd({ member: eli.evm, mode: Mode.SEAL_CURRENT, envelopeHash: eliHash, envelopeSize: eliEnvelope.length, epochAfter: b2.epoch });
  const eliSig = p.sign(chair, { action: Action.ADD, boardId: board.id, paramsHash: eliParams, nonce: b2.nonce, deadline: eliDeadline });
  p.log(`  4b Eli, MODE_SEAL_CURRENT. Read at block ${b2.blockNumber}: epoch ${b2.epoch}, nonce ${b2.nonce}`);
  p.log(`  sealed:   the chair opened the epoch ${b2.epoch} key from grant ${current.index} (sha256 and size match the chain), then sealed it to Eli alone (${eliEnvelope.length}-byte envelope, 1 recipient)`);
  const addEli = await p.relay("addMember MODE_SEAL_CURRENT", "addMember", [board.id, eli.evm, Mode.SEAL_CURRENT, eliHash, eliEnvelope.length, b2.epoch, eliDeadline, eliSig]);
  const b3 = await boardAt(p.reg, board.id);
  const grants = await grantsOf(p.reg, board.id, epoch1);
  p.check(eventNames(addEli) === "MemberAdded, EnvelopeGranted", "the receipt carries MemberAdded, EnvelopeGranted and no EpochRotated");
  p.check(b3.epoch === b2.epoch && b3.nonce === b2.nonce + 1n && sameMembers(b3.members, [chair.evm, dana.evm, eli.evm]), `board ${board.id} stays at epoch ${b3.epoch}, nonce ${b3.nonce}, members the chair, Dana and Eli`);
  p.check(
    grants.length === 2 &&
      grants[0]!.mode === Mode.ROTATE && sameHash(grants[0]!.envelopeHash, danaHash) && isZeroAddress(grants[0]!.member) &&
      grants[1]!.mode === Mode.SEAL_CURRENT && sameHash(grants[1]!.envelopeHash, eliHash) && grants[1]!.envelopeSize === eliEnvelope.length && sameAccount(grants[1]!.member, eli.evm),
    `getGrants(${board.id}, ${epoch1}) lists Dana's MODE_ROTATE grant unchanged, then Eli's MODE_SEAL_CURRENT grant appended after it`,
  );
}

interface Posted {
  docId: bigint;
  name: string;
  plaintext: Uint8Array;
  write: WriteResult;
}

/** The name of whatever an attempt threw, or undefined when it went through. */
async function refusal(attempt: () => unknown): Promise<string | undefined> {
  try {
    await attempt();
    return undefined;
  } catch (err) {
    // @ava/core imports its own copy of QoreSeal, so its errors are matched by name and code, not instanceof.
    if (err instanceof Error && err.name === "QoreSealError") return String((err as { code?: unknown }).code);
    return err instanceof Error ? err.name : String(err);
  }
}

function flipByte(bytes: Uint8Array, at: number): Uint8Array {
  const copy = Uint8Array.from(bytes);
  copy[at] = copy[at]! ^ 0x01;
  return copy;
}

async function postDoc(p: Proof, doc: string, name: string, plaintext: Uint8Array): Promise<Posted> {
  const { chair } = need(p.people, "the identities");
  const board = need(p.board1, "board 1");
  const b = await boardAt(p.reg, board.id);
  const opened = await openFor(p, chair, board.id, b.boardRef, b.epoch);
  const docRef = bytesToHex(newDocRef());
  const ciphertext = await encryptDocument({ epochKey: opened.key, registry: p.reg.address, boardRef: b.boardRef, epoch: b.epoch, docRef, plaintext });
  const cipherHash = p.put(ciphertext);
  const deadline = deadlineFrom(b.timestamp, DEADLINE_SECONDS);
  const paramsHash = paramsPost({ docRef, cipherHash, cipherSize: ciphertext.length, epoch: b.epoch });
  const signature = p.sign(chair, { action: Action.POST, boardId: board.id, paramsHash, nonce: b.nonce, deadline });
  p.log(`  post ${doc}: ${name} (${plaintext.length} bytes) encrypted with encryptDocument under the epoch ${b.epoch} key, which the chair opened from grant ${opened.index}`);
  p.log(`            the chain gets only its sha256 ${cipherHash} and size ${ciphertext.length}; read at block ${b.blockNumber}: epoch ${b.epoch}, nonce ${b.nonce}`);
  const write = await p.relay(`postDocument (${doc})`, "postDocument", [board.id, docRef, cipherHash, BigInt(ciphertext.length), b.epoch, deadline, signature]);
  const docId = write.events.find((e) => e.eventName === "DocumentPosted")?.args.docId;
  if (typeof docId !== "bigint") throw new CheckFailed("check failed: the postDocument receipt carries a DocumentPosted event");
  const d = await documentOf(p.reg, board.id, docId);
  const after = await boardAt(p.reg, board.id);
  p.check(
    sameHash(d.docRef, docRef) && sameHash(d.cipherHash, cipherHash) && d.cipherSize === BigInt(ciphertext.length) && d.epoch === b.epoch && after.documentCount === b.documentCount + 1,
    `getDocument(${board.id}, ${docId}) records this docRef, sha256 and size under epoch ${d.epoch}`,
  );
  return { docId, name, plaintext, write };
}

/** A member reads a document the way a director's browser does: record from chain, key from their own envelope, bytes by hash. */
async function readDoc(p: Proof, person: Deployer, docId: bigint): Promise<{ plaintext: Uint8Array; epoch: bigint; index: number; grant: Grant }> {
  const board = need(p.board1, "board 1");
  const d = await documentOf(p.reg, board.id, docId);
  const b = await boardAt(p.reg, board.id);
  const opened = await openFor(p, person, board.id, b.boardRef, d.epoch);
  const plaintext = await decryptDocument({
    epochKey: opened.key,
    registry: p.reg.address,
    boardRef: b.boardRef,
    epoch: d.epoch,
    docRef: d.docRef,
    ciphertext: p.blob(d.cipherHash),
    expectedHash: d.cipherHash,
    expectedSize: d.cipherSize,
  });
  return { plaintext, epoch: d.epoch, index: opened.index, grant: opened.grant };
}

async function postFirstDocument(p: Proof): Promise<void> {
  const { dana, eli } = need(p.people, "the identities");
  const board = need(p.board1, "board 1");
  p.doc1 = await postDoc(p, "doc 1", "docs/spec/actions.md", readFileSync(fileURLToPath(DOC1_URL)));
  for (const [who, person] of [["Dana", dana], ["Eli", eli]] as const) {
    const read = await readDoc(p, person, p.doc1.docId);
    const how = read.grant.mode === Mode.SEAL_CURRENT ? `the MODE_SEAL_CURRENT grant sealed to ${who}` : "the MODE_ROTATE grant";
    p.log(`  ${`${who}:`.padEnd(10)}opened epoch ${read.epoch} grant ${read.index} (${how}) after its sha256 and size matched the chain, then decrypted document ${p.doc1.docId}`);
    p.check(sameBytes(read.plaintext, p.doc1.plaintext), `${who}'s decrypted bytes equal the original ${p.doc1.plaintext.length} bytes`);
  }

  const b = await boardAt(p.reg, board.id);
  const eliGrant = (await grantsOf(p.reg, board.id, b.epoch)).find((g) => g.mode === Mode.SEAL_CURRENT && sameAccount(g.member, eli.evm));
  const grant = need(eliGrant, "Eli's grant");
  const d = await documentOf(p.reg, board.id, p.doc1.docId);
  const badEnvelope = await refusal(() =>
    openEpochKey({ registry: p.reg.address, boardRef: b.boardRef, epoch: b.epoch, envelope: flipByte(p.blob(grant.envelopeHash), 100), expectedHash: grant.envelopeHash, expectedSize: grant.envelopeSize, sealKeys: eli.seal }),
  );
  const badCipher = await refusal(async () => {
    const { key } = await openFor(p, eli, board.id, b.boardRef, d.epoch);
    return decryptDocument({ epochKey: key, registry: p.reg.address, boardRef: b.boardRef, epoch: d.epoch, docRef: d.docRef, ciphertext: flipByte(p.blob(d.cipherHash), 100), expectedHash: d.cipherHash, expectedSize: d.cipherSize });
  });
  p.log(`  tamper:   Eli's envelope with one byte changed: ${badEnvelope ?? "OPENED"}; document ${p.doc1.docId} with one byte changed: ${badCipher ?? "DECRYPTED"}`);
  p.check(badEnvelope === "HashMismatch" && badCipher === "HashMismatch", "both are refused with HashMismatch before any key touches them");
}

async function removeEli(p: Proof): Promise<void> {
  const { chair, dana, eli } = need(p.people, "the identities");
  const board = need(p.board1, "board 1");
  const doc1 = need(p.doc1, "document 1");
  const b = await boardAt(p.reg, board.id);

  const opened = await openFor(p, chair, board.id, b.boardRef, b.epoch);
  const staleRef = bytesToHex(newDocRef());
  const staleCipher = await encryptDocument({
    epochKey: opened.key,
    registry: p.reg.address,
    boardRef: b.boardRef,
    epoch: b.epoch,
    docRef: staleRef,
    plaintext: new TextEncoder().encode("Signed while epoch 1 was current, then held back until after Eli's removal."),
  });
  const staleHash = p.put(staleCipher);
  const staleDeadline = deadlineFrom(b.timestamp, DEADLINE_SECONDS);
  const staleParams = paramsPost({ docRef: staleRef, cipherHash: staleHash, cipherSize: staleCipher.length, epoch: b.epoch });
  const staleSig = p.sign(chair, { action: Action.POST, boardId: board.id, paramsHash: staleParams, nonce: b.nonce, deadline: staleDeadline });
  p.stalePost = [board.id, staleRef, staleHash, BigInt(staleCipher.length), b.epoch, staleDeadline, staleSig];
  const staleNow = await callFromDeployer(p.reg, encodeFunctionData({ abi: p.reg.abi, functionName: "postDocument", args: p.stalePost }));
  p.check(staleNow.ok, `kept for attack 7d: a postDocument the chair signs now for epoch ${b.epoch} at nonce ${b.nonce}, and eth_call of it passes now`);

  const remaining = b.members.filter((m) => !sameAccount(m, eli.evm));
  const epoch2 = b.epoch + 1n;
  const envelope = await p.sealTo(remaining, b.boardRef, epoch2, newEpochKey());
  const envelopeHash = p.put(envelope);
  const deadline = deadlineFrom(b.timestamp, DEADLINE_SECONDS);
  const paramsHash = paramsRemove({ member: eli.evm, envelopeHash, envelopeSize: envelope.length, epochAfter: epoch2 });
  const signature = p.sign(chair, { action: Action.REMOVE, boardId: board.id, paramsHash, nonce: b.nonce, deadline });
  p.log(`  6a remove Eli. Read at block ${b.blockNumber}: epoch ${b.epoch}, nonce ${b.nonce}, members ${b.members.join(", ")}`);
  p.log(`  sealed:   a fresh epoch ${epoch2} key to the ${remaining.length} members who stay, read from that same block (${envelope.length}-byte envelope)`);
  p.remove = await p.relay("removeMember", "removeMember", [board.id, eli.evm, envelopeHash, envelope.length, epoch2, deadline, signature]);
  const after = await boardAt(p.reg, board.id);
  p.check(eventNames(p.remove) === "MemberRemoved, EpochRotated, EnvelopeGranted", "the receipt carries MemberRemoved, EpochRotated, EnvelopeGranted");
  p.check(after.epoch === epoch2 && after.nonce === b.nonce + 1n && sameMembers(after.members, [chair.evm, dana.evm]), `board ${board.id} is at epoch ${after.epoch} and nonce ${after.nonce}, members the chair and Dana`);

  // Anyone holding the members' public keys can run this count (QoreSeal's recipient hints).
  const parsed = parseEnvelope(envelope);
  const hints = parsed.entries.map((e) => bytesToHex(e.hint));
  const hintFor = async (address: Hex): Promise<Hex> => bytesToHex(recipientHint(parsed.salt, (await kemRecipientOf(address)).kemPublicKey));
  const memberHints: Hex[] = [];
  for (const m of after.members) memberHints.push(await hintFor(m));
  const eliHint = await hintFor(eli.evm);
  p.check(
    parsed.entries.length === after.members.length && memberHints.every((h) => hints.includes(h)) && !hints.includes(eliHint),
    `the epoch ${epoch2} envelope holds ${parsed.entries.length} recipient entries, one for each member the registry holds after the removal (matched by their on-chain ML-KEM keys), and none for Eli`,
  );

  p.doc2 = await postDoc(p, "doc 2", "docs/security/threat-model.md", readFileSync(fileURLToPath(DOC2_URL)));
  const danaRead = await readDoc(p, dana, p.doc2.docId);
  p.log(`  Dana:     opened epoch ${danaRead.epoch} grant ${danaRead.index} after its sha256 and size matched the chain, then decrypted document ${p.doc2.docId}`);
  p.check(sameBytes(danaRead.plaintext, p.doc2.plaintext), `Dana's decrypted bytes equal the original ${p.doc2.plaintext.length} bytes`);

  const eliOpens = await refusal(() => openFor(p, eli, board.id, after.boardRef, epoch2));
  p.log(`  Eli:      tries to open the epoch ${epoch2} envelope with his own keys: ${eliOpens ?? "OPENED"}`);
  p.check(eliOpens === "NOT_A_RECIPIENT", "Eli is refused with NOT_A_RECIPIENT");
  const d1 = await documentOf(p.reg, board.id, doc1.docId);
  const d2 = await documentOf(p.reg, board.id, p.doc2.docId);
  const eliOldKey = await refusal(async () => {
    const { key } = await openFor(p, eli, board.id, after.boardRef, d1.epoch);
    return decryptDocument({ epochKey: key, registry: p.reg.address, boardRef: after.boardRef, epoch: d2.epoch, docRef: d2.docRef, ciphertext: p.blob(d2.cipherHash), expectedHash: d2.cipherHash, expectedSize: d2.cipherSize });
  });
  p.log(`  Eli:      tries document ${p.doc2.docId} with the epoch ${d1.epoch} key he still holds: ${eliOldKey ?? "DECRYPTED"}`);
  p.check(eliOldKey === "DocumentError", `the epoch ${d1.epoch} key does not decrypt an epoch ${d2.epoch} document`);

  const kept = await readDoc(p, eli, doc1.docId);
  p.check(sameBytes(kept.plaintext, doc1.plaintext), `what a removed director keeps: Eli still opens his epoch 1 envelope and decrypts document ${doc1.docId} (${doc1.plaintext.length} bytes, equal to the original)`);
  p.log("            A key already handed out cannot be taken back; the removal closes every document posted from now on.");
}

/** eth_call of one exact attack transaction from the deployer. It must revert with one of `expected` ("" is a revert with no error data). */
async function attack(p: Proof, label: string, what: string, data: Hex, expected: readonly string[], value?: bigint): Promise<void> {
  const outcome = await callFromDeployer(p.reg, data, value);
  p.log(`  ${label}: ${what}`);
  if (outcome.ok) throw new CheckFailed(`check failed: ${label} was not refused; eth_call of it passed`);
  const { name, text } = describeRefusal(p.reg.abi, outcome);
  p.log(`      eth_call: refused, ${text}`);
  p.check(expected.includes(name), `refused with ${expected.map((n) => (n === "" ? "a revert carrying no error data" : n)).join(" or ")}`);
}

/** The node's own words for a refused broadcast. */
function nodeAnswer(err: unknown): string {
  const text = err instanceof BaseError ? (err.details ?? err.shortMessage) : err instanceof Error ? err.message : String(err);
  return text.replace(/\s+/g, " ").slice(0, 700);
}

async function attacks(p: Proof): Promise<void> {
  const { chair, dana } = need(p.people, "the identities");
  const board1 = need(p.board1, "board 1");
  const board2 = need(p.board2, "board 2");
  const addDana = need(p.addDana, "Dana's landed addMember");
  const remove = need(p.remove, "the landed removeMember");
  const stalePost = need(p.stalePost, "the held-back postDocument");
  const { client, abi, address: registry } = p.reg;
  const encode = (functionName: string, args: readonly unknown[]): Hex => encodeFunctionData({ abi, functionName, args });
  p.log("  Attacks a to h are each an eth_call of the exact transaction from the deployer; none is broadcast.");

  const b2 = await boardAt(p.reg, board2.id);
  const aEpoch = b2.epoch + 1n;
  const aEnvelope = await p.sealTo([...b2.members, dana.evm], b2.boardRef, aEpoch, newEpochKey());
  const aHash = p.put(aEnvelope);
  const aDeadline = deadlineFrom(b2.timestamp, DEADLINE_SECONDS);
  const aParams = paramsAdd({ member: dana.evm, mode: Mode.ROTATE, envelopeHash: aHash, envelopeSize: aEnvelope.length, epochAfter: aEpoch });
  const aMessage = actionMessage({ registry, action: Action.ADD, boardId: board2.id, paramsHash: aParams, nonce: b2.nonce, deadline: aDeadline });
  const aSig = signAction(dana.pqc.secretKey, aMessage);
  p.check(verifyAction(dana.pqc.publicKey, aMessage, aSig), "7a setup: Dana's signature is a valid ML-DSA-87 signature under her own registered key");
  await attack(
    p,
    "7a",
    `Dana, not a member of board ${board2.id}, signs an addMember adding herself to it as if she were its chair`,
    encode("addMember", [board2.id, dana.evm, Mode.ROTATE, aHash, aEnvelope.length, aEpoch, aDeadline, bytesToHex(aSig)]),
    ["BadSignature"],
  );

  const createTx = await client.getTransaction({ hash: board1.create.hash });
  p.check(createTx.input.toLowerCase() === board1.create.data.toLowerCase(), `7b setup: the input of ${board1.create.hash} read back from the chain is the createBoard calldata that landed`);
  await attack(p, "7b", `the landed createBoard ${board1.create.hash} replayed byte for byte`, createTx.input, ["BoardRefUsed", "BadSignature"]);

  const removeTx = await client.getTransaction({ hash: remove.hash });
  p.check(removeTx.input.toLowerCase() === remove.data.toLowerCase(), `7c setup: the input of ${remove.hash} read back from the chain is the removeMember calldata that landed`);
  await attack(p, "7c", `the landed removeMember ${remove.hash} replayed byte for byte`, removeTx.input, ["NotMember", "BadSignature"]);
  const removed = decodeFunctionData({ abi, data: removeTx.input });
  const [, , rHash, rSize, , rDeadline, rSig] = removed.args as readonly [bigint, Hex, Hex, number, bigint, bigint, Hex];
  const b1 = await boardAt(p.reg, board1.id);
  await attack(
    p,
    "7c",
    `the same removal signature aimed at the board as it is now (remove Dana, epoch ${b1.epoch + 1n}, board nonce ${b1.nonce}), so every check before the signature passes`,
    encode("removeMember", [board1.id, dana.evm, rHash, rSize, b1.epoch + 1n, rDeadline, rSig]),
    ["BadSignature"],
  );

  await attack(p, "7d", `the postDocument the chair signed for epoch 1 before the removal, submitted now that board ${board1.id} is at epoch ${b1.epoch}`, encode("postDocument", stalePost), ["WrongEpoch"]);

  const b2now = await boardAt(p.reg, board2.id);
  p.check(
    b2now.epoch === 0n && b2now.nonce === 0n,
    `7e setup: board ${board2.id} is at epoch 0 and nonce 0, as board ${board1.id} was when the chair signed Dana's addMember, so only the board id differs`,
  );
  await attack(
    p,
    "7e",
    `the chair's landed addMember signature for board ${board1.id} (${addDana.write.hash}) submitted for board ${board2.id}`,
    encode("addMember", [board2.id, ...addDana.args.slice(1)]),
    ["BadSignature"],
  );

  const now = await boardAt(p.reg, board1.id);
  const opened = await openFor(p, chair, board1.id, now.boardRef, now.epoch);
  const fRef = bytesToHex(newDocRef());
  const fCipher = await encryptDocument({
    epochKey: opened.key,
    registry,
    boardRef: now.boardRef,
    epoch: now.epoch,
    docRef: fRef,
    plaintext: new TextEncoder().encode("A post the chair really signed, used only as the control for attacks f to i."),
  });
  const fHash = p.put(fCipher);
  const fDeadline = deadlineFrom(now.timestamp, DEADLINE_SECONDS);
  const fParams = paramsPost({ docRef: fRef, cipherHash: fHash, cipherSize: fCipher.length, epoch: now.epoch });
  const fSig = p.sign(chair, { action: Action.POST, boardId: board1.id, paramsHash: fParams, nonce: now.nonce, deadline: fDeadline });
  const post = (sig: Hex, deadline: bigint): Hex => encode("postDocument", [board1.id, fRef, fHash, BigInt(fCipher.length), now.epoch, deadline, sig]);
  const control = await callFromDeployer(p.reg, post(fSig, fDeadline));
  p.check(control.ok, `7f control: a fresh postDocument the chair really signed at board nonce ${now.nonce} passes eth_call`);
  await attack(p, "7f", "the same call with one byte of the signature flipped (byte 100)", post(bytesToHex(flipByte(hexToBytes(fSig), 100)), fDeadline), ["BadSignature"]);

  const latest = await client.getBlock({ blockTag: "latest" });
  const gAhead = BigInt(MAX_DEADLINE_AHEAD) + 120n;
  const gDeadline = latest.timestamp + gAhead;
  const gSig = p.sign(chair, { action: Action.POST, boardId: board1.id, paramsHash: fParams, nonce: now.nonce, deadline: gDeadline });
  await attack(p, "7g", `the same post, signed by the chair with a deadline ${gAhead} s after the latest block`, post(gSig, gDeadline), ["DeadlineTooFar"]);

  await attack(p, "7h", "the control post carrying 1 uqor of value", post(fSig, fDeadline), [""], ONE_UQOR_WEI);
  await attack(p, "7h", "a plain transfer of 1 uqor to the registry with no calldata", "0x", [""], ONE_UQOR_WEI);

  const window = await withRetry(() => fetchEvmWindow({ rest: REST, address: chair.qor1 }), { retries: 4, backoff: 2_000 });
  p.check(!window.live, `7i setup: the chair's account ${chair.evm} has no live EVM window (stored window: ${window.found})`);
  const data = post(fSig, fDeadline);
  const gas = withHeadroom(await client.estimateGas({ account: chair.evm, to: registry, data }));
  const fee = await fees(client);
  const nonceBefore = await client.getTransactionCount({ address: chair.evm, blockTag: "pending" });
  const serialized = await privateKeyToAccount(chair.privateKey).signTransaction({ type: "eip1559", chainId: EVM_CHAIN_ID, nonce: nonceBefore, to: registry, data, gas, value: 0n, ...fee });
  const hash = keccak256(serialized);
  p.log(`  7i: the control post, sent as a plain EVM transaction from the chair's own account and signed with its secp256k1 key alone (${hash})`);
  let answer: string | undefined;
  let kind: string | undefined;
  try {
    await client.sendRawTransaction({ serializedTransaction: serialized });
  } catch (err) {
    answer = nodeAnswer(err);
    kind = classifyEvmWindowRejection(err);
  }
  p.log(`      node:     ${answer ?? "ACCEPTED"}`);
  const code = answer === undefined ? undefined : /\bcode\W{0,3}(\d+)\b/.exec(answer)?.[1];
  p.check(
    answer !== undefined && kind === "no-window",
    `refused by the chain before any contract code runs: "no open EVM authorisation window"${code === undefined ? "" : `, the node's code ${code}`}`,
  );
  await sleep(6_000);
  const seen = await client.getTransaction({ hash }).catch(() => undefined);
  const nonceAfter = await client.getTransactionCount({ address: chair.evm, blockTag: "pending" });
  p.check(seen === undefined && nonceAfter === nonceBefore, `the transaction is not on chain and the chair's nonce is still ${nonceAfter}`);
}

const STEPS: { n: string; title: string; run: (p: Proof) => Promise<void> }[] = [
  { n: "1", title: "Chain and registry", run: chainAndRegistry },
  { n: "2", title: "Identities: chair, Dana, Eli", run: identities },
  { n: "3", title: "The chair creates a board (3a), and a second one for attack 7e (3b)", run: createBoards },
  { n: "4", title: "The chair adds Dana (MODE_ROTATE), then Eli (MODE_SEAL_CURRENT)", run: addMembers },
  { n: "5", title: "The chair posts document 1 under epoch 1; Dana and Eli decrypt it", run: postFirstDocument },
  { n: "6", title: "The chair removes Eli and posts document 2 under epoch 2", run: removeEli },
  { n: "7", title: "Attacks, each refused", run: attacks },
];

/**
 * What a whole run needs when the guard stops one: the floor, the stopped write's worst case, and
 * every other write still to come at the average this run measured (or at that worst case when
 * nothing has landed yet).
 */
function runBudget(p: Proof, stop: BudgetError): string {
  const spent = p.writes.reduce((s, w) => s + w.result.window.feeUqor + w.result.evmFeeUqor, 0n);
  const measured = p.writes.length > 0;
  const perWrite = measured ? spent / BigInt(p.writes.length) : stop.maxSpendUqor;
  const after = BigInt(Math.max(WRITES_PER_RUN - p.writes.length - 1, 0));
  const finish = DEPLOYER_FLOOR_UQOR + stop.maxSpendUqor + after * perWrite;
  const fresh = DEPLOYER_FLOOR_UQOR + stop.maxSpendUqor + BigInt(WRITES_PER_RUN - 1) * perWrite;
  const rate = measured
    ? `about ${formatQor(perWrite)} QOR each, window included, as this run measured`
    : `up to ${formatQor(perWrite)} QOR each in the worst case (the window's fee cap plus its max_value), since no write has landed in this run to measure`;
  return (
    `a full run makes ${WRITES_PER_RUN} registry writes, each with its own window, at ${rate}. ` +
    `Finishing this run would need ${measured ? "about" : "at most"} ${formatQor(finish - stop.balanceUqor)} QOR more; ` +
    `a fresh run should start with ${measured ? "about" : "at most"} ${formatQor(fresh)} QOR at ${p.reg.deployer.qor1}.`
  );
}

/** Step 8: every step's outcome, the QOR this run spent, and the live gas of every write. */
async function summary(p: Proof, startBalance: bigint): Promise<void> {
  p.log("\n8. Summary");
  for (const step of STEPS) {
    const o = p.outcomes.find((x) => x.n === step.n);
    p.log(`  ${step.n}. ${(o === undefined ? "not run" : o.ok ? "OK" : "FAILED").padEnd(8)}${step.title}`);
  }
  const failed = p.outcomes.find((o) => !o.ok);
  p.log(failed === undefined ? "  result:   every step OK" : `  result:   first failure at step ${failed.n}: ${failed.reason}`);

  const end = await balanceOf(p.reg.deployer.qor1);
  const windowFees = p.writes.reduce((s, w) => s + w.result.window.feeUqor, 0n);
  const writeFees = p.writes.reduce((s, w) => s + w.result.evmFeeUqor, 0n);
  p.log(`  spent:    ${formatQor(startBalance - end)} QOR realised: the deployer's bank balance went from ${formatQor(startBalance)} to ${formatQor(end)} QOR. Nothing is unrealised; no QOR is held anywhere.`);
  p.log(`            ${p.writes.length} window opens ${formatQor(windowFees)} QOR, ${p.writes.length} registry writes ${formatQor(writeFees)} QOR, identity funding ${formatQor(p.fundingUqor)} QOR`);
  p.log("  live cost per action, measured in this run: gas used on chain, then what the action cost in QOR (the write's own fee plus the one-transaction window opened for it):");
  for (const w of p.writes) {
    const total = w.result.evmFeeUqor + w.result.window.feeUqor;
    p.log(
      `    ${w.label.padEnd(30)}${String(w.result.receipt.gasUsed).padStart(8)} gas   ${formatQor(total).padEnd(9)} QOR ` +
        `(write ${formatQor(w.result.evmFeeUqor)} + window ${formatQor(w.result.window.feeUqor)})   ${w.result.hash}`,
    );
  }
  const window = await withRetry(() => fetchEvmWindow({ rest: REST, address: p.reg.deployer.qor1 }), { retries: 4, backoff: 2_000 });
  p.log(`  window:   the deployer's last window has ${window.remainingTxs} transactions and ${window.remainingValue} uqor left (live ${window.live})`);
}

async function main(): Promise<void> {
  const startedAt = new Date();
  const stamp = startedAt.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const reportName = `prove-registry-${stamp}.txt`;

  const record = recordedRegistry();
  if (record === undefined) throw new Error("deployments/testnet.json records no BoardRegistry. Run: npm run deploy:registry");
  const deployer: Deployer = await deriveDeployer(requireMnemonic());
  const artifact = loadRegistryArtifact();
  const reg: Registry = { client: evmClient(), deployer, address: record.address, abi: artifact.abi };
  const p = new Proof(reg, record, artifact);
  const startBalance = await balanceOf(deployer.qor1);
  p.log(`Ava BoardRegistry, live proof on the QoreChain testnet. Started ${startedAt.toISOString()}.`);
  p.log(`relayer:  the deployer ${deployer.qor1} / ${deployer.evm}, ${formatQor(startBalance)} QOR. It sends every registry transaction and grants nothing.`);

  for (const step of STEPS) {
    p.log(`\n${step.n}. ${step.title}`);
    try {
      await step.run(p);
      p.outcomes.push({ n: step.n, title: step.title, ok: true });
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      p.log(`  FAILED:   ${reason}`);
      if (err instanceof BudgetError) p.log(`  budget:   ${runBudget(p, err)}`);
      p.outcomes.push({ n: step.n, title: step.title, ok: false, reason });
      break;
    }
  }

  try {
    await summary(p, startBalance);
  } catch (err) {
    p.log(`  the summary could not read the chain: ${err instanceof Error ? err.message : String(err)}`);
  }
  const failed = p.outcomes.find((o) => !o.ok);
  p.log(`\nreport:   deployments/${reportName}`);
  writeFileSync(fileURLToPath(new URL(reportName, REPORT_DIR)), `${p.lines.join("\n")}\n`, "utf8");
  if (failed !== undefined) process.exitCode = 1;
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
