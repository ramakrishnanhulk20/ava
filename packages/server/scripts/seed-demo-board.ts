import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";
import {
  KemKeyUnavailable,
  Mode,
  encryptDocument,
  fetchKemKey,
  generateMnemonic,
  identityFromMnemonic,
  newBoardRef,
  newDocRef,
  newEpochKey,
  sameAccount,
  sealEpochKey,
  sha256,
  type Identity,
} from "@ava/core";
import { buildRegisterPqcKeyMsg, clearPqcStatusCache, fetchPqcStatus, isRegisteredPqcKey, msg, signProofOfPossession, verifyProofOfPossession, withRetry } from "@qorechain/sdk";
import { put } from "@vercel/blob/client";
import { bytesToHex, type Hex, type PublicClient } from "viem";
import { boardRegistryAbi } from "../src/abi/boardRegistry.ts";
import { VercelBlobBackend } from "../src/blob.ts";
import { isRelayerMnemonic, publicAddress, relayerFromMnemonic, type RelayerAccount } from "../src/chain/account.ts";
import { startDeadline } from "../src/chain/deadline.ts";
import { codeKeccak, evmClient } from "../src/chain/evm.ts";
import { assertTestnet, liveChain } from "../src/chain/live.ts";
import { balanceOf, sendNative } from "../src/chain/native.ts";
import {
  CHAIN_ID,
  KEM_REGISTRATION_FEE,
  KEY_REGISTRATION_FEE,
  REGISTRY_ADDRESS,
  REGISTRY_CODE_KECCAK,
  REST,
  SPONSOR_AMOUNT_UQOR,
  SPONSOR_SEND_FEE_UQOR,
  UQOR_PER_QOR,
} from "../src/config.ts";
import { liveDemoChain, openCurrentEpochKey, provenMldsaKey, relayAction, signedAction, uploadEnvelope, type BoardSnapshot, type DemoChain, type RelayBody } from "../src/demoBoard.ts";
import { handleDocumentToken, handleDocumentVerify } from "../src/docupload.ts";
import { loadEnv, type ServerEnv } from "../src/env.ts";
import type { RelayContext } from "../src/relay.ts";
import { handleSponsor, liveSponsor, type SponsorContext } from "../src/sponsor.ts";
import { UpstashStore } from "../src/store.ts";

const ENV_PATH = fileURLToPath(new URL("../.env", import.meta.url));
/** The demo chair is the Q-Day Drill account, whose classical key is handed out on 18 Nov. */
const SEED_OPENS_AT = Date.parse("2026-11-19T00:00:00Z");
const DIRECTORS = [
  { name: "Asha", variable: "DEMO_ASHA_MNEMONIC" },
  { name: "Ben", variable: "DEMO_BEN_MNEMONIC" },
  { name: "Chen", variable: "DEMO_CHEN_MNEMONIC" },
] as const;
// Each script counts under its own loopback address, so its sponsorships and uploads never use up
// another script's or the local dev server's hourly allowance.
const CLIENT_IP = "127.0.0.2";
const MNEMONIC_WORDS = 24;
// Eight relayed actions at about 0.04 QOR each plus one window open, with room to spare.
const RELAYER_FLOOR_UQOR = 1_000_000n;
const SPONSOR_FLOOR_UQOR = BigInt(DIRECTORS.length) * (SPONSOR_AMOUNT_UQOR + SPONSOR_SEND_FEE_UQOR);
const SEND_BUDGET_MS = 120_000;
const RECEIPT_WAIT_MS = 90_000;
const LABEL = "Ava demo board, Q4 pack: agenda and notes, written for this demo.";

interface Live {
  env: ServerEnv;
  chain: DemoChain;
  store: UpstashStore;
  blobs: VercelBlobBackend;
  relay: () => RelayContext;
  sponsor: () => SponsorContext;
  hashes: string[];
}

function formatQor(uqor: bigint): string {
  const fraction = (uqor % UQOR_PER_QOR).toString().padStart(6, "0").replace(/0+$/, "");
  return `${uqor / UQOR_PER_QOR}${fraction === "" ? "" : `.${fraction}`}`;
}

function lineFor(name: string): RegExp {
  return new RegExp(`^\\s*(export\\s+)?${name}\\s*=`, "m");
}

/** A director's phrase from .env, or a fresh one written there. Never printed; messages name the variable only. */
function ensureMnemonic(variable: string): string {
  const raw = process.env[variable];
  if (raw !== undefined && raw.trim() !== "") {
    if (!isRelayerMnemonic(raw)) throw new Error(`${variable} in ${ENV_PATH} is not ${MNEMONIC_WORDS} valid words.`);
    return raw.trim().split(/\s+/).join(" ");
  }
  const existing = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
  if (lineFor(variable).test(existing)) throw new Error(`${ENV_PATH} has an empty ${variable} line. Delete it to have a new identity made, or fill it.`);
  const mnemonic = generateMnemonic();
  if (!isRelayerMnemonic(mnemonic)) throw new Error("The new phrase is not 24 valid words. Nothing was written.");
  const lead = existing.length > 0 && !existing.endsWith("\n") ? "\n" : "";
  appendFileSync(ENV_PATH, `${lead}${variable}="${mnemonic}"\n`, { encoding: "utf8", mode: 0o600 });
  if (parseEnv(readFileSync(ENV_PATH, "utf8"))[variable] !== mnemonic) throw new Error(`Read-back of ${variable} from ${ENV_PATH} failed. Delete that line and run again.`);
  process.env[variable] = mnemonic;
  return mnemonic;
}

async function provenOnRest(account: RelayerAccount): Promise<boolean> {
  clearPqcStatusCache();
  const status = await fetchPqcStatus({ rest: REST, address: account.qor1 });
  return status.registered && isRegisteredPqcKey(status, account.pqc.publicKey) === true && status.possessionProven === true;
}

/** "ours", "none" or "other" for the identity's published ML-KEM key, read as the bot reads it (C15). */
async function kemState(identity: Identity): Promise<"ours" | "none" | "other"> {
  try {
    const key = await fetchKemKey(identity.evm);
    return Buffer.from(key).equals(Buffer.from(identity.seal.mlkemPublicKey)) ? "ours" : "other";
  } catch (error) {
    if (error instanceof KemKeyUnavailable && error.reason === "NOT_FOUND") return "none";
    throw error;
  }
}

async function waitFor(what: string, check: () => Promise<boolean>): Promise<void> {
  await withRetry(
    async () => {
      if (!(await check())) throw new Error(`${what} not visible yet`);
    },
    { retries: 10, backoff: 2_000, maxBackoff: 6_000 },
  );
}

/**
 * Makes one director ready the way a browser onboards a person: sponsored through handleSponsor,
 * then its ML-DSA-87 key (classical MsgRegisterPQCKeyV2, the chain's first-transaction rule) and its
 * ML-KEM-1024 key (hybrid MsgRegisterKEMKey). Each part runs only when the chain shows it missing.
 */
async function onboard(live: Live, name: string, variable: string): Promise<Identity> {
  const mnemonic = ensureMnemonic(variable);
  const [identity, account] = await Promise.all([identityFromMnemonic(mnemonic), relayerFromMnemonic(mnemonic)]);
  if (!sameAccount(identity.qor1, account.qor1)) throw new Error(`${name}: the two derivations disagree. Stopping.`);
  const [balance, proven, kem] = await Promise.all([balanceOf(account.qor1), provenOnRest(account), kemState(identity)]);
  if (kem === "other") throw new Error(`${name} publishes a KEM key that is not this phrase's. Stopping.`);
  console.log(`${name.padEnd(9)} ${identity.qor1} / ${identity.evm} (phrase in .env as ${variable})`);

  if (!proven) {
    if (balance < SPONSOR_AMOUNT_UQOR) {
      const response = await handleSponsor(jsonRequest("http://internal/api/sponsor", { address: identity.qor1 }), live.sponsor());
      const answer = (await response.json()) as { txHash?: string; error?: string };
      if (response.status !== 202 || answer.txHash === undefined) throw new Error(`${name}: sponsor refused with ${response.status} ${answer.error ?? ""}`);
      live.hashes.push(answer.txHash);
      console.log(`  sponsored ${formatQor(SPONSOR_AMOUNT_UQOR)} QOR by hybrid MsgSend ${answer.txHash}`);
      await waitFor(`${name} funding`, async () => (await balanceOf(account.qor1)) >= balance + SPONSOR_AMOUNT_UQOR);
    }
    const proof = signProofOfPossession({ chainId: CHAIN_ID, account: account.qor1, keypair: account.pqc });
    if (!verifyProofOfPossession({ chainId: CHAIN_ID, account: account.qor1, publicKey: account.pqc.publicKey, proof })) throw new Error(`${name}: the proof of possession does not verify locally.`);
    const tx = await sendNative(account, "classical", [buildRegisterPqcKeyMsg(account.qor1, { pqcKeypair: account.pqc, proofOfPossession: proof })], KEY_REGISTRATION_FEE, startDeadline(SEND_BUDGET_MS));
    live.hashes.push(tx.hash);
    await waitFor(`${name} ML-DSA-87 key`, () => provenOnRest(account));
    console.log(`  ML-DSA-87 registered, possession proven, in ${tx.hash} (gas used ${tx.gasUsed} of ${tx.gasWanted})`);
  }
  if (kem === "none") {
    const message = msg.pqc.registerKemKey({ sender: account.qor1, publicKey: identity.seal.mlkemPublicKey });
    const tx = await sendNative(account, "hybrid", [message], KEM_REGISTRATION_FEE, startDeadline(SEND_BUDGET_MS));
    live.hashes.push(tx.hash);
    await waitFor(`${name} ML-KEM-1024 key`, async () => (await kemState(identity)) === "ours");
    console.log(`  ML-KEM-1024 registered in ${tx.hash} (gas used ${tx.gasUsed} of ${tx.gasWanted}, pqc_hybrid_verify verified)`);
  }
  await waitFor(`${name} key on the EVM lane`, async () => provenMldsaKey(await live.chain.keyStatus(identity.evm)) !== undefined);
  return identity;
}

function jsonRequest(url: string, body: unknown): Request {
  return new Request(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
}

/** Relays one signed action through handleRelay and requires a successful receipt (C26). */
async function relayed(live: Live, label: string, body: RelayBody): Promise<Hex> {
  const outcome = await relayAction(body, live.relay());
  if (outcome.txHash === undefined) throw new Error(`${label}: the relay refused with ${outcome.status} ${outcome.error ?? ""}`);
  const status = await live.chain.receipt(outcome.txHash, RECEIPT_WAIT_MS);
  if (status !== "success") throw new Error(`${label}: ${outcome.txHash} ${status === undefined ? "did not land in time" : "reverted"}.`);
  live.hashes.push(outcome.txHash);
  console.log(`${label.padEnd(30)} ${outcome.txHash}`);
  return outcome.txHash;
}

/** Seals a fresh key for `epoch` to each member's on-chain ML-KEM key (C11, C15) and uploads it through handleUpload. */
async function sealFresh(live: Live, boardRef: Hex, epoch: bigint, members: readonly Hex[]): Promise<{ epochKey: Uint8Array; hash: Hex; size: number }> {
  const recipients = [];
  for (const address of members) recipients.push({ address, kemPublicKey: await fetchKemKey(address) });
  const epochKey = newEpochKey();
  const envelope = sealEpochKey({ registry: REGISTRY_ADDRESS, boardRef, epoch, epochKey, recipients });
  const uploaded = await uploadEnvelope(envelope, { clientIp: CLIENT_IP, now: Date.now(), store: live.store, blobs: live.blobs, blobOrigin: live.env.BLOB_ORIGIN });
  return { epochKey, ...uploaded };
}

/** The current epoch's key as the chain records it, opened by the chair after the C12 check, and required to equal the key the seed holds. */
async function checkedKey(live: Live, snapshot: BoardSnapshot, chair: Identity, held: Uint8Array): Promise<Uint8Array> {
  const opened = await openCurrentEpochKey({ snapshot, sealKeys: chair.seal, blobs: live.blobs, blobOrigin: live.env.BLOB_ORIGIN });
  if (!Buffer.from(opened).equals(Buffer.from(held))) throw new Error(`The epoch ${snapshot.epoch} envelope on chain does not carry the key the seed sealed. Stopping.`);
  return opened;
}

/** Encrypts one pack, stores it through the document token and verify path, then posts it. */
async function postPack(live: Live, chair: Identity, snapshot: BoardSnapshot, epochKey: Uint8Array, n: number, story: string): Promise<void> {
  const text = `${LABEL}\n\nPack ${n} of 3. ${story}\n\nAgenda\n1. Welcome and roll call.\n2. How this pack stays private: it was encrypted before it left the chair's machine, and only members who hold the epoch ${snapshot.epoch} key can read it.\n3. Questions.\n\nNotes\nNo real company, figures or people appear on this board.\n`;
  const docRef = bytesToHex(newDocRef());
  const ciphertext = await encryptDocument({ epochKey, registry: REGISTRY_ADDRESS, boardRef: snapshot.boardRef, epoch: snapshot.epoch, docRef, plaintext: new TextEncoder().encode(text) });
  const hex = Buffer.from(sha256(ciphertext)).toString("hex");
  const docCtx = { clientIp: CLIENT_IP, now: Date.now(), store: live.store, blobs: live.blobs, env: { BLOB_ORIGIN: live.env.BLOB_ORIGIN, BLOB_READ_WRITE_TOKEN: live.env.BLOB_READ_WRITE_TOKEN } };
  const grant = (await (await handleDocumentToken(jsonRequest("http://internal/api/document/token", { sha256: hex }), docCtx)).json()) as { exists?: boolean; pathname?: string; token?: string; contentType?: string; error?: string };
  if (grant.exists !== true) {
    if (grant.pathname === undefined || grant.token === undefined || grant.contentType === undefined) throw new Error(`Pack ${n}: no upload token (${grant.error ?? "unknown"}).`);
    await put(grant.pathname, Buffer.from(ciphertext), { access: "public", token: grant.token, contentType: grant.contentType });
  }
  const verified = await handleDocumentVerify(jsonRequest("http://internal/api/document/verify", { sha256: hex }), { ...docCtx, now: Date.now() });
  const checked = (await verified.json()) as { size?: number; error?: string };
  if (verified.status !== 200 || checked.size !== ciphertext.length) throw new Error(`Pack ${n}: the store did not verify it (${checked.error ?? verified.status}).`);
  const body = signedAction(chair, snapshot, { kind: "post", docRef, cipherHash: `0x${hex}`, cipherSize: BigInt(ciphertext.length), epoch: snapshot.epoch });
  await relayed(live, `post pack ${n} (epoch ${snapshot.epoch})`, body);
}

/** Every precondition, reported together. Returns the list of what is missing; empty means go. */
async function readiness(env: ServerEnv, client: PublicClient, chain: DemoChain): Promise<string[]> {
  const missing: string[] = [];
  if (env.RELAYER_MNEMONIC === undefined) missing.push("RELAYER_MNEMONIC is not set. Run: npx tsx scripts/new-relayer.ts");
  if (env.SPONSOR_MNEMONIC === undefined) missing.push("SPONSOR_MNEMONIC is not set. Run: npx tsx scripts/new-sponsor.ts");
  if (env.DEMO_CHAIR_MNEMONIC === undefined) missing.push("DEMO_CHAIR_MNEMONIC is not set: the head chef copies the drill account's phrase in after the drill");
  const accounts: { role: string; qor1: string }[] = [];
  for (const [role, phrase, floor] of [
    ["relayer", env.RELAYER_MNEMONIC, RELAYER_FLOOR_UQOR],
    ["sponsor", env.SPONSOR_MNEMONIC, SPONSOR_FLOOR_UQOR],
  ] as const) {
    if (phrase === undefined) continue;
    const account = await relayerFromMnemonic(phrase);
    accounts.push({ role, qor1: account.qor1 });
    const [balance, proven] = await Promise.all([balanceOf(account.qor1), provenOnRest(account)]);
    console.log(`${role.padEnd(9)} ${account.qor1}, ${formatQor(balance)} QOR, ML-DSA-87 ${proven ? "registered, possession proven" : "not registered"}`);
    if (balance < floor) missing.push(`funds: the ${role} holds ${formatQor(balance)} QOR; send at least ${formatQor(floor - balance)} QOR more to ${account.qor1}`);
    if (!proven) missing.push(`key: the ${role}'s ML-DSA-87 key is not registered. Run: npx tsx scripts/register-${role}.ts`);
  }
  if (env.DEMO_CHAIR_MNEMONIC !== undefined) {
    const chair = await identityFromMnemonic(env.DEMO_CHAIR_MNEMONIC);
    accounts.push({ role: "chair", qor1: chair.qor1 });
    const [status, kem] = await Promise.all([chain.keyStatus(chair.evm), kemState(chair)]);
    console.log(`chair     ${chair.qor1} / ${chair.evm}`);
    if (provenMldsaKey(status) === undefined) missing.push("key: the demo chair has no possession-proven ML-DSA-87 key on the EVM lane");
    if (kem !== "ours") missing.push("key: the demo chair does not publish this phrase's ML-KEM-1024 key");
  }
  for (const a of accounts) {
    for (const b of accounts) if (a !== b && sameAccount(a.qor1, b.qor1)) missing.push(`accounts: the ${a.role} and the ${b.role} are one account; they must be three separate accounts (C36)`);
  }
  const code = await codeKeccak(client, REGISTRY_ADDRESS);
  if (code !== REGISTRY_CODE_KECCAK) missing.push(`registry: the code at ${REGISTRY_ADDRESS} is not the deployed BoardRegistry`);
  return [...new Set(missing)];
}

/**
 * Seeds Ava's public demo board on testnet, every action through the one relay pipeline: three
 * directors (Asha, Ben, Chen) onboarded through the sponsor, the board created by the demo chair,
 * Asha and Ben added by ROTATE, pack 1 posted, Chen added by SEAL_CURRENT, pack 2 posted, Chen
 * removed, pack 3 posted. Writes DEMO_BOARD_ID and DEMO_SEEDED to .env at the end.
 */
async function main(): Promise<void> {
  if (Date.now() < SEED_OPENS_AT) {
    console.log("refused:  the demo chair is the Q-Day Drill account. Seeding opens 2026-11-19T00:00:00Z, after the drill. Nothing was read or sent.");
    process.exitCode = 1;
    return;
  }
  if (existsSync(ENV_PATH)) process.loadEnvFile(ENV_PATH);
  const env = loadEnv();
  const existing = existsSync(ENV_PATH) ? readFileSync(ENV_PATH, "utf8") : "";
  if (env.DEMO_BOARD_ID !== undefined || lineFor("DEMO_BOARD_ID").test(existing) || lineFor("DEMO_SEEDED").test(existing)) {
    console.log(`refused:  DEMO_BOARD_ID or DEMO_SEEDED is already in ${ENV_PATH}. The demo board is seeded once. Nothing was sent.`);
    process.exitCode = 1;
    return;
  }
  console.log(`chain id: ${await assertTestnet()} confirmed`);
  const client = evmClient();
  const chain = liveDemoChain(client);
  const missing = await readiness(env, client, chain);
  if (missing.length > 0 || env.RELAYER_MNEMONIC === undefined || env.SPONSOR_MNEMONIC === undefined || env.DEMO_CHAIR_MNEMONIC === undefined) {
    console.log("missing:");
    for (const line of missing) console.log(`  - ${line}`);
    console.log("Nothing was sent.");
    process.exitCode = 1;
    return;
  }

  const relayerAccount = await relayerFromMnemonic(env.RELAYER_MNEMONIC);
  const relayChain = liveChain(relayerAccount, client);
  const sponsor = await liveSponsor(env.SPONSOR_MNEMONIC);
  const store = UpstashStore.connect({ url: env.UPSTASH_REDIS_REST_URL, token: env.UPSTASH_REDIS_REST_TOKEN });
  const live: Live = {
    env,
    chain,
    store,
    blobs: new VercelBlobBackend(env.BLOB_READ_WRITE_TOKEN),
    relay: () => ({ clientIp: CLIENT_IP, now: Date.now(), store, relayer: publicAddress(relayerAccount), chain: relayChain }),
    sponsor: () => ({ clientIp: CLIENT_IP, now: Date.now(), store, ...sponsor }),
    hashes: [],
  };
  const chair = await identityFromMnemonic(env.DEMO_CHAIR_MNEMONIC);

  // A run that stopped after pack 2 can be finished on the same board instead of seeding a second
  // one; it continues only when the board is exactly where a seed leaves it after pack 2.
  const resumeAt = process.argv.indexOf("--resume-board");
  if (resumeAt !== -1) {
    const boardId = BigInt(process.argv[resumeAt + 1] ?? "0");
    const saved = await Promise.all(DIRECTORS.map(async (d) => {
      const phrase = process.env[d.variable];
      if (phrase === undefined || phrase === "") throw new Error(`${d.variable} is not in ${ENV_PATH}. Cannot resume.`);
      return identityFromMnemonic(phrase);
    }));
    const [asha, ben, chen] = saved;
    if (asha === undefined || ben === undefined || chen === undefined) throw new Error("A director is missing. Stopping.");
    const stored = await client.readContract({ address: REGISTRY_ADDRESS, abi: boardRegistryAbi, functionName: "getBoard", args: [boardId] });
    const snapshot = await chain.board(boardId);
    const expected = [chair.evm, asha.evm, ben.evm, chen.evm];
    const matches = sameAccount(snapshot.chair, chair.evm) && snapshot.epoch === 2n && stored.documentCount === 2
      && snapshot.members.length === expected.length && expected.every((a) => snapshot.members.some((m) => sameAccount(m, a)));
    if (!matches) throw new Error(`Board ${boardId} is not where a seed stops after pack 2. Nothing was sent.`);
    console.log(`resume:   board ${boardId}, epoch ${snapshot.epoch}, nonce ${snapshot.nonce}, 4 members, 2 packs: finishing from the removal of Chen`);
    await finish(live, chain, chair, boardId, stored.boardRef, snapshot, [asha, ben, chen]);
    return;
  }

  // One at a time: each onboarding spends from the sponsor, whose sends are queued anyway.
  const directors: Identity[] = [];
  for (const d of DIRECTORS) directors.push(await onboard(live, d.name, d.variable));
  const [asha, ben, chen] = directors;
  if (asha === undefined || ben === undefined || chen === undefined) throw new Error("A director is missing. Stopping.");

  const boardRef = bytesToHex(newBoardRef());
  const first = await sealFresh(live, boardRef, 0n, [chair.evm]);
  const [latest, createNonce] = await Promise.all([
    client.getBlock({ blockTag: "latest" }),
    client.readContract({ address: REGISTRY_ADDRESS, abi: boardRegistryAbi, functionName: "createNonces", args: [chair.evm] }),
  ]);
  await relayed(live, "create board (epoch 0)", signedAction(chair, { boardId: 0n, nonce: createNonce, blockTimestamp: latest.timestamp }, { kind: "create", boardRef, envelopeHash: first.hash, envelopeSize: first.size }));
  const boardId = await client.readContract({ address: REGISTRY_ADDRESS, abi: boardRegistryAbi, functionName: "boardIdOf", args: [boardRef] });
  console.log(`board id:                      ${boardId}`);

  let snapshot = await chain.board(boardId);
  if (!sameAccount(snapshot.chair, chair.evm)) throw new Error(`Board ${boardId} does not name the demo chair. Stopping.`);
  for (const director of [asha, ben]) {
    const next = await sealFresh(live, boardRef, snapshot.epoch + 1n, [...snapshot.members, director.evm]);
    const body = signedAction(chair, snapshot, { kind: "add", member: director.evm, mode: Mode.ROTATE, envelopeHash: next.hash, envelopeSize: next.size, epochAfter: snapshot.epoch + 1n });
    await relayed(live, `add ${director === asha ? "Asha" : "Ben"} (ROTATE to ${snapshot.epoch + 1n})`, body);
    snapshot = await chain.board(boardId);
    next.epochKey = await checkedKey(live, snapshot, chair, next.epochKey);
    if (director === ben) {
      await postPack(live, chair, snapshot, next.epochKey, 1, `Posted in epoch ${snapshot.epoch}, when the board was the chair, Asha and Ben.`);
    }
  }

  snapshot = await chain.board(boardId);
  const current = await openCurrentEpochKey({ snapshot, sealKeys: chair.seal, blobs: live.blobs, blobOrigin: env.BLOB_ORIGIN });
  const toChen = sealEpochKey({ registry: REGISTRY_ADDRESS, boardRef, epoch: snapshot.epoch, epochKey: current, recipients: [{ address: chen.evm, kemPublicKey: await fetchKemKey(chen.evm) }] });
  const chenEnvelope = await uploadEnvelope(toChen, { clientIp: CLIENT_IP, now: Date.now(), store, blobs: live.blobs, blobOrigin: env.BLOB_ORIGIN });
  await relayed(
    live,
    `add Chen (SEAL_CURRENT ${snapshot.epoch})`,
    signedAction(chair, snapshot, { kind: "add", member: chen.evm, mode: Mode.SEAL_CURRENT, envelopeHash: chenEnvelope.hash, envelopeSize: chenEnvelope.size, epochAfter: snapshot.epoch }),
  );
  snapshot = await chain.board(boardId);
  await postPack(live, chair, snapshot, current, 2, `Posted in epoch ${snapshot.epoch}, after Chen joined by having the current key sealed to Chen alone. Chen can read packs 1 and 2: joining an epoch exposes everything posted in it, and the exposure ledger shows that.`);
  // Posting moves the board nonce, so the removal must be signed over a fresh read.
  snapshot = await chain.board(boardId);
  await finish(live, chain, chair, boardId, boardRef, snapshot, [asha, ben, chen]);
}

type Snapshot = Awaited<ReturnType<ReturnType<typeof liveDemoChain>["board"]>>;

/** Removes Chen, posts pack 3, and writes DEMO_BOARD_ID and DEMO_SEEDED: the last stretch of a seed. */
async function finish(
  live: Live,

  chain: ReturnType<typeof liveDemoChain>,
  chair: Identity,
  boardId: bigint,
  boardRef: `0x${string}`,
  start: Snapshot,
  [asha, ben, chen]: Identity[],
): Promise<void> {
  if (asha === undefined || ben === undefined || chen === undefined) throw new Error("A director is missing. Stopping.");
  let snapshot = start;
  const remaining = snapshot.members.filter((m) => !sameAccount(m, chen.evm));
  const fresh = await sealFresh(live, boardRef, snapshot.epoch + 1n, remaining);
  await relayed(live, `remove Chen (to epoch ${snapshot.epoch + 1n})`, signedAction(chair, snapshot, { kind: "remove", member: chen.evm, envelopeHash: fresh.hash, envelopeSize: fresh.size, epochAfter: snapshot.epoch + 1n }));
  snapshot = await chain.board(boardId);
  const third = await checkedKey(live, snapshot, chair, fresh.epochKey);
  await postPack(live, chair, snapshot, third, 3, `Posted in epoch ${snapshot.epoch}, after Chen was removed and the board moved to a fresh key sealed to the chair, Asha and Ben only. Chen cannot read this pack.`);

  const seeded = [asha.evm, ben.evm, chen.evm];
  const tail = readFileSync(ENV_PATH, "utf8");
  appendFileSync(ENV_PATH, `${tail.endsWith("\n") ? "" : "\n"}DEMO_BOARD_ID=${boardId}\nDEMO_SEEDED=${seeded.join(",")}\n`, { encoding: "utf8" });
  const written = loadEnv(parseEnv(readFileSync(ENV_PATH, "utf8")));
  if (written.DEMO_BOARD_ID !== boardId || written.DEMO_SEEDED?.length !== seeded.length) throw new Error(`Read-back of DEMO_BOARD_ID and DEMO_SEEDED from ${ENV_PATH} failed. Fix those two lines by hand: board ${boardId}.`);
  const final = await chain.board(boardId);
  console.log(`board:    ${boardId}, epoch ${final.epoch}, nonce ${final.nonce}, members ${final.members.join(", ")}`);
  console.log(`written:  DEMO_BOARD_ID=${boardId} and DEMO_SEEDED (Asha, Ben, Chen) in ${ENV_PATH}`);
  console.log(`tx hashes (${live.hashes.length}): ${live.hashes.join(" ")}`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
