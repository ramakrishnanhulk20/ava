import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  KemKeyUnavailable,
  Mode,
  challengeMessage,
  decryptDocument,
  fetchKemKey,
  generateMnemonic,
  identityFromMnemonic,
  openEpochKey,
  sameAccount,
  signAction,
  type Identity,
} from "@ava/core";
import { buildRegisterPqcKeyMsg, clearPqcStatusCache, fetchPqcStatus, isRegisteredPqcKey, msg, signProofOfPossession, verifyProofOfPossession, withRetry } from "@qorechain/sdk";
import { bytesToHex, hexToBytes, type Hex } from "viem";
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
import { handleDemoChallenge, handleDemoJoin, type DemoContext } from "../src/demo.ts";
import { envelopeUrl, liveDemoChain, provenMldsaKey } from "../src/demoBoard.ts";
import { loadEnv, type ServerEnv } from "../src/env.ts";
import { handleSponsor, liveSponsor } from "../src/sponsor.ts";
import { UpstashStore } from "../src/store.ts";

const ENV_PATH = fileURLToPath(new URL("../.env", import.meta.url));
// Each script counts under its own loopback address, so the seed's three sponsorships and local
// dev-server traffic never use up this check's hourly allowance.
const CLIENT_IP = "127.0.0.3";
const RELAYER_FLOOR_UQOR = 1_000_000n;
const SPONSOR_FLOOR_UQOR = SPONSOR_AMOUNT_UQOR + SPONSOR_SEND_FEE_UQOR;
const SEND_BUDGET_MS = 120_000;
const RECEIPT_WAIT_MS = 90_000;

function formatQor(uqor: bigint): string {
  const fraction = (uqor % UQOR_PER_QOR).toString().padStart(6, "0").replace(/0+$/, "");
  return `${uqor / UQOR_PER_QOR}${fraction === "" ? "" : `.${fraction}`}`;
}

function jsonRequest(url: string, body: unknown): Request {
  return new Request(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
}

async function provenOnRest(account: RelayerAccount): Promise<boolean> {
  clearPqcStatusCache();
  const status = await fetchPqcStatus({ rest: REST, address: account.qor1 });
  return status.registered && isRegisteredPqcKey(status, account.pqc.publicKey) === true && status.possessionProven === true;
}

async function waitFor(what: string, check: () => Promise<boolean>): Promise<void> {
  await withRetry(
    async () => {
      if (!(await check())) throw new Error(`${what} not visible yet`);
    },
    { retries: 10, backoff: 2_000, maxBackoff: 6_000 },
  );
}

async function publishesOwnKem(identity: Identity): Promise<boolean> {
  try {
    return Buffer.from(await fetchKemKey(identity.evm)).equals(Buffer.from(identity.seal.mlkemPublicKey));
  } catch (error) {
    if (error instanceof KemKeyUnavailable && error.reason === "NOT_FOUND") return false;
    throw error;
  }
}

/** What must be in place before anything is spent. Empty means go. */
async function missingFor(env: ServerEnv | undefined): Promise<string[]> {
  const missing: string[] = [];
  if (env === undefined) return ["server settings: packages/server/.env does not pass loadEnv (see .env.example)"];
  if (env.DEMO_BOARD_ID === undefined) missing.push("DEMO_BOARD_ID is not set: run npx tsx scripts/seed-demo-board.ts (from 19 Nov) first");
  if (env.DEMO_CHAIR_MNEMONIC === undefined) missing.push("DEMO_CHAIR_MNEMONIC is not set: the head chef copies the drill account's phrase in after the drill");
  for (const [role, phrase, floor] of [
    ["relayer", env.RELAYER_MNEMONIC, RELAYER_FLOOR_UQOR],
    ["sponsor", env.SPONSOR_MNEMONIC, SPONSOR_FLOOR_UQOR],
  ] as const) {
    if (phrase === undefined || !isRelayerMnemonic(phrase)) {
      missing.push(`${role.toUpperCase()}_MNEMONIC is not set. Run: npx tsx scripts/new-${role}.ts`);
      continue;
    }
    const account = await relayerFromMnemonic(phrase);
    const [balance, proven] = await Promise.all([balanceOf(account.qor1), provenOnRest(account)]);
    console.log(`${role.padEnd(9)} ${account.qor1}, ${formatQor(balance)} QOR, ML-DSA-87 ${proven ? "registered, possession proven" : "not registered"}`);
    if (balance < floor) missing.push(`funds: the ${role} holds ${formatQor(balance)} QOR; send at least ${formatQor(floor - balance)} QOR more to ${account.qor1}`);
    if (!proven) missing.push(`key: the ${role}'s ML-DSA-87 key is not registered. Run: npx tsx scripts/register-${role}.ts`);
  }
  return missing;
}

/**
 * The demo path a judge takes, end to end on testnet: a fresh guest identity is sponsored through
 * handleSponsor, registers its two keys, asks handleDemoChallenge for a challenge, signs the exact
 * bytes it was given, joins through handleDemoJoin, and once the addMember lands opens the current
 * epoch's envelope with its own keys and decrypts the latest pack. Prints what is missing and sends
 * nothing until the relayer and sponsor are funded and the board is seeded.
 */
async function main(): Promise<void> {
  if (existsSync(ENV_PATH)) process.loadEnvFile(ENV_PATH);
  console.log(`chain id: ${await assertTestnet()} confirmed`);
  const client = evmClient();
  const code = await codeKeccak(client, REGISTRY_ADDRESS);
  if (code !== REGISTRY_CODE_KECCAK) throw new Error(`The code at ${REGISTRY_ADDRESS} is not the deployed BoardRegistry. Stopping.`);
  let env: ServerEnv | undefined;
  try {
    env = loadEnv();
  } catch {
    env = undefined;
  }
  const missing = await missingFor(env);
  if (missing.length > 0 || env === undefined || env.DEMO_BOARD_ID === undefined || env.RELAYER_MNEMONIC === undefined || env.SPONSOR_MNEMONIC === undefined) {
    console.log("missing:");
    for (const line of missing) console.log(`  - ${line}`);
    console.log("Nothing was sent.");
    return;
  }
  const boardId = env.DEMO_BOARD_ID;

  const store = UpstashStore.connect({ url: env.UPSTASH_REDIS_REST_URL, token: env.UPSTASH_REDIS_REST_TOKEN });
  const blobs = new VercelBlobBackend(env.BLOB_READ_WRITE_TOKEN);
  const chain = liveDemoChain(client);
  const relayerAccount = await relayerFromMnemonic(env.RELAYER_MNEMONIC);
  const demo = (): DemoContext => ({
    clientIp: CLIENT_IP,
    now: Date.now(),
    store,
    env,
    chain,
    blobs,
    relayer: publicAddress(relayerAccount),
    relayChain: liveChain(relayerAccount, client),
  });

  // The guest lives in memory only, like a judge's first visit; its phrase is never written or shown.
  const mnemonic = generateMnemonic();
  const [guest, account] = await Promise.all([identityFromMnemonic(mnemonic), relayerFromMnemonic(mnemonic)]);
  console.log(`guest:    ${guest.qor1} / ${guest.evm} (fresh, in memory only)`);

  const sponsored = await handleSponsor(jsonRequest("http://internal/api/sponsor", { address: guest.qor1 }), { clientIp: CLIENT_IP, now: Date.now(), store, ...(await liveSponsor(env.SPONSOR_MNEMONIC)) });
  const sponsorAnswer = (await sponsored.json()) as { txHash?: string; error?: string };
  console.log(`sponsor:  HTTP ${sponsored.status} ${JSON.stringify(sponsorAnswer)}`);
  if (sponsored.status !== 202) throw new Error("The sponsor refused the fresh guest. Stopping.");
  await waitFor("the sponsored funds", async () => (await balanceOf(guest.qor1)) >= SPONSOR_AMOUNT_UQOR);

  const proof = signProofOfPossession({ chainId: CHAIN_ID, account: account.qor1, keypair: account.pqc });
  if (!verifyProofOfPossession({ chainId: CHAIN_ID, account: account.qor1, publicKey: account.pqc.publicKey, proof })) throw new Error("The proof of possession does not verify locally.");
  const pq = await sendNative(account, "classical", [buildRegisterPqcKeyMsg(account.qor1, { pqcKeypair: account.pqc, proofOfPossession: proof })], KEY_REGISTRATION_FEE, startDeadline(SEND_BUDGET_MS));
  console.log(`ML-DSA:   registered in ${pq.hash} (gas used ${pq.gasUsed} of ${pq.gasWanted})`);
  const kem = await sendNative(account, "hybrid", [msg.pqc.registerKemKey({ sender: account.qor1, publicKey: guest.seal.mlkemPublicKey })], KEM_REGISTRATION_FEE, startDeadline(SEND_BUDGET_MS));
  console.log(`ML-KEM:   registered in ${kem.hash} (gas used ${kem.gasUsed} of ${kem.gasWanted})`);
  await waitFor("the guest's keys on chain", async () => provenMldsaKey(await chain.keyStatus(guest.evm)) !== undefined && (await publishesOwnKem(guest)));
  console.log(`balance:  ${formatQor(await balanceOf(guest.qor1))} QOR left after both registrations`);

  const issued = await handleDemoChallenge(jsonRequest("http://internal/api/demo/challenge", { guest: guest.qor1 }), demo());
  const challenge = (await issued.json()) as { registry: string; boardId: string; botNonce: Hex; expiry: string; message: Hex; error?: string };
  if (issued.status !== 200) throw new Error(`No challenge: HTTP ${issued.status} ${challenge.error ?? ""}`);
  const rebuilt = challengeMessage({ registry: challenge.registry, boardId: BigInt(challenge.boardId), guest: guest.evm, botNonce: challenge.botNonce, expiry: BigInt(challenge.expiry) });
  if (bytesToHex(rebuilt) !== challenge.message.toLowerCase() || !sameAccount(challenge.registry, REGISTRY_ADDRESS) || BigInt(challenge.boardId) !== boardId) {
    throw new Error("The challenge bytes are not the spec's encoding of the fields it names. Refusing to sign.");
  }
  console.log(`challenge: ${hexToBytes(challenge.message).length} bytes for board ${challenge.boardId}, expiry ${challenge.expiry}; rebuilt locally byte for byte`);
  const signature = bytesToHex(signAction(guest.mldsa.secretKey, hexToBytes(challenge.message)));

  const joined = await handleDemoJoin(jsonRequest("http://internal/api/demo/join", { guest: guest.evm, botNonce: challenge.botNonce, expiry: challenge.expiry, signature }), demo());
  const joinAnswer = (await joined.json()) as { txHash?: Hex; error?: string };
  console.log(`join:     HTTP ${joined.status} ${JSON.stringify(joinAnswer)}`);
  if (joined.status !== 202 || joinAnswer.txHash === undefined) throw new Error("The demo bot did not admit the guest. Stopping.");
  const landed = await chain.receipt(joinAnswer.txHash, RECEIPT_WAIT_MS);
  console.log(`receipt:  ${landed ?? "not seen in time"}`);
  if (landed !== "success") throw new Error("The addMember did not land successfully.");

  const snapshot = await chain.board(boardId);
  if (!snapshot.members.some((m) => sameAccount(m, guest.evm))) throw new Error("The guest is not a member after the addMember landed.");
  const grant = snapshot.grants.find((g) => g.mode === Mode.SEAL_CURRENT && sameAccount(g.member, guest.evm));
  if (grant === undefined) throw new Error(`No SEAL_CURRENT grant for the guest in epoch ${snapshot.epoch}.`);
  const envelope = await blobs.read(envelopeUrl(env.BLOB_ORIGIN, grant.envelopeHash), grant.envelopeSize);
  if (envelope === null) throw new Error("The guest's envelope is not in the blob store.");
  const epochKey = openEpochKey({ registry: REGISTRY_ADDRESS, boardRef: snapshot.boardRef, epoch: snapshot.epoch, envelope, expectedHash: grant.envelopeHash, expectedSize: grant.envelopeSize, sealKeys: guest.seal });
  console.log(`opened:   the epoch ${snapshot.epoch} key, from the envelope the registry recorded for this guest, hash and size checked`);

  const board = await client.readContract({ address: REGISTRY_ADDRESS, abi: boardRegistryAbi, functionName: "getBoard", args: [boardId] });
  if (board.documentCount === 0) throw new Error("The demo board holds no packs.");
  const docId = BigInt(board.documentCount) - 1n;
  const doc = await client.readContract({ address: REGISTRY_ADDRESS, abi: boardRegistryAbi, functionName: "getDocument", args: [boardId, docId] });
  if (doc.epoch !== snapshot.epoch) {
    console.log(`latest:   pack ${docId} was posted in epoch ${doc.epoch}, before this guest's epoch ${snapshot.epoch}: not readable, by design (a guest sees only its own epoch).`);
    console.log("result:   joined and opened the current epoch key; no pack has been posted in this epoch yet");
    return;
  }
  const ciphertext = await blobs.read(new URL(`${env.BLOB_ORIGIN}/document/${doc.cipherHash.slice(2).toLowerCase()}`), Number(doc.cipherSize));
  if (ciphertext === null) throw new Error("The latest pack is not in the blob store.");
  const plain = await decryptDocument({ epochKey, registry: REGISTRY_ADDRESS, boardRef: snapshot.boardRef, epoch: doc.epoch, docRef: doc.docRef, ciphertext, expectedHash: doc.cipherHash, expectedSize: doc.cipherSize });
  const firstLine = new TextDecoder("utf-8", { fatal: true }).decode(plain).split("\n")[0] ?? "";
  console.log(`latest:   pack ${docId} (epoch ${doc.epoch}, ${doc.cipherSize} bytes) decrypted as the guest: "${firstLine}"`);
  console.log("result:   a fresh identity was sponsored, proved its key to the bot, was admitted and read the latest pack");
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
