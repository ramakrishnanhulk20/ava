import {
  buildRegisterPqcKeyMsg,
  clearPqcStatusCache,
  fetchKemKey,
  fetchPqcStatus,
  getJson,
  isRegisteredPqcKey,
  msg,
  qorechainRegistry,
  signProofOfPossession,
  verifyProofOfPossession,
  withRetry,
  type KemKeyResult,
  type PqcStatus,
} from "@qorechain/sdk";
import { buildRegisterKemKeyMessage } from "@qorechain/qoreseal";
import { deriveDeployer, sameAccount, type Deployer } from "./account.js";
import { assertTestnet } from "./chain.js";
import { CHAIN_ID, DENOM, FUNDED_THRESHOLD_UQOR, HTTP, REST, UQOR_PER_QOR, requireMnemonic } from "./env.js";
import { FEE_RULE, REGISTRATION_FEE, sendTx, type Messages } from "./tx.js";

function formatQor(uqor: bigint): string {
  const fraction = (uqor % UQOR_PER_QOR).toString().padStart(6, "0").replace(/0+$/, "");
  return fraction === "" ? `${uqor / UQOR_PER_QOR}` : `${uqor / UQOR_PER_QOR}.${fraction}`;
}

async function balanceOf(address: string): Promise<bigint> {
  const body = await getJson<{ balances?: unknown }>(`${REST}/cosmos/bank/v1beta1/balances/${encodeURIComponent(address)}`, HTTP);
  if (!Array.isArray(body.balances)) throw new Error("Unexpected balance answer: no balances list.");
  const coin = body.balances.find((c: { denom?: unknown }) => c?.denom === DENOM) as { amount?: unknown } | undefined;
  if (coin === undefined) return 0n;
  if (typeof coin.amount !== "string" || !/^\d{1,40}$/.test(coin.amount)) throw new Error("Unexpected balance amount.");
  return BigInt(coin.amount);
}

/** True only when the chain holds this phrase's ML-KEM key for exactly this account. */
function isOurKemKey(kem: KemKeyResult, deployer: Deployer): boolean {
  return (
    kem.found &&
    kem.key !== undefined &&
    sameAccount(kem.key.address, deployer.qor1) &&
    kem.key.algorithmId === 2 &&
    Buffer.from(kem.key.publicKey).equals(Buffer.from(deployer.seal.mlkemPublicKey))
  );
}

function isOurProvenPqKey(pqc: PqcStatus, deployer: Deployer): boolean {
  return pqc.registered && isRegisteredPqcKey(pqc, deployer.pqc.publicKey) === true && pqc.possessionProven === true;
}

async function readPqc(address: string): Promise<PqcStatus> {
  clearPqcStatusCache();
  return fetchPqcStatus({ rest: REST, address });
}

function pqKeyMessages(deployer: Deployer): Messages {
  const proof = signProofOfPossession({ chainId: CHAIN_ID, account: deployer.qor1, keypair: deployer.pqc });
  if (!verifyProofOfPossession({ chainId: CHAIN_ID, account: deployer.qor1, publicKey: deployer.pqc.publicKey, proof })) {
    throw new Error("The proof of possession does not verify locally. Refusing to send a registration the chain would refuse after taking the fee.");
  }
  // The organisers' example leaves ecdsa_pubkey empty: the chain binds the key of the transaction's signer.
  return [buildRegisterPqcKeyMsg(deployer.qor1, { pqcKeypair: deployer.pqc, proofOfPossession: proof })];
}

function kemKeyMessages(deployer: Deployer): Messages {
  const message = msg.pqc.registerKemKey({ sender: deployer.qor1, publicKey: deployer.seal.mlkemPublicKey });
  // The SDK message is the one its registry can sign; QoreSeal's builder is the reference encoding.
  const reference = buildRegisterKemKeyMessage({ sender: deployer.qor1, mlkemPublicKey: deployer.seal.mlkemPublicKey });
  if (message.typeUrl !== reference.typeUrl || !Buffer.from(qorechainRegistry().encode(message)).equals(Buffer.from(reference.value))) {
    throw new Error("The SDK and QoreSeal encode the KEM registration differently. Refusing to send.");
  }
  return [message];
}

async function waitFor(what: string, check: () => Promise<boolean>): Promise<void> {
  await withRetry(
    async () => {
      if (!(await check())) throw new Error(`${what} not visible yet`);
    },
    { retries: 8, backoff: 2_000, maxBackoff: 6_000 },
  );
}

async function main(): Promise<void> {
  const chainId = await assertTestnet();
  const deployer = await deriveDeployer(requireMnemonic());
  const [balance, pqc, kem] = await Promise.all([
    balanceOf(deployer.qor1),
    readPqc(deployer.qor1),
    fetchKemKey({ rest: REST, address: deployer.qor1 }),
  ]);

  console.log(`chain id:  ${chainId} confirmed`);
  console.log(`qor1:      ${deployer.qor1}`);
  console.log(`0x:        ${deployer.evm}`);
  console.log(`balance:   ${formatQor(balance)} QOR`);

  if (pqc.registered && !isOurProvenPqKey(pqc, deployer)) {
    throw new Error("The account has an ML-DSA-87 key that is not this phrase's key with possession proven. Refusing: a second registration is refused after the fee is taken.");
  }
  if (kem.found && !isOurKemKey(kem, deployer)) {
    throw new Error("The account already publishes a KEM key that is not this phrase's key. Refusing to replace it.");
  }

  const needPq = !pqc.registered;
  const needKem = !kem.found;
  if (!needPq && !needKem) {
    console.log("PQ key:    found, possession_proven true, this phrase's ML-DSA-87 key");
    console.log("KEM key:   found, algorithm 2, this phrase's ML-KEM-1024 key");
    console.log("Nothing to register.");
    return;
  }
  if (balance < FUNDED_THRESHOLD_UQOR) {
    throw new Error(`Not funded: send at least ${formatQor(FUNDED_THRESHOLD_UQOR)} QOR to ${deployer.qor1} first.`);
  }

  if (needPq) {
    console.log(`ML-DSA-87: registering with MsgRegisterPQCKeyV2, signed classical, fee ${REGISTRATION_FEE.amount[0]!.amount} uqor for ${REGISTRATION_FEE.gas} gas`);
    const tx = await sendTx(deployer, "classical", pqKeyMessages(deployer), "", REGISTRATION_FEE);
    await waitFor("ML-DSA-87 key", async () => isOurProvenPqKey(await readPqc(deployer.qor1), deployer));
    console.log(`ML-DSA-87: registered in ${tx.hash} (height ${tx.height}, gas used ${tx.gasUsed} of ${tx.gasWanted})`);
  }
  if (needKem) {
    console.log(`ML-KEM:    registering with MsgRegisterKEMKey, signed hybrid, fee ${FEE_RULE}`);
    const tx = await sendTx(deployer, "hybrid", kemKeyMessages(deployer), "");
    await waitFor("ML-KEM-1024 key", async () => isOurKemKey(await fetchKemKey({ rest: REST, address: deployer.qor1 }), deployer));
    console.log(`ML-KEM:    registered in ${tx.hash} (height ${tx.height}, gas used ${tx.gasUsed} of ${tx.gasWanted}, fee ${tx.fee.amount[0]!.amount} uqor, pqc_hybrid_verify verified)`);
  }

  console.log("PQ key:    found, possession_proven true, this phrase's ML-DSA-87 key");
  console.log("KEM key:   found, algorithm 2, this phrase's ML-KEM-1024 key");
  console.log(`balance:   ${formatQor(await balanceOf(deployer.qor1))} QOR`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
