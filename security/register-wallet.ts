import { balanceOf, formatQor, pqcStatus } from "./lib/chain.ts";
import { loadSuiteEnv } from "./lib/env.ts";
import { assertNoForeignSecrets, assertTestnet, installFetchGuard } from "./lib/guard.ts";
import { personAt } from "./lib/identities.ts";
import { KEM_FEE_EST_UQOR, MLDSA_FEE_UQOR, isOurProvenKey, kemOf, registerKem, registerMldsa } from "./lib/people.ts";

// Room for the simulated KEM fee to come in above the estimate.
const MARGIN_UQOR = 100_000n;

/**
 * Registers the security wallet's ML-DSA-87 key with a proof of possession, the way
 * packages/server/scripts/register-relayer.ts registers the relayer's, then its ML-KEM-1024 key,
 * which the relayer does not need but a board chair does (C15). Reads first and sends nothing for
 * a key the chain already holds.
 */
async function main(): Promise<void> {
  assertNoForeignSecrets();
  const env = loadSuiteEnv();
  installFetchGuard();
  const chain = await assertTestnet();
  const wallet = await personAt(env.mnemonic, 0, "wallet");
  const [balance, pqc, kem] = await Promise.all([balanceOf(wallet.qor1), pqcStatus(wallet.qor1), kemOf(wallet.evm)]);
  console.log(`chain id:  ${chain.cosmos} and EVM ${chain.evm} confirmed`);
  console.log(`qor1:      ${wallet.qor1}`);
  console.log(`0x:        ${wallet.evm}`);
  console.log(`balance:   ${formatQor(balance)} QOR`);

  if (pqc.registered && !isOurProvenKey(pqc, wallet)) {
    throw new Error("The account has an ML-DSA-87 key that is not this phrase's key with possession proven. Refusing: a second registration is refused after the fee is taken.");
  }
  if (kem !== undefined && !Buffer.from(kem).equals(Buffer.from(wallet.seal.mlkemPublicKey))) {
    throw new Error("The account publishes an ML-KEM-1024 key that is not this phrase's. Refusing to replace it.");
  }
  if (pqc.registered && kem !== undefined) {
    console.log("PQ key:    found, possession_proven true, this phrase's ML-DSA-87 key. Nothing to register.");
    console.log("KEM key:   found, this phrase's ML-KEM-1024 key. Nothing to register.");
    return;
  }
  const needed = (pqc.registered ? 0n : MLDSA_FEE_UQOR) + (kem === undefined ? KEM_FEE_EST_UQOR : 0n) + MARGIN_UQOR;
  if (balance < needed) throw new Error(`Not funded: send at least ${formatQor(needed - balance)} QOR more to ${wallet.qor1} first.`);

  if (!pqc.registered) {
    console.log("ML-DSA-87: registering with MsgRegisterPQCKeyV2 and a proof of possession, signed classical, fee 100000 uqor for 800000 gas");
    const tx = await registerMldsa(wallet, true);
    console.log(`ML-DSA-87: registered in ${tx.hash} (height ${tx.height}, gas used ${tx.gasUsed} of ${tx.gasWanted})`);
  }
  if (!isOurProvenKey(await pqcStatus(wallet.qor1), wallet)) throw new Error("The chain does not show this phrase's proven ML-DSA-87 key. Stopping before the KEM registration.");
  console.log("PQ key:    found, possession_proven true, this phrase's ML-DSA-87 key");

  if (kem === undefined) {
    console.log("ML-KEM-1024: registering with MsgRegisterKEMKey, hybrid-signed, simulated fee");
    const tx = await registerKem(wallet);
    console.log(`ML-KEM-1024: registered in ${tx.hash} (height ${tx.height}, gas used ${tx.gasUsed} of ${tx.gasWanted})`);
  }
  console.log("KEM key:   found through qor_getKEMKey, algorithm 2, 1,568 bytes, this phrase's ML-KEM-1024 key");
  console.log(`balance:   ${formatQor(await balanceOf(wallet.qor1))} QOR`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
