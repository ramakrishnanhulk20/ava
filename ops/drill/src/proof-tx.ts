import { MSG_SEND_TYPE_URL } from "@qorechain/sdk";
import { deriveDrillAccount } from "./account.js";
import { assertTestnet } from "./chain.js";
import { DENOM, DRILL_DAY_END, DRILL_DAY_START, REST, requireMnemonic } from "./env.js";
import { formatQor, readStatus } from "./status.js";
import { FEE_RULE, MAX_FEE_UQOR, sendTx, type Messages } from "./tx.js";

const dryRun = process.argv.includes("--dry-run");
const MEMO = "q-day-drill proof";
const AMOUNT_UQOR = "1";

async function main(): Promise<void> {
  const chainId = await assertTestnet();
  const account = await deriveDrillAccount(requireMnemonic());

  const messages: Messages = [
    { typeUrl: MSG_SEND_TYPE_URL, value: { fromAddress: account.qor1, toAddress: account.qor1, amount: [{ denom: DENOM, amount: AMOUNT_UQOR }] } },
  ];
  const now = Date.now();
  const insideDrillDay = now >= DRILL_DAY_START && now <= DRILL_DAY_END;
  const window = `${new Date(DRILL_DAY_START).toISOString()} to ${new Date(DRILL_DAY_END).toISOString()}`;

  console.log(`chain id:  ${chainId} confirmed`);
  console.log(`message:   ${MSG_SEND_TYPE_URL} (signed hybrid: eth_secp256k1 plus ML-DSA-87)`);
  console.log(`  from:    ${account.qor1}`);
  console.log(`  to:      ${account.qor1} (itself)`);
  console.log(`  amount:  ${AMOUNT_UQOR} ${DENOM}`);
  console.log(`  memo:    "${MEMO}"`);
  console.log(`  fee:     ${FEE_RULE}`);
  console.log(`check:     code 0 and a pqc_hybrid_verify event with status verified`);
  console.log(`live run:  allowed only ${window}; now ${new Date(now).toISOString()} is ${insideDrillDay ? "inside" : "outside"} it`);

  if (dryRun) {
    console.log("dry run: nothing was signed for broadcast or sent.");
    return;
  }
  if (!insideDrillDay) {
    throw new Error(`Refusing a live run outside drill day (${window}).`);
  }

  const status = await readStatus(account);
  if (!status.pq.found || status.pq.matchesOurKey !== true || status.pq.possessionProven !== true) {
    throw new Error("The account's ML-DSA-87 key is not registered as this phrase's key with possession proven. Run: npm run register");
  }
  if (status.balanceUqor <= MAX_FEE_UQOR) {
    throw new Error(`Balance ${formatQor(status.balanceUqor)} QOR may not cover the fee cap of ${formatQor(MAX_FEE_UQOR)} QOR. Fund ${account.qor1} first.`);
  }

  const tx = await sendTx(account, "hybrid", messages, MEMO);
  console.log(`proof tx:  ${tx.hash}`);
  console.log(`result:    code 0, pqc_hybrid_verify verified, 4,627-byte ML-DSA-87 signature; height ${tx.height}, gas used ${tx.gasUsed} of ${tx.gasWanted}, fee ${tx.fee.amount[0]!.amount} uqor`);
  console.log(`anyone:    curl -s ${REST}/cosmos/tx/v1beta1/txs/${tx.hash}`);
  console.log("Submit this hash on the project page as the drill-day proof.");
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
