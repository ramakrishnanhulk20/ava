import { MSG_SEND_TYPE_URL, bech32ToHex, bytesToBech32, getJson, isValidBech32, isValidEvmAddress, toChecksumAddress } from "@qorechain/sdk";
import { deriveDrillAccount } from "./account.js";
import { assertTestnet } from "./chain.js";
import { DENOM, DRILL_DAY_START, HTTP, REST, UQOR_PER_QOR, requireMnemonic } from "./env.js";
import { formatQor, readStatus } from "./status.js";
import { FEE_RULE, MAX_FEE_UQOR, sendTx, type Messages } from "./tx.js";

// The drill account must keep its value for the Q-Day Drill, so one run can move at most this much.
const MAX_AMOUNT_UQOR = 10n * UQOR_PER_QOR;
const DAY_MS = 86_400_000;
const MEMO = "fund";
const USAGE = "Usage: npm run fund -- <qor1 or 0x address> <amount in QOR, at most 10>";

/**
 * A qor1 address with a valid bech32 checksum, or a 0x address in its exact
 * EIP-55 form, as its 20 bytes. Anything else is refused.
 */
function recipientBytes(address: string): Uint8Array {
  let hex: string;
  if (address.startsWith("qor1")) {
    if (!isValidBech32(address, "qor")) throw new Error("The recipient is not a valid qor1 address (bech32 checksum or prefix).");
    hex = bech32ToHex(address);
  } else if (address.startsWith("0x")) {
    // Lowercase or uppercase hex carries no checksum, so a typo would go unnoticed.
    if (!isValidEvmAddress(address) || toChecksumAddress(address) !== address) {
      throw new Error("The recipient is not a 0x address in its EIP-55 checksum form.");
    }
    hex = address;
  } else {
    throw new Error(`The recipient must start with qor1 or 0x. ${USAGE}`);
  }
  const bytes = Uint8Array.from(Buffer.from(hex.slice(2), "hex"));
  if (bytes.length !== 20) throw new Error(`An account is 20 bytes; the recipient decodes to ${bytes.length}.`);
  return bytes;
}

function amountUqor(text: string): bigint {
  const match = /^(\d{1,3})(?:\.(\d{1,6}))?$/.exec(text);
  if (match === null) throw new Error(`The amount must be a QOR number with at most 6 decimals. ${USAGE}`);
  const uqor = BigInt(match[1]!) * UQOR_PER_QOR + BigInt((match[2] ?? "").padEnd(6, "0"));
  if (uqor <= 0n) throw new Error("The amount must be above 0.");
  if (uqor > MAX_AMOUNT_UQOR) throw new Error(`Refusing to send ${formatQor(uqor)} QOR: one run sends at most ${formatQor(MAX_AMOUNT_UQOR)} QOR.`);
  return uqor;
}

async function balanceOf(address: string): Promise<bigint> {
  const body = await getJson<{ balances?: unknown }>(`${REST}/cosmos/bank/v1beta1/balances/${encodeURIComponent(address)}`, HTTP);
  if (!Array.isArray(body.balances)) throw new Error("Unexpected balance answer: no balances list.");
  const coin = body.balances.find((c: { denom?: unknown }) => c?.denom === DENOM) as { amount?: unknown } | undefined;
  if (coin === undefined) return 0n;
  if (typeof coin.amount !== "string" || !/^\d{1,40}$/.test(coin.amount)) throw new Error("Unexpected balance amount.");
  return BigInt(coin.amount);
}

async function main(): Promise<void> {
  const chainId = await assertTestnet();

  const now = Date.now();
  if (now >= DRILL_DAY_START && now < DRILL_DAY_START + DAY_MS) {
    throw new Error("Refusing to move funds on drill day (18 Nov 2026 UTC): the drill account keeps its value for the Q-Day Drill.");
  }

  const [to, amount, ...extra] = process.argv.slice(2);
  if (to === undefined || amount === undefined || extra.length > 0) throw new Error(USAGE);
  const recipient = bytesToBech32(recipientBytes(to), "qor");
  const uqor = amountUqor(amount);

  const account = await deriveDrillAccount(requireMnemonic());
  if (recipient === account.qor1) throw new Error("The recipient is the drill account itself. Nothing to do.");

  const status = await readStatus(account);
  if (!status.pq.found || status.pq.matchesOurKey !== true || status.pq.possessionProven !== true) {
    throw new Error("The drill account's ML-DSA-87 key is not registered as this phrase's key with possession proven. Run: npm run register");
  }
  if (status.balanceUqor < uqor + MAX_FEE_UQOR) {
    throw new Error(`Balance ${formatQor(status.balanceUqor)} QOR does not cover ${formatQor(uqor)} QOR plus the ${formatQor(MAX_FEE_UQOR)} QOR fee cap.`);
  }

  const messages: Messages = [
    { typeUrl: MSG_SEND_TYPE_URL, value: { fromAddress: account.qor1, toAddress: recipient, amount: [{ denom: DENOM, amount: uqor.toString() }] } },
  ];

  console.log(`chain id:  ${chainId} confirmed`);
  console.log(`message:   ${MSG_SEND_TYPE_URL} (signed hybrid: eth_secp256k1 plus ML-DSA-87)`);
  console.log(`  from:    ${account.qor1}`);
  console.log(`  to:      ${recipient}`);
  console.log(`  amount:  ${uqor} ${DENOM} (${formatQor(uqor)} QOR)`);
  console.log(`  fee:     ${FEE_RULE}`);

  const tx = await sendTx(account, "hybrid", messages, MEMO);
  console.log(`tx hash:   ${tx.hash}`);
  console.log(`result:    code 0, pqc_hybrid_verify verified; height ${tx.height}, gas used ${tx.gasUsed} of ${tx.gasWanted}, fee ${tx.fee.amount[0]!.amount} uqor`);

  const [fromAfter, toAfter] = await Promise.all([balanceOf(account.qor1), balanceOf(recipient)]);
  console.log(`balance:   ${account.qor1} now ${formatQor(fromAfter)} QOR`);
  console.log(`balance:   ${recipient} now ${formatQor(toAfter)} QOR`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
