import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fetchEvmWindow, getJson, withRetry } from "@qorechain/sdk";
import { keccak256, stringToBytes, type Hex } from "viem";
import { deriveDeployer } from "./account.js";
import { assertTestnet, evmClient } from "./chain.js";
import { EVM_CHAIN_ID, EXPLORER, HTTP, REST, requireMnemonic } from "./env.js";
import { assertBudget, balanceOf, describeWindow, evmFeeUqor, fees, formatQor, openWindow, sendEvm, windowSpendCap, windowValueFor, withHeadroom } from "./lib/evm.js";
import { PACKAGE_ROOT, fromRpc, loadRegistryArtifact, recordedRegistry, saveRegistry, type RegistryArtifact } from "./lib/registry.js";

const SOURCIFY = "https://sourcify.dev/server";
const CONTRACT_ID = "src/BoardRegistry.sol:BoardRegistry";
const SOURCIFY_POLL_TRIES = 30;
const SOURCIFY_POLL_MS = 3_000;
// The explorer's pages load a few dozen script chunks; this bounds what the evidence check fetches.
const MAX_EXPLORER_CHUNKS = 60;
const MAX_TEXT_BYTES = 4_000_000;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function fetchText(url: string): Promise<{ status: number; text: string }> {
  return withRetry(
    async () => {
      const res = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(HTTP.timeoutMs) });
      const text = await res.text();
      if (text.length > MAX_TEXT_BYTES) throw new Error(`${url} answered more than ${MAX_TEXT_BYTES} bytes.`);
      return { status: res.status, text };
    },
    { retries: HTTP.retries, backoff: HTTP.retryDelayMs },
  );
}

/**
 * The standard JSON input Sourcify recompiles: the build's own solc settings, and every source the
 * metadata names, read from disk and refused unless its keccak256 is the one the build compiled.
 */
function standardJsonInput(artifact: RegistryArtifact): Record<string, unknown> {
  const sources: Record<string, { content: string }> = {};
  for (const [path, info] of Object.entries(artifact.metadata.sources)) {
    const disk = readFileSync(join(PACKAGE_ROOT, path), "utf8");
    // A Windows checkout can carry CRLF line endings the build did not compile; the build's own
    // keccak256 decides which of the two forms is sent, and anything else is refused.
    const content = [disk, disk.replace(/\r\n/g, "\n")].find((c) => keccak256(stringToBytes(c)) === info.keccak256);
    if (content === undefined) throw new Error(`${path} on disk is not the file this build compiled. Run forge build first.`);
    sources[path] = { content };
  }
  const { compilationTarget: _target, ...settings } = artifact.metadata.settings;
  return {
    language: artifact.metadata.language,
    sources,
    settings: { ...settings, outputSelection: { "*": { "*": ["abi", "evm.bytecode", "evm.deployedBytecode", "metadata"] } } },
  };
}

/** Sourcify: verified only for a chain it lists. Otherwise "not available" with its own chain list as the evidence. */
async function sourcify(address: Hex, deployTx: Hex, artifact: RegistryArtifact): Promise<string> {
  const chains = await getJson<unknown>(`${SOURCIFY}/chains`, HTTP);
  if (!Array.isArray(chains)) throw new Error(`${SOURCIFY}/chains did not answer with a list.`);
  const listed = chains.find((c: { chainId?: unknown }) => c?.chainId === EVM_CHAIN_ID) as { name?: unknown; supported?: unknown } | undefined;
  if (listed === undefined) return `not available: ${SOURCIFY}/chains lists ${chains.length} chains and chain ${EVM_CHAIN_ID} is not among them`;
  if (listed.supported !== true) return `not available: ${SOURCIFY}/chains lists chain ${EVM_CHAIN_ID} (${String(listed.name)}) with supported ${String(listed.supported)}`;

  const res = await fetch(`${SOURCIFY}/v2/verify/${EVM_CHAIN_ID}/${address}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ stdJsonInput: standardJsonInput(artifact), compilerVersion: artifact.compilerVersion, contractIdentifier: CONTRACT_ID, creationTransactionHash: deployTx }),
    redirect: "error",
    signal: AbortSignal.timeout(60_000),
  });
  const submitted = (await res.json().catch(() => ({}))) as { verificationId?: unknown; customCode?: unknown; message?: unknown };
  if (res.status !== 202 || typeof submitted.verificationId !== "string") {
    return `not verified: POST /v2/verify answered HTTP ${res.status} ${String(submitted.customCode ?? "")} ${String(submitted.message ?? "").slice(0, 200)}`;
  }
  for (let i = 0; i < SOURCIFY_POLL_TRIES; i++) {
    await sleep(SOURCIFY_POLL_MS);
    const job = await getJson<{ isJobCompleted?: unknown; contract?: { match?: unknown }; error?: { customCode?: unknown; message?: unknown } }>(
      `${SOURCIFY}/v2/verify/${submitted.verificationId}`,
      HTTP,
    );
    if (job.isJobCompleted !== true) continue;
    if (job.contract?.match === "match" || job.contract?.match === "exact_match") return `verified: Sourcify job ${submitted.verificationId}, ${String(job.contract.match)}`;
    return `not verified: Sourcify job ${submitted.verificationId} ended ${String(job.error?.customCode ?? "")} ${String(job.error?.message ?? "").slice(0, 200)}`;
  }
  return `not verified yet: Sourcify job ${submitted.verificationId} still running after ${(SOURCIFY_POLL_TRIES * SOURCIFY_POLL_MS) / 1000} s`;
}

/**
 * The explorer at EXPLORER is a Next.js app. The evidence is its own shipped code: every `/api/...`
 * route the home page and the contract's address page call. Only a route about source code or
 * verification could take a submission.
 */
async function explorer(address: Hex): Promise<string> {
  const pages = [`${EXPLORER}/`, `${EXPLORER}/address/${address}`];
  const chunks = new Set<string>();
  for (const page of pages) {
    const { status, text } = await fetchText(page);
    if (status !== 200) throw new Error(`${page} answered HTTP ${status}.`);
    for (const m of text.matchAll(/["'](\/_next\/static\/chunks\/[A-Za-z0-9_.~-]+\.js)["']/g)) chunks.add(m[1]!);
  }
  if (chunks.size === 0 || chunks.size > MAX_EXPLORER_CHUNKS) throw new Error(`The explorer pages name ${chunks.size} script chunks; expected 1 to ${MAX_EXPLORER_CHUNKS}.`);
  const routes = new Set<string>();
  for (const chunk of chunks) {
    const { text } = await fetchText(`${EXPLORER}${chunk}`);
    for (const m of text.matchAll(/["'`](\/api\/[A-Za-z0-9_${}./-]*)["'`]/g)) routes.add(m[1]!.replace(/\$\{[^}]*\}/g, "{param}"));
  }
  const listed = [...routes].sort().join(", ");
  const submitRoutes = [...routes].filter((r) => /verif|source|solc|compile/i.test(r));
  if (submitRoutes.length === 0) {
    return `not available: the explorer's code (${chunks.size} script chunks of its home and address pages) calls only ${listed}; none takes source code`;
  }
  return `not attempted: the explorer's code names ${submitRoutes.join(", ")}, and no document we hold says what it accepts`;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.some((a) => a !== "--new")) throw new Error(`Unknown argument. The only option is --new.`);
  const replace = args.includes("--new");

  const chainId = await assertTestnet();
  console.log(`chain id:   ${chainId} confirmed (EVM chain id ${EVM_CHAIN_ID})`);
  const artifact = loadRegistryArtifact();
  const existing = recordedRegistry();
  if (existing !== undefined && !replace) {
    throw new Error(`deployments/testnet.json already records BoardRegistry at ${existing.address} (tx ${existing.deployTx}). Refusing to deploy again. Run with --new to deploy another and replace the record.`);
  }
  if (existing !== undefined) console.log(`replacing:  the recorded BoardRegistry at ${existing.address} (--new)`);

  const deployer = await deriveDeployer(requireMnemonic());
  const client = evmClient();
  const startBalance = await balanceOf(deployer.qor1);
  console.log(`deployer:   ${deployer.qor1} / ${deployer.evm}, ${formatQor(startBalance)} QOR`);
  console.log(`build:      solc ${artifact.compilerVersion}, ${(artifact.bytecode.length - 2) / 2}-byte creation code, ${(artifact.deployedBytecode.length - 2) / 2}-byte runtime code`);

  const gas = withHeadroom(await client.estimateGas({ account: deployer.evm, data: artifact.bytecode }));
  const fee = await fees(client);
  const maxValue = windowValueFor(gas, fee);
  await assertBudget(deployer, windowSpendCap(maxValue), "the deploy");
  const window = await openWindow(deployer, maxValue, []);
  console.log(`window:     ${describeWindow(window, "unscoped (a contract creation needs it)")}`);

  const { hash, receipt } = await sendEvm(client, deployer, { data: artifact.bytecode, gas, ...fee });
  if (receipt.status !== "success" || receipt.contractAddress == null) throw new Error(`Deploy ${hash} did not succeed.`);
  const address = fromRpc(receipt.contractAddress);
  console.log(`deploy tx:  ${hash}, block ${receipt.blockNumber}, gas used ${receipt.gasUsed} of ${gas}, fee ${formatQor(evmFeeUqor(receipt))} QOR`);
  console.log(`address:    ${address}`);

  const code = await client.getCode({ address });
  if (code === undefined || code.toLowerCase() !== artifact.deployedBytecode.toLowerCase()) throw new Error(`The code at ${address} differs from the compiled runtime code.`);
  const runtimeCodeHash = keccak256(code);
  console.log(`code:       the deployed runtime code equals the compiled runtime code, byte for byte: yes (keccak256 ${runtimeCodeHash})`);

  saveRegistry({ address, deployTx: hash, blockNumber: receipt.blockNumber.toString(), deployer: deployer.evm, runtimeCodeHash, solcVersion: artifact.compilerVersion });
  console.log("recorded:   deployments/testnet.json BoardRegistry (address, deploy tx, block, deployer, runtime code hash, solc version)");

  const after = await withRetry(() => fetchEvmWindow({ rest: REST, address: deployer.qor1 }), { retries: 4, backoff: 2_000 });
  console.log(`window now: ${after.remainingTxs} txs and ${after.remainingValue} uqor left, live ${after.live}`);

  console.log(`sourcify:   ${await sourcify(address, hash, artifact)}`);
  console.log(`explorer:   ${await explorer(address)}`);
  console.log(`            ${EXPLORER}/address/${address} (switch to Testnet)`);
  const endBalance = await balanceOf(deployer.qor1);
  console.log(`spent:      ${formatQor(startBalance - endBalance)} QOR realised (window fee plus deploy fee); deployer now ${formatQor(endBalance)} QOR`);
}

main().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
