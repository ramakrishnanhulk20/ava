// Real ML-DSA-87 signatures for Foundry tests, run through vm.ffi.
// Usage: node test/ffi/sign.mjs <32-byte seed as 0x hex> <message as 0x hex>
// Derives the key pair from the seed, signs the message (pure ML-DSA-87, empty context, no prehash,
// deterministic, the form QoreChain's pqcVerify checks), verifies the signature itself, and prints
// abi.encode(bytes pubkey, bytes signature) as 0x hex. Any bad input or failed check exits with code 1
// and prints nothing on stdout, so a test can never receive a signature this script did not verify.
// The seed is a test fixture only: never pass a real key's seed on a command line.
import { mldsa87 } from "@qorechain/pqc";
import { bytesToHex, encodeAbiParameters, hexToBytes, isHex } from "viem";

function fail(reason) {
  process.stderr.write(`sign.mjs: ${reason}\n`);
  process.exit(1);
}

const args = process.argv.slice(2);
if (args.length !== 2) fail("expected exactly two arguments: <seed hex> <message hex>");
const [seedHex, messageHex] = args;
if (!isHex(seedHex, { strict: true }) || seedHex.length !== 66) fail("seed must be 32 bytes as 0x hex");
if (!isHex(messageHex, { strict: true }) || messageHex.length % 2 !== 0) fail("message must be 0x hex");

const message = hexToBytes(messageHex);
const { publicKey, secretKey } = mldsa87.keygen(hexToBytes(seedHex));
const signature = mldsa87.sign(secretKey, message);
if (publicKey.length !== 2592) fail(`public key is ${publicKey.length} bytes, not 2592`);
if (signature.length !== 4627) fail(`signature is ${signature.length} bytes, not 4627`);
if (!mldsa87.verify(publicKey, message, signature)) fail("the signature does not verify under its own key");

process.stdout.write(
  encodeAbiParameters([{ type: "bytes" }, { type: "bytes" }], [bytesToHex(publicKey), bytesToHex(signature)]),
);
