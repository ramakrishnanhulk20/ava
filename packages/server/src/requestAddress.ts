// Addresses that arrive in a request use the strict decoder; values read from the chain use the
// lenient one (threat model C16).
export { accountBytesStrict } from "@ava/core";
