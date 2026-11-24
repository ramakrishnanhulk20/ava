import { useSyncExternalStore } from "react";
import { decodeAbiParameters, encodeFunctionData } from "viem";
import { client, useDemoBoard, type DemoBoard } from "./chain";

const PQC_STATUS_ADDRESS = "0x0000000000000000000000000000000000000a02";
const REFRESH_MS = 30_000;
// An inactive precompile answers success with empty data, which would otherwise read as "not registered".
const MIN_STATUS_BYTES = 160;

const pqcKeyStatusAbi = [
  {
    type: "function",
    name: "pqcKeyStatus",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [
      { name: "registered", type: "bool" },
      { name: "algorithmId", type: "uint8" },
      { name: "pubkey", type: "bytes" },
      { name: "possessionProven", type: "bool" },
    ],
  },
] as const;

export const DRILL_QOR1 = process.env.NEXT_PUBLIC_DRILL_ACCOUNT_QOR1 ?? "";
export const DRILL_EVM = process.env.NEXT_PUBLIC_DRILL_ACCOUNT_EVM ?? "";

export type KeyStatus = "none" | "unproven" | "proven";

type Store = { key: KeyStatus | null; failing: boolean };

const EMPTY: Store = { key: null, failing: false };

let store: Store = EMPTY;
const listeners = new Set<() => void>();
let timer: ReturnType<typeof setInterval> | undefined;

function publish(next: Store) {
  store = next;
  for (const listener of listeners) listener();
}

async function readKey() {
  try {
    const { data } = await client.call({
      to: PQC_STATUS_ADDRESS,
      data: encodeFunctionData({
        abi: pqcKeyStatusAbi,
        functionName: "pqcKeyStatus",
        args: [DRILL_EVM as `0x${string}`],
      }),
    });
    if (data === undefined || (data.length - 2) / 2 < MIN_STATUS_BYTES)
      throw new Error("pqcKeyStatus answered with empty or short data.");
    const [registered, , , possessionProven] = decodeAbiParameters(pqcKeyStatusAbi[0].outputs, data);
    const key: KeyStatus = !registered ? "none" : possessionProven ? "proven" : "unproven";
    publish({ key, failing: false });
  } catch {
    publish({ ...store, failing: true });
  }
}

function start() {
  void readKey();
  timer = setInterval(() => void readKey(), REFRESH_MS);
}

function stop() {
  clearInterval(timer);
  timer = undefined;
}

function onVisibility() {
  if (document.visibilityState === "hidden") stop();
  else if (timer === undefined) start();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  if (listeners.size === 1) {
    document.addEventListener("visibilitychange", onVisibility);
    if (document.visibilityState === "visible") start();
  }
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      document.removeEventListener("visibilitychange", onVisibility);
      stop();
    }
  };
}

export type DrillAccount = {
  qor1: string;
  evm: string;
  /** The ML-DSA-87 key's state, or null until the first read answers. */
  key: KeyStatus | null;
  /** True when the last read of the key failed. The earlier answer, if any, stays on show. */
  keyFailing: boolean;
  board: DemoBoard;
};

export function useDrillAccount(): DrillAccount {
  const snapshot = useSyncExternalStore(
    subscribe,
    () => store,
    () => EMPTY,
  );
  const board = useDemoBoard();
  return { qor1: DRILL_QOR1, evm: DRILL_EVM, key: snapshot.key, keyFailing: snapshot.failing, board };
}

const KEY_TEXT: Record<KeyStatus, string> = {
  none: "NOT REGISTERED",
  unproven: "REGISTERED · POSSESSION NOT PROVEN",
  proven: "REGISTERED · POSSESSION PROVEN",
};

/** The honest line for a live value: the value, a wait label, or a failure label. Never a made-up number. */
export function liveText(value: string | null, failing: boolean): string {
  if (value === null) return failing ? "NOT ANSWERING · RETRYING" : "READING THE CHAIN";
  return failing ? `${value} · RETRYING` : value;
}

export function keyText(key: KeyStatus | null): string | null {
  return key === null ? null : KEY_TEXT[key];
}

/** "qor1g7rde5…4hpfwy": the first ten and the last six characters. */
export function shortQor1(address: string): string {
  return address.length > 16 ? `${address.slice(0, 10)}…${address.slice(-6)}` : address;
}
