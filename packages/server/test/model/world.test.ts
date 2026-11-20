// Not covered here: anything random. This only proves the model's world drives the real handlers
// end to end, one public relay and one demo join, before the randomised runs in invariants.test.ts
// lean on it.
import { challengeMessage, signAction, toHex } from "@ava/core";
import { bytesToHex, hexToBytes, type Hex } from "viem";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { REGISTRY_ADDRESS } from "../../src/config.ts";
import { admittedKey, handleDemoChallenge, handleDemoJoin } from "../../src/demo.ts";
import { handleRelay } from "../../src/relay.ts";
import { CLIENT_IPS, DEMO_BOARD, World, appRequest, makeCast, rotateBody, type Cast } from "./world.ts";

// The bot derives the demo chair's keys from its phrase on every join and removal. The same
// derivation, cached, gives the same keys and keeps the model's thousands of runs inside minutes.
vi.mock("@ava/core", async (importOriginal) => {
  const real = await importOriginal<typeof import("@ava/core")>();
  const derived = new Map<string, ReturnType<typeof real.identityFromMnemonic>>();
  return {
    ...real,
    identityFromMnemonic: (phrase: string) => {
      const known = derived.get(phrase) ?? real.identityFromMnemonic(phrase);
      derived.set(phrase, known);
      return known;
    },
  };
});

let cast: Cast;

beforeAll(async () => {
  cast = await makeCast(1, 2);
}, 60_000);

beforeEach(() => {
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("the model's world", () => {
  it("relays one public chair action to the chain, which lands it and moves the board's nonce", async () => {
    const world = await World.create(cast, { fillers: 0, fillerStepMinutes: 20, tightLimits: false, demoRelaysPerHour: 120, preSpend: 0 });
    world.begin("relay");
    const response = await handleRelay(appRequest("/api/relay", rotateBody(world, 1n, 10n, 1)), world.relayContext(CLIENT_IPS[0]));
    world.end();
    expect(response.status).toBe(202);
    const { txHash } = (await response.json()) as { txHash: Hex };
    expect(world.status(txHash)).toBe("landed");
    expect(world.board(1n).nonce).toBe(11n);
    expect(await world.store.get("rate:relay:valid")).toBe("1");
  });

  it("admits one guest through a challenge and a signed join, and the add lands on the demo board", async () => {
    const world = await World.create(cast, { fillers: 2, fillerStepMinutes: 20, tightLimits: false, demoRelaysPerHour: 120, preSpend: 0 });
    const guest = cast.guests[0];
    if (guest === undefined) throw new Error("The cast has no guest.");
    world.begin("join");
    const ctx = world.demoContext(CLIENT_IPS[1]);
    const challenge = (await (await handleDemoChallenge(appRequest("/api/demo/challenge", { guest: guest.qor1 }), ctx)).json()) as { botNonce: Hex; expiry: string };
    const message = challengeMessage({ registry: REGISTRY_ADDRESS, boardId: DEMO_BOARD, guest: toHex(guest.account), botNonce: challenge.botNonce, expiry: BigInt(challenge.expiry) });
    const body = { guest: guest.evm, botNonce: challenge.botNonce, expiry: challenge.expiry, signature: bytesToHex(signAction(guest.mldsa.secretKey, message)) };
    const response = await handleDemoJoin(appRequest("/api/demo/join", body), ctx);
    world.end();
    expect(response.status).toBe(202);
    expect(world.isMember(DEMO_BOARD, guest.evm)).toBe(true);
    expect(await world.store.get(admittedKey(hexToBytes(guest.evm)))).not.toBeNull();
  });
});
