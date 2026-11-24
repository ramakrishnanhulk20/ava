// Covers what the board room works out from a board's history (threat model C38): who sits on the
// board according to its events, whether that agrees with the registry's own member list, and what it
// accepts back from the browser's storage, and which pages of the chain's history it asks for. Does
// NOT cover the log reads themselves (the live run does) or the rule for who can open which pack
// (boardRules, used here as it is).
import { describe, expect, it } from "vitest";
import type { HistoryEvent } from "../boardRules";
import { membersFromEvents, parseHistory, readBackToCreation, sameMembers, serialiseHistory } from "./history";

const CHAIR = "0x1111111111111111111111111111111111111111";
const ASHA = "0x2222222222222222222222222222222222222222";
const BEN = "0x3333333333333333333333333333333333333333";
const tx = (n: number): `0x${string}` => `0x${n.toString(16).padStart(64, "0")}`;

const events: HistoryEvent[] = [
  { name: "BoardCreated", chair: CHAIR, tx: tx(1), block: 100, index: 0 },
  { name: "EnvelopeGranted", epoch: 0, mode: 1, member: "0x0000000000000000000000000000000000000000", tx: tx(1), block: 100, index: 1 },
  { name: "MemberAdded", member: ASHA, epoch: 0, mode: 0, tx: tx(2), block: 110, index: 0 },
  { name: "MemberAdded", member: BEN, epoch: 1, mode: 1, tx: tx(3), block: 120, index: 0 },
  { name: "DocumentPosted", docId: 0, epoch: 1, tx: tx(4), block: 130, index: 0 },
  { name: "MemberRemoved", member: ASHA, newEpoch: 2, tx: tx(5), block: 140, index: 0 },
];

describe("membersFromEvents", () => {
  it("lists the chair and everyone added and not removed since", () => {
    expect(membersFromEvents(events).sort()).toEqual([CHAIR, BEN].sort());
  });

  it("counts someone added again after a removal as a member", () => {
    const again: HistoryEvent[] = [...events, { name: "MemberAdded", member: ASHA, epoch: 2, mode: 0, tx: tx(6), block: 150, index: 0 }];
    expect(membersFromEvents(again).sort()).toEqual([CHAIR, ASHA, BEN].sort());
  });

  it("is empty for a history with no creation in it", () => {
    expect(membersFromEvents([])).toEqual([]);
  });
});

describe("sameMembers", () => {
  it("agrees whatever the order and the letter case", () => {
    expect(sameMembers([CHAIR, BEN], [BEN.toUpperCase().replace("0X", "0x"), CHAIR])).toBe(true);
  });

  it("disagrees when one is missing, one is extra or one appears twice", () => {
    expect(sameMembers([CHAIR, BEN], [CHAIR])).toBe(false);
    expect(sameMembers([CHAIR], [CHAIR, BEN])).toBe(false);
    expect(sameMembers([CHAIR, CHAIR], [CHAIR, BEN])).toBe(false);
  });
});

describe("readBackToCreation", () => {
  const pages = Array.from({ length: 10 }, (_, i) => ({ from: BigInt(i * 100), to: BigInt(i * 100 + 99) }));
  const created = (block: number): HistoryEvent => ({ name: "BoardCreated", chair: CHAIR, tx: tx(block), block, index: 0 });
  const posted = (block: number): HistoryEvent => ({ name: "DocumentPosted", docId: block, epoch: 0, tx: tx(block), block, index: 0 });

  function chain(all: HistoryEvent[]) {
    const asked: number[] = [];
    const read = async (range: { from: bigint; to: bigint }): Promise<HistoryEvent[]> => {
      asked.push(Number(range.from) / 100);
      return all.filter((event) => BigInt(event.block) >= range.from && BigInt(event.block) <= range.to);
    };
    return { asked, read };
  }

  it("returns everything from the creation to the newest page, and never asks for the pages far below it", async () => {
    const all = [posted(120), created(710), posted(745), posted(830), posted(990)];
    const { asked, read } = chain(all);
    const found = await readBackToCreation(pages, read, () => undefined);
    expect(found.map((event) => event.block).sort((a, b) => a - b)).toEqual([710, 745, 830, 990]);
    expect(asked).toEqual(expect.arrayContaining([9, 8, 7]));
    // Four pages are asked for at once, so the three below the creation's may already be on their way.
    expect(Math.min(...asked)).toBeGreaterThanOrEqual(4);
  });

  it("stops after its first round when the board was made in the newest page", async () => {
    const { asked, read } = chain([posted(120), created(950), posted(960)]);
    const found = await readBackToCreation(pages, read, () => undefined);
    expect(found.map((event) => event.block)).toEqual([950, 960]);
    expect([...asked].sort((a, b) => a - b)).toEqual([6, 7, 8, 9]);
  });

  it("reads every page when none holds a creation, as when continuing an earlier read", async () => {
    const { asked, read } = chain([posted(15), posted(480), posted(990)]);
    const found = await readBackToCreation(pages, read, () => undefined);
    expect(found.map((event) => event.block).sort((a, b) => a - b)).toEqual([15, 480, 990]);
    expect([...asked].sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });

  it("fails as a whole when one page cannot be read", async () => {
    const read = async (range: { from: bigint; to: bigint }): Promise<HistoryEvent[]> => {
      if (range.from === 800n) throw new Error("page lost");
      return [];
    };
    await expect(readBackToCreation(pages, read, () => undefined)).rejects.toThrow("page lost");
  });

  it("counts only the pages that matter, and ends with all of them read", async () => {
    const { read } = chain([created(710), posted(990)]);
    const told: [number, number][] = [];
    await readBackToCreation(pages, read, (done, total) => told.push([done, total]));
    expect(told[0]).toEqual([0, 10]);
    expect(told.at(-1)).toEqual([3, 3]);
    for (const [done, total] of told) expect(done).toBeLessThanOrEqual(total);
  });

  it("reads nothing for no pages", async () => {
    const { asked, read } = chain([]);
    expect(await readBackToCreation([], read, () => undefined)).toEqual([]);
    expect(asked).toEqual([]);
  });
});

describe("parseHistory", () => {
  it("reads back exactly what serialiseHistory wrote", () => {
    const read = { through: 10_603_900n, events };
    expect(parseHistory(serialiseHistory(read))).toEqual(read);
  });

  it("takes nothing it cannot read as a history: missing, malformed, or an event of an unknown kind or shape", () => {
    const good = JSON.parse(serialiseHistory({ through: 5n, events })) as { through: string; events: Record<string, unknown>[] };
    const withEvent = (event: Record<string, unknown>): string => JSON.stringify({ through: "5", events: [event] });
    for (const raw of [
      null,
      "",
      "{}",
      "not json",
      JSON.stringify({ ...good, through: "x" }),
      JSON.stringify({ ...good, events: "none" }),
      withEvent({ name: "Surprise", tx: tx(1), block: 1, index: 0 }),
      withEvent({ name: "MemberAdded", member: "not an address", epoch: 0, mode: 0, tx: tx(1), block: 1, index: 0 }),
      withEvent({ name: "MemberRemoved", member: ASHA, newEpoch: "2", tx: tx(1), block: 1, index: 0 }),
      withEvent({ name: "BoardCreated", chair: CHAIR, tx: "0x12", block: 1, index: 0 }),
      withEvent({ name: "DocumentPosted", docId: 0, epoch: 1, tx: tx(1), block: -1, index: 0 }),
    ]) {
      expect(parseHistory(raw)).toBeUndefined();
    }
  });
});
