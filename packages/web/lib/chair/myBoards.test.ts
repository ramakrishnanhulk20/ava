// Covers how the page keeps the list of boards that name an account: which block ranges it reads,
// how new finds fold into what it already knew, and what it accepts back from the browser's storage.
// Does NOT cover the log reads themselves or the registry (the live run does), and the list is public
// chain data, so nothing here is a secret.
import { describe, expect, it } from "vitest";
import { mergeBoards, pagesBetween, parseSeen, serialiseSeen } from "./myBoards";

describe("pagesBetween", () => {
  it("covers every block from the first to the last exactly once, in pages of the given size", () => {
    expect(pagesBetween(100n, 129n, 10n)).toEqual([
      { from: 100n, to: 109n },
      { from: 110n, to: 119n },
      { from: 120n, to: 129n },
    ]);
    expect(pagesBetween(100n, 125n, 10n).at(-1)).toEqual({ from: 120n, to: 125n });
    expect(pagesBetween(7n, 7n, 10n)).toEqual([{ from: 7n, to: 7n }]);
  });

  it("reads nothing when there is nothing new", () => {
    expect(pagesBetween(8n, 7n, 10n)).toEqual([]);
  });
});

describe("mergeBoards", () => {
  it("adds new boards to the ones already known, each once, lowest first", () => {
    const known = { through: 500n, chaired: [42n], joined: [15n] };
    expect(mergeBoards(known, { through: 900n, chaired: [44n, 42n], joined: [15n, 7n] })).toEqual({ through: 900n, chaired: [42n, 44n], joined: [7n, 15n] });
  });

  it("starts from nothing on a first read", () => {
    expect(mergeBoards(undefined, { through: 900n, chaired: [], joined: [15n] })).toEqual({ through: 900n, chaired: [], joined: [15n] });
  });

  it("never moves the point it has read through backwards", () => {
    expect(mergeBoards({ through: 900n, chaired: [], joined: [] }, { through: 800n, chaired: [1n], joined: [] }).through).toBe(900n);
  });
});

describe("parseSeen", () => {
  it("reads back exactly what serialiseSeen wrote", () => {
    const seen = { through: 10_603_900n, chaired: [40n, 41n, 42n], joined: [15n] };
    expect(parseSeen(serialiseSeen(seen))).toEqual(seen);
  });

  it("takes nothing it cannot read as a list: missing, malformed or the wrong shape", () => {
    for (const raw of [null, "", "not json", "[]", '{"through":"x","chaired":[],"joined":[]}', '{"through":"5","chaired":["-1"],"joined":[]}', '{"through":"5","chaired":"42","joined":[]}', '{"through":"5","chaired":[42],"joined":[]}']) {
      expect(parseSeen(raw)).toBeUndefined();
    }
  });
});
