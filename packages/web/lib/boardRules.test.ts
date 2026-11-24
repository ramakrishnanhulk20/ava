// Covers the ledger's rule for who can open which pack (threat model C38): it works from the epochs
// a key was sealed to someone in, never from dates. The named checks live in boardRules.check.ts,
// which the dev server also runs in the browser; this runs them with the suite and adds the cases
// the exposure rule is easiest to get wrong. Does NOT cover reading the events from the chain.
import { describe, expect, it } from "vitest";
import { buildProofModel, stateAt, tenuresByMember, type Address, type Director, type HistoryEvent, type PackInfo } from "./boardRules";
import { runRuleChecks } from "./boardRules.check";

const addr = (n: number) => `0x${n.toString(16).padStart(40, "0")}` as Address;
const tx = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as `0x${string}`;
const CHAIR = addr(1);
const DANA = addr(2);
const NOBODY = addr(0);

describe("the ledger's rules", () => {
  it("pass every named check", () => {
    const passed = runRuleChecks();
    expect(passed).toHaveLength(13);
    expect(new Set(passed).size).toBe(passed.length);
  });

  // The board of the live walk: three packs in epoch 0, a director let into epoch 0 afterwards with
  // the current key, then removed into epoch 1, then a fourth pack.
  const events: HistoryEvent[] = [
    { name: "BoardCreated", chair: CHAIR, tx: tx(1), block: 10, index: 0 },
    { name: "EnvelopeGranted", epoch: 0, mode: 1, member: NOBODY, tx: tx(1), block: 10, index: 1 },
    { name: "DocumentPosted", docId: 0, epoch: 0, tx: tx(2), block: 20, index: 0 },
    { name: "DocumentPosted", docId: 1, epoch: 0, tx: tx(3), block: 30, index: 0 },
    { name: "DocumentPosted", docId: 2, epoch: 0, tx: tx(4), block: 40, index: 0 },
    { name: "MemberAdded", member: DANA, epoch: 0, mode: 0, tx: tx(5), block: 50, index: 0 },
    { name: "EnvelopeGranted", epoch: 0, mode: 0, member: DANA, tx: tx(5), block: 50, index: 1 },
    { name: "MemberRemoved", member: DANA, newEpoch: 1, tx: tx(6), block: 60, index: 0 },
    { name: "EnvelopeGranted", epoch: 1, mode: 1, member: NOBODY, tx: tx(6), block: 60, index: 1 },
    { name: "DocumentPosted", docId: 3, epoch: 1, tx: tx(7), block: 70, index: 0 },
  ];
  const packs: PackInfo[] = [
    { index: 0, epoch: 0, postedAt: 100 },
    { index: 1, epoch: 0, postedAt: 200 },
    { index: 2, epoch: 0, postedAt: 300 },
    { index: 3, epoch: 1, postedAt: 700 },
  ];
  const directors: Director[] = [
    { name: "Chair", address: CHAIR },
    { name: "Dana", address: DANA },
  ];
  const model = buildProofModel(events, packs, directors, CHAIR);
  const row = (name: string) => model.rows.find((found) => found.director.name === name);

  it("count a director let into an epoch as a reader of the packs posted in it before they came", () => {
    expect(row("Dana")?.cells.map((cell) => cell.state)).toEqual(["open", "open", "open", "locked"]);
  });

  it("point each of those cells at the transaction that let them in, and the locked one at the removal", () => {
    expect(row("Dana")?.cells.map((cell) => cell.tx)).toEqual([tx(5), tx(5), tx(5), tx(6)]);
  });

  it("keep the chair open throughout, and report nothing opened after the removal", () => {
    expect(row("Chair")?.cells.map((cell) => cell.state)).toEqual(["open", "open", "open", "open"]);
    expect(model.proof.opened).toBe(0);
    expect(model.proof.kept).toBe(3);
    expect(model.proof.removal?.tx).toBe(tx(6));
  });

  it("answer from the epoch alone: a pack dated before the join is still open, one dated after the removal still locked", () => {
    const dana = tenuresByMember(events).get(DANA.toLowerCase()) ?? [];
    expect(dana).toHaveLength(1);
    expect(stateAt(dana, 0)).toBe("open");
    expect(stateAt(dana, 1)).toBe("locked");
    const redated = buildProofModel(
      events,
      packs.map((pack) => ({ ...pack, postedAt: 1_000 - pack.postedAt })),
      directors,
      CHAIR,
    );
    expect(redated.rows.find((found) => found.director.name === "Dana")?.cells.map((cell) => cell.state)).toEqual(["open", "open", "open", "locked"]);
  });
});
