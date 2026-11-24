import {
  buildProofModel,
  stateAt,
  type Address,
  type Director,
  type HistoryEvent,
  type PackInfo,
  type Tenure,
} from "./boardRules";

const addr = (n: number) => `0x${n.toString(16).padStart(40, "0")}` as Address;
const tx = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as `0x${string}`;

const CHAIR = addr(1);
const ASHA = addr(2);
const BEN = addr(3);
const CHEN = addr(4);
const GUEST_A = addr(10);
const GUEST_B = addr(11);

let block = 100;
const at = (txNumber: number) => ({ tx: tx(txNumber), block: block++, index: 0 });

// The same shape as the demo board: the chair creates it, Asha and Ben join by rotation, Chen joins
// by a single envelope in epoch 2, and Chen is removed into epoch 3.
const events: HistoryEvent[] = [
  { name: "BoardCreated", chair: CHAIR, ...at(1) },
  { name: "EnvelopeGranted", epoch: 0, mode: 1, member: addr(0), ...at(1) },
  { name: "MemberAdded", member: ASHA, epoch: 1, mode: 1, ...at(2) },
  { name: "EnvelopeGranted", epoch: 1, mode: 1, member: addr(0), ...at(2) },
  { name: "MemberAdded", member: BEN, epoch: 2, mode: 1, ...at(3) },
  { name: "EnvelopeGranted", epoch: 2, mode: 1, member: addr(0), ...at(3) },
  { name: "MemberAdded", member: CHEN, epoch: 2, mode: 0, ...at(4) },
  { name: "EnvelopeGranted", epoch: 2, mode: 0, member: CHEN, ...at(4) },
  { name: "MemberRemoved", member: CHEN, newEpoch: 3, ...at(5) },
  { name: "EnvelopeGranted", epoch: 3, mode: 1, member: addr(0), ...at(5) },
  { name: "MemberAdded", member: GUEST_A, epoch: 4, mode: 1, ...at(6) },
  { name: "EnvelopeGranted", epoch: 4, mode: 1, member: addr(0), ...at(6) },
  { name: "MemberAdded", member: GUEST_B, epoch: 4, mode: 0, ...at(7) },
  { name: "MemberRemoved", member: GUEST_A, newEpoch: 5, ...at(8) },
  { name: "EnvelopeGranted", epoch: 5, mode: 1, member: addr(0), ...at(8) },
];

const directors: Director[] = [
  { name: "Chair", address: CHAIR },
  { name: "Asha", address: ASHA },
  { name: "Ben", address: BEN },
  { name: "Chen", address: CHEN },
];

const packs: PackInfo[] = [
  { index: 0, epoch: 2, postedAt: 1 },
  { index: 1, epoch: 2, postedAt: 2 },
  { index: 2, epoch: 3, postedAt: 3 },
];

function check(name: string, ok: boolean, detail: string) {
  if (!ok) throw new Error(`rule check failed: ${name}. ${detail}`);
  return name;
}

const tenure = (startEpoch: number, endEpoch: number | null): Tenure => ({
  startEpoch,
  mode: 1,
  startTx: tx(900),
  startBlock: 1,
  endEpoch,
  endTx: endEpoch === null ? null : tx(901),
  endBlock: endEpoch === null ? null : 2,
});

/** Runs every check and returns their names. Throws on the first one that fails. */
export function runRuleChecks(): string[] {
  const passed: string[] = [];
  const model = buildProofModel(events, packs, directors, CHAIR);
  const states = (name: string) =>
    model.rows
      .find((row) => row.director.name === name)
      ?.cells.map((cell) => cell.state)
      .join(",") ?? "";
  const evidence = (name: string) =>
    model.rows.find((row) => row.director.name === name)?.cells.map((cell) => cell.tx) ?? [];

  passed.push(check("chair is open for every pack", states("Chair") === "open,open,open", states("Chair")));
  passed.push(
    check("a director added by rotation is open from their epoch", states("Asha") === "open,open,open", states("Asha")),
  );
  passed.push(
    check(
      "a removed director is open before removal and locked after",
      states("Chen") === "open,open,locked",
      states("Chen"),
    ),
  );
  passed.push(
    check("the proof number counts packs opened after a removal", model.proof.opened === 0, String(model.proof.opened)),
  );
  passed.push(
    check("the kept count counts packs opened before the removal", model.proof.kept === 2, String(model.proof.kept)),
  );
  passed.push(
    check(
      "the removal link is the removal transaction",
      model.proof.removal?.tx === tx(5),
      String(model.proof.removal?.tx),
    ),
  );

  passed.push(
    check(
      "open evidence: single-envelope join links the add, rotation links the epoch grant",
      evidence("Chen")[0] === tx(4) &&
        evidence("Ben")[0] === tx(3) &&
        evidence("Asha")[2] === tx(5) &&
        evidence("Chair")[0] === tx(3),
      JSON.stringify([evidence("Chen")[0], evidence("Ben")[0], evidence("Asha")[2], evidence("Chair")[0]]),
    ),
  );
  passed.push(check("locked evidence links the removal", evidence("Chen")[2] === tx(5), String(evidence("Chen")[2])));

  const early = buildProofModel(events, [{ index: 0, epoch: 0, postedAt: 1 }], directors, CHAIR);
  passed.push(
    check(
      "a director who joins after the pack is not yet a member and links their add",
      early.rows.find((row) => row.director.name === "Asha")?.cells[0]?.state === "notyet" &&
        early.rows.find((row) => row.director.name === "Asha")?.cells[0]?.tx === tx(2),
      JSON.stringify(early.rows.find((row) => row.director.name === "Asha")?.cells[0]),
    ),
  );

  const twice = [tenure(2, 3), tenure(5, null)];
  const sequence = [1, 2, 3, 4, 5, 6].map((epoch) => stateAt(twice, epoch)).join(",");
  passed.push(check("a re-added member has two tenures", sequence === "notyet,open,locked,locked,open,open", sequence));

  passed.push(
    check(
      "guests are counted per pack, now and since the start",
      model.guests.ever === 2 && model.guests.now === 1 && model.guests.perPack.join(",") === "0,0,0",
      JSON.stringify(model.guests),
    ),
  );

  const lateGuests = buildProofModel(
    events,
    [
      { index: 0, epoch: 4, postedAt: 1 },
      { index: 1, epoch: 5, postedAt: 2 },
    ],
    directors,
    CHAIR,
  );
  passed.push(
    check(
      "a guest removed into epoch 5 is open at 4 and locked at 5",
      lateGuests.guests.perPack.join(",") === "2,1",
      lateGuests.guests.perPack.join(","),
    ),
  );

  const chen = model.rows.find((row) => row.director.name === "Chen");
  passed.push(
    check(
      "the removed row carries a removed chip with the new epoch",
      chen?.chip.kind === "removed" && chen.chip.epoch === 3,
      JSON.stringify(chen?.chip),
    ),
  );

  return passed;
}
