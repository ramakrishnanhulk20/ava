import type { ReactNode } from "react";

const LABEL = "mono text-[10px] tracking-[0.14em] text-ink-soft";
const CARD = "rounded-lg border border-rule bg-sheet p-5";

function Lane({ label, title, lines }: { label: string; title: string; lines: string[] }) {
  return (
    <div className={CARD}>
      <p className={LABEL}>{label}</p>
      <p className="mt-2 text-[17px] leading-tight font-semibold text-ink">{title}</p>
      <ul className="mt-3 flex flex-col gap-1.5 text-[14px] leading-[1.45] text-ink-soft">
        {lines.map((line) => (
          <li key={line}>{line}</li>
        ))}
      </ul>
    </div>
  );
}

function Crossing({ from, to, what, sealed = false }: { from: string; to: string; what: string; sealed?: boolean }) {
  return (
    <li className="grid grid-cols-[1fr_auto_1fr] items-center gap-3 border-t border-rule py-3 first:border-t-0 sm:grid-cols-[150px_auto_150px_1fr]">
      <span className="mono text-[11px] tracking-[0.1em] text-ink">{from}</span>
      <span aria-hidden="true" className={sealed ? "text-[18px] leading-none font-bold text-ink" : "text-[18px] leading-none text-ink-soft"}>
        {sealed ? "⟹" : "⟶"}
      </span>
      <span className="mono text-[11px] tracking-[0.1em] text-ink">{to}</span>
      <span className="col-span-3 text-[14px] leading-[1.45] text-ink-soft sm:col-span-1">
        {what}
        {sealed ? <span className="mono ml-2 text-[10px] tracking-[0.12em] text-ink">CIPHERTEXT ONLY</span> : null}
      </span>
    </li>
  );
}

function Figure({ caption, children }: { caption: string; children: ReactNode }) {
  return (
    <figure className="not-prose my-8">
      {children}
      <figcaption className={`${LABEL} mt-3`}>{caption}</figcaption>
    </figure>
  );
}

/** Diagram 1: the three places Ava runs, and what is allowed to cross between them. */
export function SystemDiagram() {
  return (
    <Figure caption="[ DIAGRAM 1 · WHERE AVA RUNS, AND WHAT CROSSES BETWEEN ]">
      <div className="grid gap-3 lg:grid-cols-3">
        <Lane label="YOUR BROWSER" title="Holds every secret" lines={["Your 24 recovery words, locked with your passphrase", "Your ML-DSA-87 signing key and ML-KEM-1024 sealing key", "Seals keys, encrypts packs, signs board changes, decrypts"]} />
        <Lane label="AVA'S SERVER" title="Holds no key of yours" lines={["Relays a signed change and pays its network fee", "Funds a new identity once with a little test QOR", "Stores ciphertext under its own hash, and counts requests"]} />
        <Lane label="QORECHAIN AND THE BLOB STORE" title="The record and the bytes" lines={["BoardRegistry: who sits on each board, each key envelope's hash, each pack's hash", "The chain's key registry: every director's public keys", "The blob store: envelopes and packs, as ciphertext named by SHA-256"]} />
      </div>
      <ul className={`${CARD} mt-3`}>
        <Crossing from="BROWSER" to="CHAIN" what="Reads directors' public keys and board state straight from the public endpoint. Our server is never on that path." />
        <Crossing from="BROWSER" to="SERVER" what="A signed board change: public fields and one ML-DSA-87 signature." />
        <Crossing from="BROWSER" to="BLOB STORE" what="An encrypted pack, uploaded with a one-time token for its exact hash and size." sealed />
        <Crossing from="BROWSER" to="SERVER" what="A key envelope, so the server can hash what it stores." sealed />
        <Crossing from="SERVER" to="CHAIN" what="One transaction per signed change. The registry checks the chair's signature itself, so the sender grants nothing." />
        <Crossing from="BLOB STORE" to="BROWSER" what="Envelopes and packs, fetched by the hash the chain recorded and checked before any key touches them." sealed />
      </ul>
    </Figure>
  );
}

const REMOVAL: { who: string; what: string }[] = [
  { who: "CHAIR'S BROWSER", what: "Reads the board and its members at one block, so the list it seals to is the list the chain holds." },
  { who: "CHAIR'S BROWSER", what: "Reads every remaining director's ML-KEM-1024 key from the chain's registry." },
  { who: "CHAIR'S BROWSER", what: "Makes a new board key and seals it into one envelope for the directors who stay." },
  { who: "SERVER", what: "Stores the envelope under its SHA-256. The chair signs that hash, computed in the browser." },
  { who: "CHAIR'S BROWSER", what: "Signs the removal with ML-DSA-87: 256 bytes naming the chain, the registry, the board, the nonce and a deadline." },
  { who: "SERVER", what: "Simulates the exact transaction, then sends it and pays the fee. It cannot change a byte of what was signed." },
  { who: "BOARDREGISTRY", what: "Builds the same 256 bytes itself, reads the chair's registered key, and asks QoreChain's ML-DSA-87 check to verify the signature." },
  { who: "BOARDREGISTRY", what: "Removes the director, moves the board to the next epoch and records the new envelope's hash." },
  { who: "CHAIR'S BROWSER", what: "Posts the next pack, encrypted under the new key." },
  { who: "REMOVED DIRECTOR", what: "Still opens every pack they could open before. The new envelope holds no entry for their key, so the next pack stays shut." },
];

/** Diagram 2: removing a director, step by step, with who does each step. */
export function RemovalSequence() {
  return (
    <Figure caption="[ DIAGRAM 2 · REMOVING A DIRECTOR ]">
      <ol className={CARD}>
        {REMOVAL.map((step, i) => (
          <li key={i} className="grid grid-cols-[36px_1fr] gap-x-3 border-t border-rule py-3 first:border-t-0 sm:grid-cols-[36px_170px_1fr]">
            <span className="display text-[22px] leading-none text-ink">{String(i + 1).padStart(2, "0")}</span>
            <span className="mono text-[11px] leading-[1.6] tracking-[0.1em] text-ink">{step.who}</span>
            <span className="col-start-2 text-[14px] leading-[1.45] text-ink-soft sm:col-start-3">{step.what}</span>
          </li>
        ))}
      </ol>
    </Figure>
  );
}

const EPOCHS: { epoch: string; event: string; pack: string; readers: string[]; shut: string[] }[] = [
  { epoch: "EPOCH 0", event: "The chair creates the board and adds Asha and Ben.", pack: "PACK 1", readers: ["Chair", "Asha", "Ben"], shut: [] },
  { epoch: "EPOCH 1", event: "The chair removes Ben. A new key is sealed to the chair and Asha.", pack: "PACK 2", readers: ["Chair", "Asha"], shut: ["Ben"] },
  { epoch: "EPOCH 2", event: "The chair adds Dana from now on. A new key is sealed to all three.", pack: "PACK 3", readers: ["Chair", "Asha", "Dana"], shut: ["Ben"] },
];

/** Diagram 3: a board's key over time, and who can read the pack posted in each epoch. */
export function EpochTimeline() {
  return (
    <Figure caption="[ DIAGRAM 3 · ONE KEY PER EPOCH: WHO CAN READ EACH PACK ]">
      <div className="grid gap-3 lg:grid-cols-3">
        {EPOCHS.map((e) => (
          <div key={e.epoch} className={CARD}>
            <p className={LABEL}>{e.epoch}</p>
            <p className="mt-2 text-[14px] leading-[1.45] text-ink-soft">{e.event}</p>
            <p className="mono mt-4 text-[11px] tracking-[0.12em] text-ink">{e.pack}</p>
            <p className="mt-1.5 text-[14px] leading-[1.45] text-ink">Can open: {e.readers.join(", ")}</p>
            <p className="mt-1 text-[14px] leading-[1.45] text-ink-soft">{e.shut.length === 0 ? "Locked to nobody on the board." : `Locked: ${e.shut.join(", ")}`}</p>
          </div>
        ))}
      </div>
      <p className="mt-3 text-[14px] leading-[1.5] text-ink-soft">
        Ben keeps pack 1: he held the key of epoch 0 and nothing can take that back. Dana cannot open packs 1 or 2: she was added from epoch 2 on. The chair can instead add a director to the current epoch, and then they read what that epoch already holds.
      </p>
    </Figure>
  );
}
