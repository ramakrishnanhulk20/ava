"use client";

import { sameAccount } from "@ava/core";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { shortHash } from "../../lib/boardRules";
import { everOnBoard } from "../../lib/chair/history";
import { readRoom, type Room } from "../../lib/chair/room";
import { formatCount } from "../../lib/chain";
import { createGuest, forgetGuest, openGuest, protectStoredPhrase, restoreGuest, storedGuest, type GuestSession, type StoredGuest } from "../../lib/guest/identity";
import { heldSession, holdSession } from "../../lib/guest/session";
import { Stopped } from "../../lib/guest/time";
import { hexRowsOf } from "../../lib/guest/shut";
import { StartBlock, type StartWork } from "../demo/StartBlock";
import { Footer } from "../Footer";
import { Nav } from "../hero/Nav";
import { PackSheets } from "../hero/PackSheets";
import { Seal } from "../hero/Seal";
import { CipherRows, type CipherRowText } from "../how/CipherRows";
import { DirectorList } from "./DirectorList";
import { PackList } from "./PackList";
import { RoomLedger } from "./RoomLedger";

const LABEL = "mono text-[11px] tracking-[0.14em] text-ink-soft";
const TAG = "mono rounded-[4px] border border-rule px-2 py-[3px] text-[10px] tracking-[0.12em] text-ink-soft";
const STAGE_ROWS = 9;
const BYTES_PER_ROW = 17;

type Reading = { state: "reading"; done: number; total: number } | { state: "ready" } | { state: "failed"; error: string };
type Standing = "chair" | "member" | "removed" | "none";

const STANDING: Record<Standing, string> = { chair: "YOU CHAIR THIS BOARD", member: "YOU ARE A MEMBER", removed: "YOU WERE REMOVED", none: "YOU ARE NOT ON THIS BOARD" };

function plural(count: number, one: string, many: string): string {
  return `${formatCount(count)} ${count === 1 ? one : many}`;
}

/** The pack on the stage carries what the registry really holds for the newest packs: their SHA-256 hashes, row after row. */
function hashRows(room: Room): CipherRowText[] {
  const bytes: number[] = [];
  for (const pack of [...room.packs].sort((a, b) => b.index - a.index)) {
    for (let i = 2; i < pack.cipherHash.length; i += 2) bytes.push(Number.parseInt(pack.cipherHash.slice(i, i + 2), 16));
  }
  const rows: CipherRowText[] = hexRowsOf(Uint8Array.from(bytes), STAGE_ROWS, BYTES_PER_ROW);
  while (rows.length < STAGE_ROWS) rows.push(null);
  return rows;
}

function RoomStage({ room, breaks }: { room: Room; breaks: number }) {
  const [reformed, setReformed] = useState(0);
  const members = room.snapshot.members.length;
  const rows = useMemo(() => hashRows(room), [room]);
  const ring = `SEALED TO ${plural(members, "MEMBER", "MEMBERS")} · EPOCH ${room.snapshot.epoch.toString()} ·`;

  return (
    <div className="demo-stage" aria-hidden="true">
      <div className="demo-stage-design">
        <div className="absolute" style={{ left: 24, top: 0, width: 460, height: 580 }}>
          <div className="how-pack relative h-full w-full">
            <PackSheets
              fixed
              liveLine={`BOARD ${room.snapshot.boardId.toString()} · ${plural(room.packs.length, "PACK", "PACKS")} · THEIR HASHES BELOW`}
              sealSize={132}
              seal={<Seal size={132} ringText={ring} state={breaks > reformed ? "breaking" : reformed > 0 ? "reformed" : "intact"} onDone={() => setReformed(breaks)} />}
            >
              <CipherRows rows={rows} />
            </PackSheets>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * One board's room: its packs, its directors and the ledger of who can read what, for the chair
 * who runs it and for the directors who sit on it. Everything shown is read from the registry and
 * the blob store by this browser. A board this account is not on shows only its public record, and
 * nothing of its packs is fetched until the visitor opens one (threat model C21).
 */
export function BoardRoom({ id }: { id: string }) {
  const router = useRouter();
  const boardId = useMemo(() => (/^[1-9]\d{0,18}$/.test(id) ? BigInt(id) : undefined), [id]);
  const [session, setSession] = useState<GuestSession | undefined>(undefined);
  const [stored, setStored] = useState<StoredGuest>({ kind: "none" });
  const [busy, setBusy] = useState<StartWork | undefined>(undefined);
  const [problem, setProblem] = useState<string | undefined>(undefined);
  const [note, setNote] = useState<string | undefined>(undefined);
  const [room, setRoom] = useState<Room | undefined>(undefined);
  const [reading, setReading] = useState<Reading | undefined>(undefined);
  const [breaks, setBreaks] = useState(0);
  const run = useRef<AbortController | undefined>(undefined);
  // Set when a removal lands, so the seal breaks once the board has been read again and shows who is left.
  const breakNext = useRef(false);

  useEffect(() => {
    const controller = new AbortController();
    run.current = controller;
    setStored(storedGuest());
    setSession(heldSession());
    return () => controller.abort();
  }, []);

  const signal = useCallback(() => run.current?.signal, []);

  const load = useCallback(async () => {
    const live = run.current?.signal;
    if (boardId === undefined || live === undefined) return;
    setReading((prior) => (prior?.state === "ready" ? prior : { state: "reading", done: 0, total: 0 }));
    try {
      const next = await readRoom(boardId, live, (done, total) => {
        if (!live.aborted) setReading((prior) => (prior?.state === "ready" ? prior : { state: "reading", done, total }));
      });
      if (live.aborted) return;
      setRoom(next);
      setReading({ state: "ready" });
      if (breakNext.current) {
        breakNext.current = false;
        setBreaks((n) => n + 1);
      }
    } catch (error) {
      if (error instanceof Stopped || live.aborted) return;
      const unknown = error instanceof Error && /UnknownBoard|reverted/i.test(error.message);
      setReading({ state: "failed", error: unknown ? `The registry holds no board ${boardId.toString()}.` : "The board could not be read from the chain. Try again." });
    }
  }, [boardId]);

  useEffect(() => {
    if (session !== undefined && boardId !== undefined) void load();
  }, [session, boardId, load]);

  const open = useCallback(
    (work: StartWork, obtain: (passphrase: string) => Promise<GuestSession>, fresh: boolean) => (passphrase: string) => {
      setBusy(work);
      setProblem(undefined);
      void obtain(passphrase)
        .then((opened) => {
          holdSession(opened);
          // A brand-new identity has no keys on chain yet; the lobby is where it gets them.
          if (fresh) router.push("/board");
          else setSession(opened);
        })
        .catch((error: unknown) => setProblem(error instanceof Error ? error.message : "That did not work. Try again."))
        .finally(() => setBusy(undefined));
    },
    [router],
  );
  const create = useMemo(() => open("making", (passphrase) => createGuest(passphrase), true), [open]);
  const reopen = useMemo(() => open("opening", (passphrase) => openGuest(passphrase), false), [open]);
  const protect = useMemo(() => open("making", (passphrase) => protectStoredPhrase(passphrase), false), [open]);
  // A restored identity already has its keys and its seats on chain, so it goes straight into the room.
  const restore = useCallback((phrase: string, passphrase: string) => open("making", (chosen) => restoreGuest(phrase, chosen), false)(passphrase), [open]);
  const forget = useCallback(() => {
    try {
      forgetGuest();
      setNote("This browser no longer holds your identity. Starting again makes a new one.");
    } catch (error) {
      setNote(error instanceof Error ? error.message : "The identity could not be removed.");
    }
    holdSession(undefined);
    setProblem(undefined);
    setStored(storedGuest());
  }, []);

  const me = session?.guest;
  const standing: Standing | undefined =
    room === undefined || me === undefined
      ? undefined
      : sameAccount(room.snapshot.chair, me.identity.evm)
        ? "chair"
        : room.snapshot.members.some((m) => sameAccount(m, me.identity.evm))
          ? "member"
          : everOnBoard(room.events, me.identity.evm)
            ? "removed"
            : "none";
  const onRemoved = useCallback(() => {
    breakNext.current = true;
  }, []);

  return (
    <main className="w-full overflow-x-clip">
      <div className="mx-auto w-full max-w-[1440px] px-5 pt-7 pb-24 sm:px-14">
        <Nav />

        <header className="pt-[120px]">
          <p className="mono flex items-start gap-2.5 text-[12px] tracking-[0.16em] text-ink-soft">
            <span className="mt-[5px] size-2 shrink-0 rounded-full bg-accent" aria-hidden="true" />
            {room === undefined
              ? `[ BOARD ${boardId?.toString() ?? "?"} · QORECHAIN TESTNET ]`
              : `[ BOARD ${room.snapshot.boardId.toString()} · EPOCH ${formatCount(room.snapshot.epoch)} · ${plural(room.snapshot.members.length, "MEMBER", "MEMBERS")} · ${plural(room.packs.length, "PACK", "PACKS")} ]`}
          </p>
          <h1 className="display mt-6 max-w-[12em] text-[clamp(2.75rem,5.5vw,5.5rem)] leading-[0.98] tracking-[-0.02em] text-ink">
            {boardId === undefined ? "No such board." : `Board ${boardId.toString()}.`}
          </h1>
          {room !== undefined && standing !== undefined ? (
            <p className="mt-6 flex flex-wrap items-center gap-x-4 gap-y-2">
              <span className={TAG}>{STANDING[standing]}</span>
              <span className={LABEL}>
                CHAIRED BY <span className="font-mono normal-case">{shortHash(room.snapshot.chair)}</span> · READ AT BLOCK {formatCount(room.snapshot.blockNumber)}
              </span>
            </p>
          ) : null}
          <p className="mt-6">
            <Link href="/board" className="link-draw mono text-[12px] tracking-[0.12em] text-ink">
              [ ALL YOUR BOARDS ]
            </Link>
          </p>

          {boardId === undefined ? (
            <p className="mt-6 max-w-[48ch] text-[18px] leading-[1.6] text-ink-soft">A board is opened by its number, like /board/42.</p>
          ) : session === undefined ? (
            <>
              <p className="mt-6 max-w-[48ch] text-[18px] leading-[1.6] text-ink-soft">Open your identity to see this board. Your keys decide which of its packs you can read.</p>
              <StartBlock
                stored={stored}
                busy={busy}
                problem={problem}
                note={note}
                onCreate={create}
                onReopen={reopen}
                onProtect={protect}
                onForget={forget}
                createLabel="MAKE MY IDENTITY"
                createHint="TESTNET ONLY · YOUR RECOVERY WORDS NEVER LEAVE THIS BROWSER · ABOUT A MINUTE"
                onRestore={restore}
              />
            </>
          ) : null}
        </header>

        {session !== undefined && boardId !== undefined ? (
          reading?.state === "failed" ? (
            <div className="mt-[72px]">
              <p className="max-w-[48ch] text-[17px] leading-[1.5] text-ink">{reading.error}</p>
              <button
                type="button"
                onClick={() => void load()}
                className="mono mt-4 min-h-9 cursor-pointer rounded-lg border border-ink px-4 py-1.5 text-[12px] tracking-[0.12em] text-ink transition-colors duration-200 hover:bg-ink hover:text-on-ink"
              >
                READ IT AGAIN
              </button>
            </div>
          ) : room === undefined || me === undefined || standing === undefined ? (
            <div className="mt-[72px] max-w-[560px]" aria-live="polite">
              <div className="demo-track" />
              <p className={`${LABEL} mt-2`}>
                {reading?.state === "reading" && reading.total > 0
                  ? `READING THE BOARD'S HISTORY · PAGE ${formatCount(reading.done)} OF ${formatCount(reading.total)}`
                  : "READING THE BOARD FROM THE REGISTRY"}
              </p>
            </div>
          ) : (
            <section className="mt-[72px] lg:grid lg:grid-cols-12 lg:gap-x-8">
              <div className="max-lg:order-1 max-lg:mx-auto max-lg:mb-14 max-lg:w-[min(360px,80vw)] lg:col-span-5 lg:col-start-8">
                <div className="lg:sticky lg:top-[calc(50vh-290px)]">
                  <RoomStage room={room} breaks={breaks} />
                </div>
              </div>
              <div className="flex flex-col gap-20 max-lg:order-2 lg:col-span-7 lg:col-start-1 lg:row-start-1">
                <PackList room={room} me={me} isChair={standing === "chair"} signal={signal} onChanged={() => void load()} />
                <DirectorList room={room} me={me} isChair={standing === "chair"} signal={signal} onChanged={() => void load()} onRemoved={onRemoved} />
                <RoomLedger room={room} me={me} signal={signal} />
              </div>
            </section>
          )
        ) : null}
      </div>
      <Footer />
    </main>
  );
}
