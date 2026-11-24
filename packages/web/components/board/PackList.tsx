"use client";

import { useCallback, useEffect, useRef, useState, type ChangeEvent } from "react";
import { shortDate, stateAt, tenuresByMember, type CellState } from "../../lib/boardRules";
import { openPack, postPack } from "../../lib/chair/board";
import type { PackRecord } from "../../lib/chair/history";
import type { Room } from "../../lib/chair/room";
import { formatCount } from "../../lib/chain";
import type { GuestAccount } from "../../lib/guest/identity";
import { CONTAINER_FIXED_BYTES, cleanFilename, kindOf, packFile, unpackFile, type PackKind } from "../../lib/pack/format";
import { StateLine } from "../proof/StateLine";
import { ActionLine, useAction } from "./ActionLine";

const LABEL = "mono text-[11px] tracking-[0.14em] text-ink-soft";
const SMALL_BUTTON =
  "mono min-h-9 cursor-pointer rounded-lg border border-ink px-4 py-1.5 text-[12px] tracking-[0.12em] text-ink transition-colors duration-200 hover:bg-ink hover:text-on-ink disabled:cursor-not-allowed disabled:opacity-45 disabled:hover:bg-transparent disabled:hover:text-ink";
// The registry's cap on a pack's ciphertext, less the nonce and tag around it and the room the name's container takes.
const MAX_FILE_BYTES = 26_214_400 - 28 - CONTAINER_FIXED_BYTES - 1_300;

type Opened =
  | { state: "opening" }
  | { state: "failed"; why: string }
  | { state: "open"; kind: PackKind; name: string; text?: string; url: string; size: number };

type PackListProps = {
  room: Room;
  me: GuestAccount;
  isChair: boolean;
  signal: () => AbortSignal | undefined;
  /** Called after a pack lands, so the room reads the board again. */
  onChanged: () => void;
};

/**
 * One pack opened on this device. Text is put on the page as text. An image is shown only inside
 * a sandboxed frame. Everything else is offered as a download under a cleaned name, and the
 * decrypted bytes never become a page of their own on this site (threat model C19, C20).
 */
function OpenedPack({ opened, onClose }: { opened: Opened; onClose: () => void }) {
  if (opened.state === "opening") {
    return (
      <div className="mt-4 max-w-[560px]">
        <div className="demo-track" />
        <p className="mt-2 text-[15px] leading-[1.5] text-ink-soft">Fetching the envelope and the pack by their on-chain hashes and decrypting here.</p>
      </div>
    );
  }
  if (opened.state === "failed") return <p className="mt-4 max-w-[52ch] text-[15px] leading-[1.5] text-ink">{opened.why}</p>;

  return (
    <div className="mt-5">
      <p className={`${LABEL} flex flex-wrap items-center gap-x-4 gap-y-2`}>
        <span>
          DECRYPTED ON THIS DEVICE · {opened.name} · {formatCount(opened.size)} BYTES
        </span>
        <a href={opened.url} download={opened.name} className="link-draw text-ink">
          [ SAVE A COPY ]
        </a>
        <button type="button" onClick={onClose} className="link-draw cursor-pointer text-ink">
          [ CLOSE ]
        </button>
      </p>
      {opened.kind === "text" ? (
        <article className="paper mt-4 max-h-[70vh] overflow-auto p-7 sm:p-10">
          <p className="text-[17px] leading-[1.7] whitespace-pre-wrap text-ink">{opened.text}</p>
        </article>
      ) : opened.kind === "image/png" || opened.kind === "image/jpeg" ? (
        <iframe sandbox="" src={opened.url} title={`Pack image ${opened.name}`} className="paper mt-4 h-[60vh] w-full" />
      ) : (
        <p className="mt-4 max-w-[52ch] text-[15px] leading-[1.5] text-ink-soft">
          This kind of file is not shown on the page. Save a copy and open it with the program you trust for it.
        </p>
      )}
    </div>
  );
}

function PackRow({ pack, state, opened, onOpen, onClose }: { pack: PackRecord; state: CellState; opened: Opened | undefined; onOpen: () => void; onClose: () => void }) {
  return (
    <li className="border-t border-rule py-5">
      <div className="flex items-center gap-5 sm:gap-7">
        <span className="display w-16 shrink-0 text-[40px] leading-none text-ink" aria-hidden="true">
          {String(pack.index + 1).padStart(2, "0")}
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
            <span className="text-[18px] leading-[1.35] text-ink">Pack {pack.index + 1}</span>
            <StateLine state={state} tickSize={14} />
          </span>
          <span className={`${LABEL} mt-1.5 block`}>
            EPOCH {formatCount(pack.epoch)} · {formatCount(pack.cipherSize)} BYTES · {shortDate(pack.postedAt)}
          </span>
        </span>
        {state === "open" && opened?.state !== "open" ? (
          <button type="button" onClick={onOpen} disabled={opened?.state === "opening"} className={SMALL_BUTTON}>
            OPEN
          </button>
        ) : null}
      </div>
      {opened !== undefined ? <OpenedPack opened={opened} onClose={onClose} /> : null}
    </li>
  );
}

/** The board's packs, newest first: which of them this account can open, by the board's own history, and the real open behind each. */
export function PackList({ room, me, isChair, signal, onChanged }: PackListProps) {
  const [opened, setOpened] = useState<Record<number, Opened>>({});
  const urls = useRef<string[]>([]);
  const fileInput = useRef<HTMLInputElement>(null);
  const post = useAction(signal);
  const boardId = room.snapshot.boardId;
  const tenures = tenuresByMember(room.events).get(me.identity.evm.toLowerCase()) ?? [];

  useEffect(
    () => () => {
      for (const url of urls.current) URL.revokeObjectURL(url);
    },
    [],
  );

  const open = useCallback(
    (pack: PackRecord) => {
      const live = signal();
      if (live === undefined) return;
      setOpened((prior) => ({ ...prior, [pack.index]: { state: "opening" } }));
      void openPack(me, boardId, BigInt(pack.index), live)
        .then(({ plaintext }) => {
          if (live.aborted) return;
          const file = unpackFile(plaintext);
          const kind = kindOf(file.bytes);
          const name = cleanFilename(file.name, `board-${boardId.toString()}-pack-${pack.index + 1}${kind === "text" ? ".txt" : kind === "image/png" ? ".png" : kind === "image/jpeg" ? ".jpg" : ""}`);
          // Only an image keeps its own type, for the sandboxed frame; every other blob is plain bytes, so it can only download.
          const type = kind === "image/png" || kind === "image/jpeg" ? kind : "application/octet-stream";
          const url = URL.createObjectURL(new Blob([Uint8Array.from(file.bytes)], { type }));
          urls.current.push(url);
          const text = kind === "text" ? new TextDecoder("utf-8").decode(file.bytes) : undefined;
          setOpened((prior) => ({ ...prior, [pack.index]: { state: "open", kind, name, text, url, size: file.bytes.length } }));
        })
        .catch((error: unknown) => {
          if (live.aborted) return;
          setOpened((prior) => ({ ...prior, [pack.index]: { state: "failed", why: error instanceof Error ? error.message : "The pack could not be opened." } }));
        });
    },
    [boardId, me, signal],
  );

  const close = useCallback((index: number) => setOpened(({ [index]: _closed, ...rest }) => rest), []);

  const choose = useCallback(
    (event: ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0];
      event.target.value = "";
      if (file === undefined) return;
      post.start(
        `Posting ${cleanFilename(file.name, "the pack")}`,
        async (say, live) => {
          if (file.size === 0) throw new Error("That file is empty.");
          if (file.size > MAX_FILE_BYTES) throw new Error(`That file is ${formatCount(file.size)} bytes. A pack holds at most ${formatCount(MAX_FILE_BYTES)}.`);
          const bytes = new Uint8Array(await file.arrayBuffer());
          const posted = await postPack(me, boardId, packFile({ name: file.name, bytes }), live, say);
          return { text: `Pack ${(posted.docId + 1n).toString()} is on chain at epoch ${posted.epoch.toString()}, in block ${formatCount(posted.block)}. Only its ciphertext left this device.`, hash: posted.txHash };
        },
        onChanged,
      );
    },
    [boardId, me, onChanged, post],
  );

  const newestFirst = [...room.packs].sort((a, b) => b.index - a.index);

  return (
    <section aria-labelledby="packs-title">
      <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
        <h2 id="packs-title" className={LABEL}>
          [ PACKS ]
        </h2>
        <p className={LABEL}>NAMES AND CONTENTS ARE NEVER ON CHAIN · ONLY A HASH, A SIZE AND A TIME</p>
      </div>

      {newestFirst.length > 0 ? (
        <ol className="mt-6 border-b border-rule">
          {newestFirst.map((pack) => (
            <PackRow key={pack.index} pack={pack} state={stateAt(tenures, pack.epoch)} opened={opened[pack.index]} onOpen={() => open(pack)} onClose={() => close(pack.index)} />
          ))}
        </ol>
      ) : (
        <p className="mt-6 max-w-[48ch] border-t border-rule pt-6 text-[17px] leading-[1.5] text-ink">No pack has been posted to this board yet.</p>
      )}

      {isChair ? (
        <div className="mt-8">
          <input ref={fileInput} type="file" onChange={choose} className="sr-only" aria-label="Choose a file to post as a pack" tabIndex={-1} />
          {post.busy ? null : (
            <>
              <button type="button" onClick={() => fileInput.current?.click()} className="btn-primary cursor-pointer">
                Post a pack <span className="arrow">→</span>
              </button>
              <p className={`${LABEL} mt-3.5 max-w-[60ch] leading-[1.7]`}>
                ANY FILE UP TO 25 MB. IT IS ENCRYPTED IN THIS BROWSER FOR THE {formatCount(room.snapshot.members.length)} {room.snapshot.members.length === 1 ? "MEMBER" : "MEMBERS"} ON THE BOARD NOW; ONLY THE CIPHERTEXT IS UPLOADED.
              </p>
            </>
          )}
          <div className={post.run === undefined ? "" : "mt-6"}>
            <ActionLine run={post.run} />
          </div>
        </div>
      ) : null}
    </section>
  );
}
