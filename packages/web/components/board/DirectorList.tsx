"use client";

import { AddressError, Mode, accountBytesStrict, sameAccount, toHex } from "@ava/core";
import { useCallback, useId, useState, type FormEvent } from "react";
import { shortHash, tenuresByMember } from "../../lib/boardRules";
import { addDirector, removeDirector } from "../../lib/chair/board";
import type { Room } from "../../lib/chair/room";
import { formatCount } from "../../lib/chain";
import type { GuestAccount } from "../../lib/guest/identity";
import { ActionLine, useAction } from "./ActionLine";

const LABEL = "mono text-[11px] tracking-[0.14em] text-ink-soft";
const TAG = "mono rounded-[4px] border border-rule px-2 py-[3px] text-[10px] tracking-[0.12em] text-ink-soft";
const SMALL_BUTTON =
  "mono min-h-9 cursor-pointer rounded-lg border border-ink px-4 py-1.5 text-[12px] tracking-[0.12em] text-ink transition-colors duration-200 hover:bg-ink hover:text-on-ink disabled:cursor-not-allowed disabled:opacity-45 disabled:hover:bg-transparent disabled:hover:text-ink";

type DirectorListProps = {
  room: Room;
  me: GuestAccount;
  isChair: boolean;
  signal: () => AbortSignal | undefined;
  /** Called after a director is added or removed, so the room reads the board again. */
  onChanged: () => void;
  /** Called once a removal has landed: the cue for the seal to break and re-form. */
  onRemoved: () => void;
};

/** Who sits on the board now and who has left, from the registry's own record, and the chair's two changes: add and remove. */
export function DirectorList({ room, me, isChair, signal, onChanged, onRemoved }: DirectorListProps) {
  const { snapshot, events } = room;
  const boardId = snapshot.boardId;
  const [address, setAddress] = useState("");
  const [mode, setMode] = useState<Mode>(Mode.ROTATE);
  const [problem, setProblem] = useState<string | undefined>(undefined);
  const [asking, setAsking] = useState<string | undefined>(undefined);
  const change = useAction(signal);
  const fieldId = useId();
  const groupId = useId();

  const tenures = tenuresByMember(events);
  const sitting = [...snapshot.members].sort((a, b) => Number(sameAccount(b, snapshot.chair)) - Number(sameAccount(a, snapshot.chair)));
  const left = [...tenures].filter(([member, own]) => own.at(-1)?.endEpoch !== null && !snapshot.members.some((m) => sameAccount(m, member)));

  const add = useCallback(
    (event: FormEvent) => {
      event.preventDefault();
      let director: `0x${string}`;
      try {
        director = toHex(accountBytesStrict(address.trim()));
      } catch (error) {
        setProblem(error instanceof AddressError ? "That is not an address this app can read. Paste the qor1 address the director sent you." : "That address could not be read.");
        return;
      }
      setProblem(undefined);
      change.start(
        `Adding ${shortHash(director)}`,
        async (say, live) => {
          const added = await addDirector(me, boardId, director, mode, live, say);
          return { text: `${shortHash(director)} is on the board at epoch ${added.epoch.toString()}, in block ${formatCount(added.block)}.`, hash: added.txHash };
        },
        () => {
          setAddress("");
          onChanged();
        },
      );
    },
    [address, boardId, change, me, mode, onChanged],
  );

  const remove = useCallback(
    (member: string) => {
      setAsking(undefined);
      change.start(
        `Removing ${shortHash(member)}`,
        async (say, live) => {
          const removed = await removeDirector(me, boardId, member as `0x${string}`, live, say);
          return { text: `${shortHash(member)} is off the board. It moved to epoch ${removed.epoch.toString()} in block ${formatCount(removed.block)}; the next pack is shut to them.`, hash: removed.txHash };
        },
        () => {
          onRemoved();
          onChanged();
        },
      );
    },
    [boardId, change, me, onChanged, onRemoved],
  );

  return (
    <section aria-labelledby="directors-title">
      <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-2">
        <h2 id="directors-title" className={LABEL}>
          [ DIRECTORS ]
        </h2>
        <p className={LABEL}>
          {formatCount(sitting.length)} ON THE BOARD · THE REGISTRY HOLDS AT MOST 64
        </p>
      </div>

      <ul className="mt-6 border-b border-rule">
        {sitting.map((member) => {
          const own = tenures.get(member.toLowerCase())?.at(-1);
          const chairs = sameAccount(member, snapshot.chair);
          const mine = sameAccount(member, me.identity.evm);
          return (
            <li key={member} className="border-t border-rule py-4">
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
                <span className="font-mono text-[14px] text-ink" title={member}>
                  {shortHash(member)}
                </span>
                {chairs ? <span className={TAG}>CHAIR</span> : <span className={TAG}>MEMBER</span>}
                {mine ? <span className={TAG}>YOU</span> : null}
                <span className={`${LABEL} flex-1`}>{own === undefined ? "" : `SINCE EPOCH ${formatCount(own.startEpoch)}`}</span>
                {isChair && !chairs && asking !== member ? (
                  <button type="button" onClick={() => setAsking(member)} disabled={change.busy} className={SMALL_BUTTON}>
                    REMOVE
                  </button>
                ) : null}
              </div>
              {asking === member ? (
                <div className="mt-3 max-w-[560px]">
                  <p className="text-[15px] leading-[1.5] text-ink">
                    Remove {shortHash(member)}? The board gets a new key sealed to everyone else, so the next pack is shut to them. They keep what they could already open.
                  </p>
                  <div className="mt-3 flex flex-wrap gap-3">
                    <button type="button" onClick={() => remove(member)} className={SMALL_BUTTON}>
                      REMOVE THEM
                    </button>
                    <button type="button" onClick={() => setAsking(undefined)} className="link-draw mono cursor-pointer text-[12px] tracking-[0.12em] text-ink">
                      [ KEEP THEM ]
                    </button>
                  </div>
                </div>
              ) : null}
            </li>
          );
        })}
        {left.map(([member, own]) => (
          <li key={member} className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-rule py-4 opacity-60">
            <span className="font-mono text-[14px] text-ink" title={member}>
              {shortHash(member)}
            </span>
            <span className={TAG}>REMOVED · EPOCH {formatCount(own.at(-1)?.endEpoch ?? 0)}</span>
            {sameAccount(member, me.identity.evm) ? <span className={TAG}>YOU</span> : null}
          </li>
        ))}
      </ul>

      <div className={change.run === undefined ? "" : "mt-6"}>
        <ActionLine run={change.run} />
      </div>

      {isChair && !change.busy ? (
        <form onSubmit={add} className="mt-8 max-w-[560px]" noValidate>
          <label htmlFor={fieldId} className="mono block text-[11px] tracking-[0.14em] text-ink-soft">
            ADD A DIRECTOR BY THEIR ADDRESS
          </label>
          <input
            id={fieldId}
            className="field mt-2"
            style={{ paddingRight: 16 }}
            value={address}
            onChange={(event) => setAddress(event.target.value)}
            placeholder="qor1…"
            spellCheck={false}
            autoCapitalize="none"
            autoCorrect="off"
            aria-invalid={problem !== undefined}
          />
          <fieldset className="mt-4" aria-labelledby={groupId}>
            <legend id={groupId} className="mono text-[11px] tracking-[0.14em] text-ink-soft">
              WHAT THEY CAN READ
            </legend>
            <label className="mt-3 flex cursor-pointer items-start gap-3 text-[15px] leading-[1.5] text-ink">
              <input type="radio" name="mode" checked={mode === Mode.ROTATE} onChange={() => setMode(Mode.ROTATE)} className="mt-[5px] accent-[var(--ink)]" />
              <span>
                Only packs from now on. <span className="text-ink-soft">The board gets a new key, sealed to everyone and to them.</span>
              </span>
            </label>
            <label className="mt-2 flex cursor-pointer items-start gap-3 text-[15px] leading-[1.5] text-ink">
              <input type="radio" name="mode" checked={mode === Mode.SEAL_CURRENT} onChange={() => setMode(Mode.SEAL_CURRENT)} className="mt-[5px] accent-[var(--ink)]" />
              <span>
                This epoch&apos;s packs too. <span className="text-ink-soft">The current key is sealed to them as well, so they can read what epoch {formatCount(snapshot.epoch)} already holds.</span>
              </span>
            </label>
          </fieldset>
          {problem ? (
            <p role="alert" className="mt-3 text-[15px] leading-[1.5] text-ink">
              {problem}
            </p>
          ) : null}
          <button type="submit" disabled={address.trim() === ""} className="btn-primary mt-5 cursor-pointer">
            Add them <span className="arrow">→</span>
          </button>
          <p className={`${LABEL} mt-3.5 max-w-[60ch] leading-[1.7]`}>
            THEY FIRST OPEN /BOARD ON THEIR OWN DEVICE, WHICH PUTS THEIR KEYS ON CHAIN, AND SEND YOU THE ADDRESS IT SHOWS. THEIR KEY IS READ FROM THE CHAIN, NEVER FROM US.
          </p>
        </form>
      ) : null}
    </section>
  );
}
