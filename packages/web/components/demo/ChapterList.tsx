"use client";

import { Cross, Tick } from "../proof/Glyphs";
import { TxHash } from "../proof/TxHash";
import { plainError, secondsBetween, waitText, type ChapterView } from "./chapters";

export type ChapterAction = { label: string; onClick: () => void };

type ChapterListProps = {
  chapters: ChapterView[];
  now: number;
  /** Each failed chapter's own error, by chapter id. */
  errors: Partial<Record<ChapterView["id"], string>>;
  /** What a failed chapter offers: TRY AGAIN, or other ways on when trying again cannot help. */
  actionsFor: (chapter: ChapterView) => ChapterAction[];
};

const STATUS = "mono text-[11px] tracking-[0.12em] text-ink-soft";

function ChapterRow({ chapter, now, errors, actionsFor }: { chapter: ChapterView } & Omit<ChapterListProps, "chapters">) {
  const { state } = chapter;
  const waiting = state === "waiting";
  const running = state === "running";
  const wait = running ? waitText(chapter, now) : undefined;

  return (
    <li
      data-chapter={chapter.id}
      data-state={state}
      className="demo-chapter flex gap-5 sm:gap-7"
      style={{ opacity: waiting ? 0.4 : 1 }}
    >
      <p
        className={`display w-14 shrink-0 text-[40px] leading-none ${running ? "text-accent" : "text-ink"}`}
        aria-hidden="true"
      >
        {chapter.number}
      </p>
      <div className="min-w-0 flex-1 pt-1">
        <h3 className="flex items-start gap-2.5 text-[18px] leading-[1.35] text-ink">
          {state === "done" ? (
            <span className="mt-[5px]">
              <Tick size={14} drawAfter={0} />
            </span>
          ) : null}
          {state === "failed" ? (
            <span className="mt-[6px]">
              <Cross size={12} />
            </span>
          ) : null}
          <span>{chapter.title}</span>
        </h3>

        {running ? (
          <div className="mt-3">
            <div className="demo-track" />
            <p className={`${STATUS} mt-2`}>{secondsBetween(chapter.startedAt, now)}</p>
            {wait ? <p className="mt-2 max-w-[44ch] text-[15px] leading-[1.5] text-ink-soft">{wait}</p> : null}
          </div>
        ) : null}

        {state === "done" ? (
          <div className="mt-3 flex flex-col gap-1.5">
            {chapter.summary ? (
              <p className="max-w-[44ch] text-[14px] leading-[1.5] text-ink-soft">{chapter.summary}</p>
            ) : null}
            {chapter.hashes.map(({ label, hash }) => (
              <p key={label} className={`${STATUS} flex flex-wrap items-center gap-x-2`}>
                <span>{label} ·</span>
                <TxHash hash={hash} className="font-mono text-[11px]" />
              </p>
            ))}
            {chapter.startedAt !== undefined && chapter.endedAt !== undefined ? (
              <p className={STATUS}>{secondsBetween(chapter.startedAt, chapter.endedAt)}</p>
            ) : null}
          </div>
        ) : null}

        {state === "failed" ? (
          <div className="mt-3">
            <p className="max-w-[44ch] text-[15px] leading-[1.5] text-ink">{plainError(errors[chapter.id] ?? "")}</p>
            <div className="mt-4 flex flex-wrap gap-3">
              {actionsFor(chapter).map((action) => (
                <button
                  key={action.label}
                  type="button"
                  onClick={action.onClick}
                  className="mono min-h-9 cursor-pointer rounded-lg border border-ink px-4 py-1.5 text-left text-[12px] tracking-[0.12em] text-ink transition-colors duration-200 hover:bg-ink hover:text-on-ink"
                >
                  {action.label}
                </button>
              ))}
            </div>
          </div>
        ) : null}
      </div>
    </li>
  );
}

export function ChapterList({ chapters, now, errors, actionsFor }: ChapterListProps) {
  return (
    <ol className="flex flex-col gap-7">
      {chapters.map((chapter) => (
        <ChapterRow key={chapter.id} chapter={chapter} now={now} errors={errors} actionsFor={actionsFor} />
      ))}
    </ol>
  );
}
