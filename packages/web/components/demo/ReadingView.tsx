import Link from "next/link";
import type { ReactNode } from "react";
import type { JourneyView } from "../../lib/guest/journey";

type Block =
  | { kind: "heading"; text: string }
  | { kind: "paragraph"; text: string }
  | { kind: "ordered"; start: number; items: string[] }
  | { kind: "bullets"; items: string[] };

const NUMBERED = /^\s*(\d+)[.)]\s+(.*)$/u;
const BULLET = /^\s*[-*]\s+(.*)$/u;
const HASHED = /^#{1,6}\s+(.*)$/u;

const HEADING_WORDS = 6;

function headingLike(line: string): boolean {
  const text = line.trim();
  return text !== "" && text.split(/\s+/u).length <= HEADING_WORDS && !/[.!?:;,]$/u.test(text);
}

function listOf(lines: string[]): Block | null {
  if (lines.length === 0) return null;
  if (lines.every((line) => NUMBERED.test(line))) {
    const start = Number(lines[0]?.match(NUMBERED)?.[1] ?? 1);
    return { kind: "ordered", start, items: lines.map((line) => line.replace(NUMBERED, "$2")) };
  }
  if (lines.every((line) => BULLET.test(line)))
    return { kind: "bullets", items: lines.map((line) => line.replace(BULLET, "$1")) };
  return null;
}

/** One run of lines between blank lines. A short line on top of a list, or alone before more text, is a heading. */
function blocksOf(group: string[], last: boolean): Block[] {
  const out: Block[] = [];
  let rest = group;
  const top = (group[0] ?? "").trim();
  if (HASHED.test(top)) {
    out.push({ kind: "heading", text: top.replace(HASHED, "$1") });
    rest = group.slice(1);
  } else if (group.length > 1 && headingLike(top) && listOf(group.slice(1)) !== null) {
    out.push({ kind: "heading", text: top });
    rest = group.slice(1);
  } else if (group.length === 1 && headingLike(top) && !last) {
    return [{ kind: "heading", text: top }];
  }
  if (rest.length > 0) out.push(listOf(rest) ?? { kind: "paragraph", text: rest.map((line) => line.trim()).join(" ") });
  return out;
}

/** Turns the pack's plain text into blocks. Nothing here is HTML: every block is built into elements from the text. */
export function parseBlocks(text: string): { title: string; blocks: Block[] } {
  const lines = text.split(/\r?\n/u);
  const first = lines.findIndex((line) => line.trim() !== "");
  const title = first === -1 ? "" : (lines[first] ?? "").trim().replace(HASHED, "$1");

  const groups: string[][] = [];
  let current: string[] = [];
  for (const line of lines.slice(first + 1)) {
    if (line.trim() === "") {
      if (current.length > 0) groups.push(current);
      current = [];
    } else {
      current.push(line);
    }
  }
  if (current.length > 0) groups.push(current);

  const blocks = groups.flatMap((group, index) => blocksOf(group, index === groups.length - 1));

  return { title, blocks };
}

function renderBlock(block: Block, key: number): ReactNode {
  switch (block.kind) {
    case "heading":
      return (
        <h2 key={key} className="mt-10 text-[18px] leading-[1.7] font-semibold text-ink">
          {block.text}
        </h2>
      );
    case "paragraph":
      return (
        <p key={key} className="mt-5 text-[18px] leading-[1.7] text-ink">
          {block.text}
        </p>
      );
    case "ordered":
      return (
        <ol key={key} start={block.start} className="mt-5 list-decimal pl-6 text-[18px] leading-[1.7] text-ink">
          {block.items.map((item, i) => (
            <li key={i}>{item}</li>
          ))}
        </ol>
      );
    case "bullets":
      return (
        <ul key={key} className="mt-5 list-disc pl-6 text-[18px] leading-[1.7] text-ink">
          {block.items.map((item, i) => (
            <li key={i}>{item}</li>
          ))}
        </ul>
      );
  }
}

type ReadingViewProps = {
  view: JourneyView;
};

export function ReadingView({ view }: ReadingViewProps) {
  if (view.pack === undefined || view.packInfo === undefined) return null;
  const { title, blocks } = parseBlocks(view.pack);
  const { docId, epoch, size } = view.packInfo;

  return (
    <section id="reading" className="mt-[120px]">
      <p className="mono text-center text-[11px] tracking-[0.12em] text-ink-soft">
        DECRYPTED ON THIS DEVICE · PACK {(docId + 1n).toString()} · EPOCH {epoch.toString()} ·{" "}
        {size.toLocaleString("en-US")} BYTES
      </p>
      <article className="paper mx-auto mt-6 max-w-[68ch] p-7 sm:p-16">
        <h2 className="display text-[40px] leading-[1.1] text-ink">{title}</h2>
        {blocks.map(renderBlock)}
      </article>
      <p className="mono mt-10 flex flex-wrap justify-center gap-x-7 gap-y-3 text-[12px] tracking-[0.12em]">
        <Link href="/#proof" className="link-draw text-ink">
          [ SEE WHO CAN READ EACH PACK ]
        </Link>
        <Link href="/" className="link-draw text-ink">
          [ BACK TO THE HOME PAGE ]
        </Link>
      </p>
    </section>
  );
}
