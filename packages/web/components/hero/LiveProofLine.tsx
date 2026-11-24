"use client";

import { formatCount, useDemoBoard } from "../../lib/chain";

export function LiveProofLine() {
  const board = useDemoBoard();

  let text: string;
  if (board.status === "loading") {
    text = "[ READING QORECHAIN TESTNET ]";
  } else if (
    board.status === "down" ||
    board.block === null ||
    board.epoch === null ||
    board.memberCount === null ||
    board.documentCount === null
  ) {
    text = "[ TESTNET NOT ANSWERING · RETRYING ]";
  } else {
    const retrying = board.status === "retrying" ? " · RETRYING" : "";
    text =
      `[ LIVE · BLOCK ${formatCount(board.block)} · DEMO BOARD ${board.id}` +
      ` · ${formatCount(board.memberCount)} MEMBERS · EPOCH ${formatCount(board.epoch)}` +
      ` · ${formatCount(board.documentCount)} PACKS${retrying} ]`;
  }

  return (
    <p className="mono mt-4 flex items-start gap-2.5 text-[11px] leading-[1.6] tracking-[0.12em] text-ink-soft/85">
      <span className="live-dot mt-[5px]" data-live={board.status === "live"} aria-hidden="true" />
      <span>{text}</span>
    </p>
  );
}
