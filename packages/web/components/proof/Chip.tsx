import type { Chip as ChipKind } from "../../lib/boardRules";

function label(chip: ChipKind): string {
  switch (chip.kind) {
    case "chair":
      return "CHAIR";
    case "member":
      return "MEMBER";
    case "removed":
      return `REMOVED · EPOCH ${chip.epoch}`;
    case "none":
      return "NOT A MEMBER";
  }
}

export function Chip({ chip }: { chip: ChipKind }) {
  return (
    <span className="mono inline-block w-fit rounded-[4px] border border-rule px-2 py-[3px] text-[10px] tracking-[0.12em] text-ink-soft">
      {label(chip)}
    </span>
  );
}
