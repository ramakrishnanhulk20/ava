import { ROW_CLASS } from "../hero/PackSheets";

// Text bars stand in for the readable pack before it is sealed. Widths are percent of the row.
const BAR_WIDTHS = [92, 84, 88, 60, 90, 76, 82, 70, 40];

export type CipherRowText = string | null;

type CipherRowsProps = {
  /** One entry per row: ciphertext, or null for a plain text bar. */
  rows: CipherRowText[];
};

export function CipherRows({ rows }: CipherRowsProps) {
  return (
    <div className={ROW_CLASS}>
      {rows.map((text, i) => (
        <div key={i} className="h-[19px]">
          {text === null ? (
            <span className="mt-1.5 block h-[7px] rounded-[2px] bg-ink/18" style={{ width: `${BAR_WIDTHS[i]}%` }} />
          ) : (
            text
          )}
        </div>
      ))}
    </div>
  );
}
